/**
 * The dashboard HTTP API (T013, D-036): `createApi(options)` builds a Hono app over injected ports (see `ports.ts`).
 *
 * Routes (all JSON; errors are `{ error: { code, message } }`):
 * - `GET  /health`                      unauthenticated liveness (no data)
 * - `GET  /audit?limit&cursor&session`  newest-first page of audit records (`nextCursor` = seq to pass as `cursor`)
 * - `GET  /audit/verify`                full hash-chain verification (`verifyChain`)
 * - `GET  /sessions/:id?limit`          one session's timeline, oldest first
 * - `GET  /approvals?status=pending`    pending approvals joined with their redacted attempt
 * - `POST /approvals/:id/approve|reject {actor?}`  through the approval service's `decide()` (same path as Telegram)
 * - `GET  /mode`                        current kill switch / shadow state
 * - `POST /killswitch {on, actor?}`     chained `mode` record via `ModeStore`
 * - `POST /mode {mode: enforce|shadow, actor?}`
 * - `GET  /events`                      SSE: `audit` (new records), `approvals` (pending set changed), `error`, `ping`
 *
 * Guards, in order: Host header (DNS rebinding) → Origin allow-list (CSRF; exact-match CORS, never `*`) → admin
 * token on EVERY route except `/health` and CORS preflight (reads too: the audit log is sensitive even redacted) →
 * zod on params, query and body (unknown keys rejected) → 4 KiB body limit.
 *
 * Fail closed: no valid admin token configured ⇒ 503 on every authenticated route; a port error or throw ⇒ 5xx, never
 * a success. The browser must use `fetch` with the `x-admin-token` header (an `EventSource` can't send headers; the
 * token is never accepted in the URL, where it would end up in logs and history).
 */
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { streamSSE } from "hono/streaming";
import { z } from "zod";
import { createEventHub, type ApiEvent, type EventHub, type Ticker } from "./events.js";
import type { ApprovalsPort, AuditPort, DecisionStatus, ModesPort } from "./ports.js";
import {
  allowedHostHeaders,
  defaultAllowedOrigins,
  parseAdminToken,
  tokenMatches,
} from "./security.js";
import { approvalView, recordView } from "./views.js";

export const ADMIN_TOKEN_HEADER = "x-admin-token";
export const MAX_BODY_BYTES = 4096;
export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_AUDIT_PAGE_LIMIT = 200;
export const DEFAULT_SESSION_LIMIT = 500;
export const MAX_SESSION_LIMIT = 1000;
export const MAX_APPROVALS_LIMIT = 200;
export const DEFAULT_MAX_EVENT_STREAMS = 4;
export const DEFAULT_HEARTBEAT_MS = 15_000;
/** `dashboard:<slug>` is what the audit chain accepts (core `APPROVER_RE` / `MODE_ACTOR_RE`). */
export const DEFAULT_ACTOR_SLUG = "admin";

export const APPROVAL_ID_RE = /^apr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const SESSION_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

export interface ApiOptions {
  readonly audit: AuditPort;
  readonly modes: ModesPort;
  /** Absent ⇒ approval routes answer 503 `approvals.unavailable`. */
  readonly approvals?: ApprovalsPort;
  /** Raw `ASF_ADMIN_TOKEN`; invalid / unset ⇒ every authenticated route is 503 (fail closed). */
  readonly adminToken: string | undefined;
  /**
   * `ASF_API_APPROVALS=1`: allow approve / reject through the API. Default OFF (403 `api.approvals_disabled`): the
   * agent may be able to read the admin token from its own environment and must not be able to self-approve.
   */
  readonly approvalsEnabled?: boolean;
  /** Port the server listens on (the Host header must name it). */
  readonly port: number;
  /** Exact origins allowed (default: the API's own + the Vite dev server on loopback). */
  readonly allowedOrigins?: readonly string[];
  readonly maxEventStreams?: number;
  readonly heartbeatMs?: number;
  readonly eventIntervalMs?: number;
  readonly ticker?: Ticker;
  readonly logger?: (line: string) => void;
}

export interface Api {
  readonly app: Hono;
  readonly events: EventHub;
  /** Ends every event stream. */
  close(): void;
}

type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 413 | 500 | 503;

const fail = (c: Context, status: ErrorStatus, code: string, message: string): Response =>
  c.json({ error: { code, message } }, status);

/**
 * Same body as `fail`, for middleware (no route context needed). `allowedOrigin`: an origin already checked against
 * the allow-list, echoed so the dashboard can read the error.
 */
const reject = (
  status: ErrorStatus,
  code: string,
  message: string,
  allowedOrigin?: string,
): Response =>
  Response.json(
    { error: { code, message } },
    {
      status,
      headers:
        allowedOrigin === undefined
          ? {}
          : { "Access-Control-Allow-Origin": allowedOrigin, Vary: "Origin" },
    },
  );

const intParam = (min: number, max: number) =>
  z
    .string()
    .regex(/^[0-9]{1,16}$/)
    .transform(Number)
    .refine((n) => Number.isSafeInteger(n) && n >= min && n <= max, {
      message: `must be an integer ${String(min)}..${String(max)}`,
    });

const actorSchema = z
  .string()
  .regex(/^[a-z0-9_-]{1,32}$/)
  .optional();

const auditQuerySchema = z.strictObject({
  limit: intParam(1, MAX_AUDIT_PAGE_LIMIT).optional(),
  cursor: intParam(1, Number.MAX_SAFE_INTEGER).optional(),
  session: z.string().regex(SESSION_ID_RE).optional(),
});
const sessionQuerySchema = z.strictObject({ limit: intParam(1, MAX_SESSION_LIMIT).optional() });
const sessionParamSchema = z.strictObject({ id: z.string().regex(SESSION_ID_RE) });
const approvalsQuerySchema = z.strictObject({
  status: z.literal("pending").optional(),
  limit: intParam(1, MAX_APPROVALS_LIMIT).optional(),
});
const approvalParamSchema = z.strictObject({ id: z.string().regex(APPROVAL_ID_RE) });
const decisionBodySchema = z.strictObject({ actor: actorSchema });
const killSwitchBodySchema = z.strictObject({ on: z.boolean(), actor: actorSchema });
const modeBodySchema = z.strictObject({ mode: z.enum(["enforce", "shadow"]), actor: actorSchema });
const emptyQuerySchema = z.strictObject({});

const issues = (e: z.ZodError): string =>
  e.issues
    .map((i) => (i.path.length > 0 ? i.path.join(".") : "(root)"))
    .slice(0, 5)
    .join(", ");

type Parsed<T> = { ok: true; value: T } | { ok: false; res: Response };

function parseWith<T>(c: Context, schema: z.ZodType<T>, input: unknown, what: string): Parsed<T> {
  const r = schema.safeParse(input);
  if (r.success) return { ok: true, value: r.data };
  return { ok: false, res: fail(c, 400, "api.bad_request", `invalid ${what}: ${issues(r.error)}`) };
}

/** Query params; a repeated key is rejected (ambiguous). */
function query<T>(c: Context, schema: z.ZodType<T>): Parsed<T> {
  const all = c.req.queries();
  for (const [k, v] of Object.entries(all)) {
    if (v.length > 1)
      return { ok: false, res: fail(c, 400, "api.bad_request", `repeated query parameter ${k}`) };
  }
  return parseWith(c, schema, c.req.query(), "query");
}

async function body<T>(c: Context, schema: z.ZodType<T>, allowEmpty: boolean): Promise<Parsed<T>> {
  const text = await c.req.text();
  if (text.trim() === "") {
    if (allowEmpty) return parseWith(c, schema, {}, "body");
    return { ok: false, res: fail(c, 400, "api.bad_request", "a JSON body is required") };
  }
  const type = (c.req.header("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") {
    return {
      ok: false,
      res: fail(c, 400, "api.bad_request", "Content-Type must be application/json"),
    };
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (e: unknown) {
    return {
      ok: false,
      res: fail(
        c,
        400,
        "api.bad_request",
        `body is not valid JSON (${e instanceof Error ? e.name : typeof e})`,
      ),
    };
  }
  return parseWith(c, schema, json, "body");
}

const DECISION_HTTP: Record<
  DecisionStatus,
  { status: 200 | ErrorStatus; code: string; message: string }
> = {
  approved: {
    status: 200,
    code: "approved",
    message: "Approved. The firewall is executing the action.",
  },
  rejected: { status: 200, code: "rejected", message: "Rejected. Nothing was executed." },
  expired: {
    status: 409,
    code: "approval.expired",
    message: "This approval has expired (treated as rejected). Nothing was executed.",
  },
  already_decided: {
    status: 409,
    code: "approval.already_decided",
    message: "This approval was already decided. Nothing changed.",
  },
  not_found: { status: 404, code: "approval.not_found", message: "No such approval." },
  unavailable: {
    status: 503,
    code: "approval.unavailable",
    message: "The firewall could not process this decision; nothing was executed.",
  },
};

export function createApi(o: ApiOptions): Api {
  const log = o.logger ?? (() => undefined);
  const token = parseAdminToken(o.adminToken);
  const hosts = allowedHostHeaders(o.port);
  const origins = new Set(o.allowedOrigins ?? defaultAllowedOrigins(o.port));
  /** The request's Origin iff it is on the allow-list (for CORS headers on early rejections). */
  const allowedOriginOf = (origin: string | undefined): string | undefined => {
    return origin !== undefined && origins.has(origin) ? origin : undefined;
  };
  const heartbeatMs = o.heartbeatMs ?? DEFAULT_HEARTBEAT_MS;
  const events = createEventHub({
    audit: o.audit,
    ...(o.approvals === undefined ? {} : { approvals: o.approvals }),
    maxSubscribers: o.maxEventStreams ?? DEFAULT_MAX_EVENT_STREAMS,
    ...(o.eventIntervalMs === undefined ? {} : { intervalMs: o.eventIntervalMs }),
    ...(o.ticker === undefined ? {} : { ticker: o.ticker }),
    logger: log,
  });
  const app = new Hono();

  app.onError((e, c) => {
    log(`api: ${c.req.method} ${c.req.path} threw ${e.name}`);
    return fail(c, 500, "api.internal_error", "internal error");
  });
  app.notFound((c) => fail(c, 404, "api.not_found", "no such route"));

  // 1. DNS rebinding: only our own loopback Host names.
  app.use("*", async (c, next) => {
    const host = c.req.header("host")?.toLowerCase();
    if (host === undefined || !hosts.has(host)) {
      return reject(
        403,
        "api.bad_host",
        "Host header not allowed",
        allowedOriginOf(c.req.header("origin")),
      );
    }
    await next();
  });

  // 2. Origin allow-list + exact-match CORS (no wildcard). Requests without Origin (curl, same-origin GET) pass.
  app.use("*", async (c, next) => {
    const origin = c.req.header("origin");
    if (origin !== undefined && !origins.has(origin)) {
      return reject(403, "api.bad_origin", "Origin not allowed");
    }
    if (origin !== undefined) {
      c.header("Access-Control-Allow-Origin", origin);
      c.header("Vary", "Origin");
    }
    if (c.req.method === "OPTIONS") {
      if (origin === undefined) return reject(403, "api.bad_origin", "preflight without Origin");
      c.header("Access-Control-Allow-Methods", "GET, POST");
      c.header("Access-Control-Allow-Headers", `content-type, ${ADMIN_TOKEN_HEADER}`);
      c.header("Access-Control-Max-Age", "600");
      return c.body(null, 204);
    }
    await next();
  });

  app.get("/health", (c) => c.json({ ok: true }));

  // 3. Admin token on everything else (constant-time compare). Unset / weak token ⇒ 503 (fail closed).
  app.use("*", async (c, next) => {
    const allowed = allowedOriginOf(c.req.header("origin"));
    if (!token.ok) {
      return reject(
        503,
        token.error.code,
        "the API is disabled: set a strong ASF_ADMIN_TOKEN",
        allowed,
      );
    }
    if (!tokenMatches(token.value, c.req.header(ADMIN_TOKEN_HEADER))) {
      return reject(401, "api.unauthorized", `missing or wrong ${ADMIN_TOKEN_HEADER}`, allowed);
    }
    await next();
  });

  app.use(
    "*",
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (c) => fail(c, 413, "api.body_too_large", "request body too large"),
    }),
  );

  app.get("/audit", (c) => {
    const q = query(c, auditQuerySchema);
    if (!q.ok) return q.res;
    const limit = q.value.limit ?? DEFAULT_PAGE_LIMIT;
    if (q.value.session !== undefined) {
      if (q.value.cursor !== undefined) {
        return fail(c, 400, "api.bad_request", "cursor cannot be combined with session");
      }
      const s = o.audit.readSession(q.value.session, limit);
      if (!s.ok) return fail(c, 500, s.error.code, "could not read the audit log");
      return c.json({ records: s.value.map(recordView), nextCursor: null });
    }
    const page = o.audit.readPage(
      q.value.cursor === undefined ? { limit } : { limit, beforeSeq: q.value.cursor },
    );
    if (!page.ok) return fail(c, 500, page.error.code, "could not read the audit log");
    const last = page.value.at(-1);
    return c.json({
      records: page.value.map(recordView),
      nextCursor:
        page.value.length === limit && last !== undefined && last.seq > 1 ? last.seq : null,
    });
  });

  app.get("/audit/verify", (c) => {
    const q = query(c, emptyQuerySchema);
    if (!q.ok) return q.res;
    const v = o.audit.verify();
    if (!v.ok) return fail(c, 500, v.error.code, "could not verify the audit log");
    const r = v.value;
    return c.json(
      r.ok
        ? {
            ok: true,
            count: r.count,
            headHash: r.headHash,
            danglingAttempts: r.danglingAttempts.length,
          }
        : { ok: false, brokenAt: r.brokenAt },
    );
  });

  app.get("/sessions/:id", (c) => {
    const p = parseWith(c, sessionParamSchema, c.req.param(), "session id");
    if (!p.ok) return p.res;
    const q = query(c, sessionQuerySchema);
    if (!q.ok) return q.res;
    const limit = q.value.limit ?? DEFAULT_SESSION_LIMIT;
    const s = o.audit.readSession(p.value.id, limit);
    if (!s.ok) return fail(c, 500, s.error.code, "could not read the audit log");
    return c.json({
      sessionId: p.value.id,
      records: s.value.map(recordView),
      truncated: s.value.length === limit,
    });
  });

  app.get("/approvals", (c) => {
    const q = query(c, approvalsQuerySchema);
    if (!q.ok) return q.res;
    if (o.approvals === undefined) {
      return fail(c, 503, "approvals.unavailable", "approvals are not configured in this proxy");
    }
    const rows = o.approvals.listPending(q.value.limit ?? MAX_APPROVALS_LIMIT);
    if (!rows.ok) return fail(c, 500, rows.error.code, "could not read approvals");
    const out = [];
    for (const row of rows.value) {
      const a = o.audit.readAttempt(row.attemptId);
      if (!a.ok) return fail(c, 500, a.error.code, "could not read the audit log");
      out.push(approvalView(row, a.value));
    }
    return c.json({ approvals: out });
  });

  const decide =
    (decision: "approved" | "rejected") =>
    async (c: Context): Promise<Response> => {
      const p = parseWith(c, approvalParamSchema, c.req.param(), "approval id");
      if (!p.ok) return p.res;
      const q = query(c, emptyQuerySchema);
      if (!q.ok) return q.res;
      const b = await body(c, decisionBodySchema, true);
      if (!b.ok) return b.res;
      if (o.approvalsEnabled !== true) {
        return fail(
          c,
          403,
          "api.approvals_disabled",
          "approving / rejecting through the API is disabled (set ASF_API_APPROVALS=1 on the proxy host); use Telegram",
        );
      }
      if (o.approvals === undefined) {
        return fail(c, 503, "approvals.unavailable", "approvals are not configured in this proxy");
      }
      if (decision === "approved") {
        // Don't consume the single-use approval while it could not execute anyway (fail closed on an unreadable
        // mode). `executeApproved` still re-checks the kill switch right before sending (race with a later toggle).
        const mode = o.modes.read();
        if (!mode.ok) {
          return fail(
            c,
            503,
            "mode.unreadable",
            "the firewall mode is unreadable; nothing was approved",
          );
        }
        if (mode.value.killSwitch) {
          return fail(
            c,
            409,
            "kill-switch",
            "the kill switch is ON; the approval was left pending. Turn it off first",
          );
        }
      }
      const approver = `dashboard:${b.value.actor ?? DEFAULT_ACTOR_SLUG}`;
      const status = await o.approvals.decide({ approvalId: p.value.id, decision, approver });
      const m = DECISION_HTTP[status];
      if (m.status !== 200) return fail(c, m.status, m.code, m.message);
      events.poll();
      return c.json({ approvalId: p.value.id, status, approver, message: m.message });
    };
  app.post("/approvals/:id/approve", decide("approved"));
  app.post("/approvals/:id/reject", decide("rejected"));

  app.get("/mode", (c) => {
    const q = query(c, emptyQuerySchema);
    if (!q.ok) return q.res;
    const m = o.modes.read();
    if (!m.ok) {
      return c.json(
        {
          error: { code: m.error.code, message: "the firewall mode is unreadable" },
          effective: { killSwitch: true, shadow: false },
        },
        503,
      );
    }
    return c.json({ mode: m.value });
  });

  const setMode = (
    c: Context,
    change: { killSwitch?: boolean; shadow?: boolean },
    actor: string | undefined,
  ): Response => {
    const r = o.modes.set({ ...change, actor: `dashboard:${actor ?? DEFAULT_ACTOR_SLUG}` });
    if (!r.ok) return fail(c, 500, r.error.code, "the mode change was NOT recorded");
    events.poll();
    return c.json({ changed: r.value.changed, mode: r.value.mode });
  };

  app.post("/killswitch", async (c) => {
    const q = query(c, emptyQuerySchema);
    if (!q.ok) return q.res;
    const b = await body(c, killSwitchBodySchema, false);
    if (!b.ok) return b.res;
    return setMode(c, { killSwitch: b.value.on }, b.value.actor);
  });

  app.post("/mode", async (c) => {
    const q = query(c, emptyQuerySchema);
    if (!q.ok) return q.res;
    const b = await body(c, modeBodySchema, false);
    if (!b.ok) return b.res;
    return setMode(c, { shadow: b.value.mode === "shadow" }, b.value.actor);
  });

  app.get("/events", (c) => {
    const q = query(c, emptyQuerySchema);
    if (!q.ok) return q.res;
    if (events.size >= (o.maxEventStreams ?? DEFAULT_MAX_EVENT_STREAMS)) {
      return fail(c, 503, "api.too_many_streams", "too many open event streams");
    }
    return streamSSE(c, async (stream) => {
      await new Promise<void>((resolve) => {
        let chain: Promise<void> = Promise.resolve();
        let finished = false;
        const cleanup: Array<() => void> = [];
        const finish = (): void => {
          if (finished) return;
          finished = true;
          for (const f of cleanup.splice(0)) f();
          resolve();
        };
        /** Run `f` on finish (at once if already finished). */
        const onFinish = (f: () => void): void => {
          if (finished) f();
          else cleanup.push(f);
        };
        const send = (event: string, data: string): void => {
          chain = chain
            .then(() => (finished ? undefined : stream.writeSSE({ event, data })))
            .catch((e: unknown) => {
              log(`api: event stream write failed (${e instanceof Error ? e.name : typeof e})`);
              finish();
            });
        };
        stream.onAbort(finish);
        const sub = events.subscribe((e: ApiEvent) => {
          if (e.type === "close") {
            void chain.then(finish);
            return;
          }
          send(e.type, JSON.stringify(e));
        });
        if (!sub.ok) {
          send("error", JSON.stringify({ type: "error", code: sub.error.code }));
          void chain.then(finish);
          return;
        }
        onFinish(sub.value);
        send("ready", JSON.stringify({ type: "ready" }));
        const beat = setInterval(() => {
          send("ping", "{}");
        }, heartbeatMs);
        beat.unref();
        onFinish(() => {
          clearInterval(beat);
        });
      });
    });
  });

  return {
    app,
    events,
    close: () => {
      events.close();
    },
  };
}
