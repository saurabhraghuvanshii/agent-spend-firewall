/**
 * The firewall's MCP server (T003): mirrors the upstream Razorpay MCP server's tools to the agent and forwards calls.
 *
 * - `tools/list`: the LIVE upstream list (name, description, inputSchema, annotations), passed through the `advertise`
 *   hook (default: unchanged; the CLI rewrites money tools, T004). If upstream can't
 *   be reached, the committed `docs/razorpay-tools.json` snapshot (`cachedTools`) is advertised instead, so an agent
 *   that lists tools once at startup still sees them; calls then fail with `upstream_unavailable` until upstream
 *   connects, and the agent gets `notifications/tools/list_changed` if the live list differs from what it saw.
 * - `tools/call`: the name must be EXACTLY one of the names upstream listed on the CURRENT connection generation
 *   (`LiveTools`). The cache, and lists from earlier generations or a list marked stale by `list_changed`, are never
 *   an allowlist for forwarding: without a validated live list for the current generation the call is refused
 *   (`upstream_unavailable` for a name we know of, else `firewall.unknown_tool`). Every call then goes through a
 *   `CallInterceptor` with the tool's class from `classifyTool` (pass-through by default; the CLI wires T004's
 *   `moneyArgsStage`; T008 adds the policy engine).
 *   An interceptor that throws ⇒ deny (fail closed). `forward` re-checks the name against the then-current list and
 *   pins the upstream generation, so a reconnect between the check and the send can't smuggle a call through. If the
 *   tool's input schema on that list differs from the one the interceptor validated against, the call is refused
 *   (`upstream_unavailable`, "tool schema changed; retry", not sent).
 * - Upstream failures become `isError: true` results with a JSON body `{ error, message, forwarded }`; the server
 *   never throws from `tools/call` and never crashes on upstream errors.
 * - An upstream result that contains the key id / secret in any encoding is replaced wholesale by an
 *   `upstream_error` result (never patched).
 *
 * All operator logging goes through `logger` (stderr in production: stdout is the MCP channel).
 */
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  ToolSchema,
  type CallToolResult,
  type RequestId,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { escapeForTerminal } from "./cli/audit-verify.js";
import { classifyTool, type ToolClass } from "./tool-classes.js";
import type { DiscoveredTool } from "./tool-discovery.js";
import { errorText } from "./tool-discovery.js";
import {
  describeTransportError,
  noRedact,
  type Logger,
  type Redactor,
  type UpstreamCallOutcome,
  type UpstreamErrorKind,
  type UpstreamPort,
} from "./upstream.js";

// ---------------------------------------------------------------------------------------------------------------
// Interceptor seam
// ---------------------------------------------------------------------------------------------------------------

export interface CallContext {
  /** Exact upstream tool name (already checked against the live upstream list). */
  readonly tool: string;
  readonly toolClass: ToolClass;
  /**
   * Arguments as sent by the agent (untrusted). A deep-frozen COPY: mutating it is impossible, and it is not what
   * gets forwarded — only the object passed to `forward` is.
   */
  readonly args: Readonly<Record<string, unknown>>;
  /**
   * The tool's ORIGINAL upstream input schema (as listed on the current generation), deep-frozen copy. Not the
   * advertised (rewritten) one: call-time checks re-derive that themselves (T004).
   */
  readonly inputSchema: Tool["inputSchema"];
  /**
   * The agent's `reason` for a money call, set by the T004 stage after validation and stripped from `args`.
   * UNTRUSTED free text: for audit / approver display only, never for allow decisions (D-004).
   */
  readonly untrustedReason?: string;
  readonly sessionId: string;
  /** Aborted when the agent cancels the request. */
  readonly signal: AbortSignal;
}

/**
 * Forwards `args` to upstream for `ctx.tool`. Never throws: upstream failures come back as `isError` results.
 *
 * Contract (enforced by the server, relied on by T004 / T008 / T010):
 * - CALL AT MOST ONCE per intercepted call. A second call ⇒ deny `firewall.forward_twice`; a call after `intercept`
 *   has settled (resolved or thrown) ⇒ deny `firewall.forward_after_settle`. Neither reaches upstream.
 * - `args` must be a plain JSON object (no prototypes other than Object, no functions / undefined / non-finite
 *   numbers / bigint / symbols, bounded depth) ⇒ else deny `firewall.invalid_forward_args`. It is copied at the
 *   moment of the call: exactly that value is sent; later mutation by the caller has no effect.
 * - T004: the interceptor strips `reason` from the args BEFORE calling `forward` (upstream never sees it); see
 *   `money-args.ts` / `interceptor-chain.ts`.
 * - T008: the interceptor writes the audit entry BEFORE calling `forward`, and records the outcome after.
 */
export type Forward = (args: Record<string, unknown>) => Promise<CallToolResult>;

export interface CallInterceptor {
  intercept(ctx: CallContext, forward: Forward): Promise<CallToolResult>;
}

/** T003 default: forward every call unchanged. Replaced by the reason check (T004) and the policy engine (T008). */
export const passThroughInterceptor: CallInterceptor = {
  intercept: (ctx, forward) => forward({ ...ctx.args }),
};

// ---------------------------------------------------------------------------------------------------------------
// Structured results
// ---------------------------------------------------------------------------------------------------------------

export interface DenyBody {
  readonly decision: "deny";
  readonly ruleId: string;
  readonly message: string;
}

export interface UpstreamErrorBody {
  readonly error: "upstream_unavailable" | "upstream_timeout" | "upstream_error" | "cancelled";
  readonly message: string;
  readonly forwarded: boolean;
}

export function jsonErrorResult(body: DenyBody | UpstreamErrorBody): CallToolResult {
  return { isError: true, content: [{ type: "text", text: JSON.stringify(body) }] };
}

export function denyResult(ruleId: string, message: string): CallToolResult {
  return jsonErrorResult({ decision: "deny", ruleId, message });
}

const UNAVAILABLE: UpstreamErrorBody = {
  error: "upstream_unavailable",
  message: "the upstream Razorpay MCP server is unavailable; the call was not sent",
  forwarded: false,
};

/** Replacement for an upstream result that echoed credential material. */
export const CREDENTIAL_LEAK_RESULT: CallToolResult = Object.freeze(
  jsonErrorResult({
    error: "upstream_error",
    message: "upstream response contained credential material",
    forwarded: true,
  }),
);

// ---------------------------------------------------------------------------------------------------------------
// Forward reports (T008)
// ---------------------------------------------------------------------------------------------------------------

/**
 * What `forward` did, attached (out of band) to EVERY result object `forward` returns, so the audit stage can record
 * an accurate outcome without parsing agent-facing text.
 *
 * - `kind: "ok"` — upstream answered (the tool result's own `isError` may still be true).
 * - `kind: "credential_leak"` — upstream answered, but the result echoed credential material and was replaced by a
 *   fresh copy of `CREDENTIAL_LEAK_RESULT`. `sent: true`: the action may have executed.
 * - `kind: UpstreamErrorKind` — the upstream call failed; `sent` mirrors `UpstreamCallOutcome.forwarded`.
 * - `kind: "refused"` — the server refused before sending (forward twice / after settle, invalid args, unknown
 *   tool, schema changed). `sent: false`.
 */
export interface ForwardReport {
  readonly sent: boolean;
  readonly kind: "ok" | "credential_leak" | "refused" | UpstreamErrorKind;
  /** Integer ms spent in the upstream call (0 if nothing was sent). */
  readonly latencyMs: number;
  readonly requestId?: RequestId;
  readonly generation?: number;
}

const forwardReports = new WeakMap<CallToolResult, ForwardReport>();

/**
 * The report for a result returned by the server's `forward`, or `undefined` for any other object (a result built by
 * an interceptor, or a copy of a forwarded result — reports are keyed by object identity).
 */
export function forwardReportOf(r: CallToolResult): ForwardReport | undefined {
  return forwardReports.get(r);
}

/** Fresh (shallow-copied) result tagged with `report`; never tags a shared/frozen constant. */
function tagged(r: CallToolResult, report: ForwardReport): CallToolResult {
  const fresh: CallToolResult = { ...r };
  forwardReports.set(fresh, Object.freeze({ ...report }));
  return fresh;
}

// ---------------------------------------------------------------------------------------------------------------
// Argument hygiene
// ---------------------------------------------------------------------------------------------------------------

const MAX_ARG_DEPTH = 32;

/** Plain JSON value: null, boolean, finite number, string, array, or object with Object/null prototype. */
function isPlainJson(value: unknown, depth: number): boolean {
  if (depth > MAX_ARG_DEPTH) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((v) => isPlainJson(v, depth + 1));
  if (typeof value === "object") return isPlainJsonObject(value, depth);
  return false;
}

function isPlainJsonObject(value: unknown, depth = 0): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  for (const k of Object.keys(value)) {
    const d = Object.getOwnPropertyDescriptor(value, k);
    if (d === undefined || !("value" in d)) return false; // accessors are not JSON
    if (!isPlainJson(d.value, depth + 1)) return false;
  }
  return true;
}

/** Deterministic JSON (object keys sorted) for comparing schemas across listings. */
export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

const SCHEMA_CHANGED: UpstreamErrorBody = {
  error: "upstream_unavailable",
  message: "tool schema changed; retry",
  forwarded: false,
};

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) deepFreeze(v);
  }
  return value;
}

// ---------------------------------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------------------------------

export const PROXY_SERVER_INFO = { name: "agent-spend-firewall", version: "0.0.0" } as const;

export interface ProxyServerOptions {
  readonly upstream: UpstreamPort;
  readonly interceptor?: CallInterceptor;
  /** Snapshot advertised ONLY while the live upstream list is unavailable (e.g. `docs/razorpay-tools.json`). */
  readonly cachedTools?: readonly DiscoveredTool[];
  /**
   * Per-tool view of what is advertised to the agent (seam for T004's schema rewrite). Default: unchanged.
   * Applies to live and cached tools alike.
   */
  readonly advertise?: (tool: Tool, toolClass: ToolClass) => Tool;
  readonly callTimeoutMs?: number;
  readonly logger?: Logger;
  /** Applied to every message derived from upstream / errors before it reaches the agent or the log. */
  readonly redact?: Redactor;
  /** Used when the transport has no session id (stdio). Default: random UUID per server instance. */
  readonly sessionId?: string;
  /**
   * Applied to every result the interceptor returns, just before it goes to the AGENT (e.g. card / PII redaction of
   * read results, T008). Interceptors and audit stages see the unfiltered result. A filter that throws ⇒ an
   * `upstream_error` result (`forwarded` says whether this call reached upstream).
   */
  readonly resultFilter?: (tool: string, result: CallToolResult) => CallToolResult;
  /** Epoch-ms clock for `ForwardReport.latencyMs`. Default `Date.now`. */
  readonly now?: () => number;
}

export interface ProxyServer {
  readonly server: Server;
  connect(transport: Transport): Promise<void>;
  close(): Promise<void>;
}

/** A validated upstream tool list, bound to the connection generation it was listed on. */
interface LiveTools {
  readonly generation: number;
  readonly tools: ReadonlyMap<string, Tool>;
}

/** Validate a discovered tool into the SDK `Tool` shape. Invalid ⇒ `undefined` (not advertised, not callable). */
function toTool(t: DiscoveredTool): Tool | undefined {
  const parsed = ToolSchema.safeParse({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
    ...(t.annotations === undefined ? {} : { annotations: t.annotations }),
  });
  return parsed.success ? parsed.data : undefined;
}

export function createProxyServer(opts: ProxyServerOptions): ProxyServer {
  const upstream = opts.upstream;
  const interceptor = opts.interceptor ?? passThroughInterceptor;
  const log: Logger = opts.logger ?? (() => undefined);
  const redact: Redactor = opts.redact ?? noRedact;
  const advertise = opts.advertise ?? ((t: Tool) => t);
  const fallbackSessionId = opts.sessionId ?? randomUUID();
  const now = opts.now ?? Date.now;
  const resultFilter = opts.resultFilter;

  const cached = new Map<string, Tool>();
  for (const t of opts.cachedTools ?? []) {
    const tool = toTool(t);
    if (tool !== undefined) cached.set(tool.name, tool);
  }

  /**
   * Last validated upstream list. Usable for forwarding ONLY while `!stale && live.generation === upstream.generation`
   * (see `currentLive`); otherwise it only helps choose between `upstream_unavailable` and `unknown_tool`. Cleared as
   * soon as the upstream generation moves on.
   */
  let live: LiveTools | undefined;
  /** Set by upstream `list_changed`: `live` must be re-listed before it is used again. */
  let stale = false;
  let refreshing: Promise<LiveTools | undefined> | undefined;
  /** Tools last advertised to the agent, to decide whether to send `list_changed`. */
  let advertisedKey: string | undefined;

  const server = new Server(
    { name: PROXY_SERVER_INFO.name, version: PROXY_SERVER_INFO.version },
    { capabilities: { tools: { listChanged: true } } },
  );
  // Agent-side transport / parse errors: class + fixed category only (messages can embed the agent's input).
  server.onerror = (e: Error) => {
    log(`agent channel ${describeTransportError(e)}`);
  };
  let agentConnected = false;

  const listKey = (tools: Iterable<Tool>): string => JSON.stringify([...tools]);

  const notifyListChanged = (): void => {
    if (!agentConnected) return;
    server.sendToolListChanged().catch((e: unknown) => {
      log(`sending tools/list_changed failed: ${escapeForTerminal(redact(errorText(e)))}`);
    });
  };

  const unsubscribe = upstream.onToolListChanged(() => {
    log("upstream tool list changed; re-listing");
    stale = true;
    void refresh();
  });

  /** The live list iff it is valid for the current upstream connection; never a previous generation's. */
  const currentLive = (): LiveTools | undefined => {
    if (live === undefined) return undefined;
    if (live.generation !== upstream.generation) {
      live = undefined;
      return undefined;
    }
    return !stale && upstream.isConnected() ? live : undefined;
  };

  /**
   * (Re)list upstream tools if needed. Resolves to the validated list for the CURRENT generation, or `undefined` if
   * there is none (upstream down, re-list failed, or the generation changed during listing). Callers must use the
   * returned value — not `live` — for both the name check and the forward decision.
   */
  const refresh = (): Promise<LiveTools | undefined> => {
    const current = currentLive();
    if (current !== undefined) return Promise.resolve(current);
    refreshing ??= doRefresh().finally(() => {
      refreshing = undefined;
    });
    return refreshing;
  };

  const doRefresh = async (): Promise<LiveTools | undefined> => {
    const listed = await upstream.listTools();
    if (!listed.ok) {
      log(`upstream tools/list unavailable: ${escapeForTerminal(redact(listed.error.message))}`);
      currentLive(); // drops a previous generation's list
      return undefined;
    }
    if (listed.value.generation !== upstream.generation || !upstream.isConnected()) {
      log("upstream reconnected while listing tools; the list was discarded");
      currentLive();
      return undefined;
    }
    const next = new Map<string, Tool>();
    for (const d of listed.value.tools) {
      const tool = toTool(d);
      if (tool === undefined) {
        log(`upstream tool ${escapeForTerminal(d.name)} has an invalid definition; not exposed`);
        continue;
      }
      next.set(tool.name, tool);
    }
    const fresh: LiveTools = { generation: listed.value.generation, tools: next };
    live = fresh;
    stale = false;
    const key = listKey(advertisedView(next));
    if (advertisedKey !== undefined && advertisedKey !== key) notifyListChanged();
    return fresh;
  };

  const advertisedView = (tools: ReadonlyMap<string, Tool>): Tool[] =>
    [...tools.values()].map((t) => advertise(t, classifyTool(t.name)));

  /** No usable live list: a name we know of (cache or last live list) ⇒ unavailable; anything else ⇒ unknown. */
  const notAvailable = (name: string): CallToolResult =>
    cached.has(name) || live?.tools.has(name) === true
      ? jsonErrorResult(UNAVAILABLE)
      : unknownTool(name);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const current = await refresh();
    if (current !== undefined) {
      const tools = advertisedView(current.tools);
      advertisedKey = listKey(tools);
      return { tools };
    }
    if (cached.size > 0) {
      log(
        "advertising the cached tool list (upstream unavailable); calls fail until upstream connects",
      );
      const tools = advertisedView(cached);
      advertisedKey = listKey(tools);
      return { tools };
    }
    throw new McpError(
      ErrorCode.InternalError,
      "upstream Razorpay MCP server is unavailable and no cached tool list is configured",
    );
  });

  /*
   * Server-level rejections BEFORE the interceptor — no usable upstream list (`upstream_unavailable`, incl. a failed
   * re-check), a name not on the current list (`firewall.unknown_tool`), non-object arguments
   * (`firewall.invalid_args`) — are deliberately NOT audited: nothing is sent upstream, and neither the tool (not a
   * listed upstream tool) nor the args (not a JSON object) are trustworthy enough to record against a tool name.
   * They also bypass `resultFilter` (their bodies are firewall-authored and contain no upstream data). Every call that
   * reaches the interceptor as a money call is audited there (see interceptor.ts).
   */
  server.setRequestHandler(
    CallToolRequestSchema,
    async (request, extra): Promise<CallToolResult> => {
      const name = request.params.name;
      const rawArgs: unknown = request.params.arguments ?? {};
      try {
        // Exact match (Map: no prototype keys, no case folding) against the list for the CURRENT generation only.
        const current = await refresh();
        if (current === undefined) return notAvailable(name);
        const listedTool = current.tools.get(name);
        if (listedTool === undefined) return unknownTool(name);
        if (!isPlainJsonObject(rawArgs)) {
          return denyResult(
            "firewall.invalid_args",
            "tool arguments must be a plain JSON object; the call was not sent",
          );
        }

        // The interceptor validates against THIS schema; forward refuses if the schema it would send under differs.
        const schemaKey = stableStringify(listedTool.inputSchema);
        const ctx: CallContext = {
          tool: name,
          toolClass: classifyTool(name),
          args: deepFreeze(structuredClone(rawArgs)),
          inputSchema: deepFreeze(structuredClone(listedTool.inputSchema)),
          sessionId: extra.sessionId ?? fallbackSessionId,
          signal: extra.signal,
        };

        let forwardUsed = false;
        let settled = false;
        /** Set once `upstream.callTool` was invoked for this call (it may have reached Razorpay). */
        let sendAttempted = false;
        const refused = (r: CallToolResult): CallToolResult =>
          tagged(r, { sent: false, kind: "refused", latencyMs: 0 });
        const forward: Forward = async (forwardArgs) => {
          if (settled) {
            log(`interceptor called forward after settling (${escapeForTerminal(name)}); refused`);
            return refused(
              denyResult(
                "firewall.forward_after_settle",
                "the firewall refused a late forward of this call; it was not sent",
              ),
            );
          }
          if (forwardUsed) {
            log(`interceptor called forward twice (${escapeForTerminal(name)}); refused`);
            return refused(
              denyResult(
                "firewall.forward_twice",
                "the firewall refused to send this call twice; the second send was not made",
              ),
            );
          }
          forwardUsed = true;
          // Validate the given value (structuredClone would silently drop prototypes), then validate the copy that
          // is actually sent, so later mutation by the interceptor can't change it.
          let toSend: unknown;
          if (isPlainJsonObject(forwardArgs)) {
            try {
              toSend = structuredClone(forwardArgs);
            } catch {
              toSend = undefined; // not cloneable ⇒ not plain JSON; rejected below
            }
          }
          if (!isPlainJsonObject(toSend)) {
            return refused(
              denyResult(
                "firewall.invalid_forward_args",
                "the firewall could not forward this call (arguments are not a plain JSON object); it was not sent",
              ),
            );
          }
          // Re-check against the list for the generation we will send on; pin that generation.
          const current = await refresh();
          if (current === undefined) return refused(notAvailable(name));
          const nowTool = current.tools.get(name);
          if (nowTool === undefined) return refused(unknownTool(name));
          if (stableStringify(nowTool.inputSchema) !== schemaKey) {
            log(`schema of ${escapeForTerminal(name)} changed during the call; refused`);
            return refused(jsonErrorResult(SCHEMA_CHANGED));
          }
          sendAttempted = true;
          const started = now();
          const outcome = await upstream.callTool(name, toSend, {
            signal: extra.signal,
            expectedGeneration: current.generation,
            ...(opts.callTimeoutMs === undefined ? {} : { timeoutMs: opts.callTimeoutMs }),
          });
          const latencyMs = elapsedMs(started, now());
          const result = toCallResult(name, outcome);
          if (outcome.kind === "ok") {
            const leak = result === CREDENTIAL_LEAK_RESULT;
            return tagged(result, {
              sent: true,
              kind: leak ? "credential_leak" : "ok",
              latencyMs,
              generation: current.generation,
            });
          }
          return tagged(result, {
            sent: outcome.forwarded,
            kind: outcome.error,
            latencyMs: outcome.forwarded ? latencyMs : 0,
            ...(outcome.requestId === undefined ? {} : { requestId: outcome.requestId }),
            generation: outcome.generation ?? current.generation,
          });
        };
        let result: CallToolResult;
        try {
          result = await interceptor.intercept(ctx, forward);
        } catch (e: unknown) {
          log(
            `interceptor failed for ${escapeForTerminal(name)}: ${escapeForTerminal(redact(errorText(e)))}`,
          );
          return denyResult(
            "firewall.interceptor_error",
            sendAttempted
              ? "the firewall failed after this call was sent upstream; check its status before retrying"
              : "the firewall could not evaluate this call; it was denied (fail closed)",
          );
        } finally {
          settled = true;
        }
        if (resultFilter === undefined) return result;
        try {
          return resultFilter(name, result);
        } catch (e: unknown) {
          log(
            `result filter failed for ${escapeForTerminal(name)}: ${e instanceof Error ? e.name : typeof e}; result withheld`,
          );
          return jsonErrorResult({
            error: "upstream_error",
            message:
              "the firewall could not safely return this result; it was withheld" +
              (sendAttempted ? " (the call was sent: check its status before retrying)" : ""),
            forwarded: sendAttempted,
          });
        }
      } catch (e: unknown) {
        log(
          `tools/call ${escapeForTerminal(name)} failed: ${escapeForTerminal(redact(errorText(e)))}`,
        );
        return denyResult(
          "firewall.internal_error",
          "the firewall failed while handling this call; it was denied",
        );
      }
    },
  );

  const unknownTool = (name: string): CallToolResult =>
    denyResult(
      "firewall.unknown_tool",
      `unknown tool ${JSON.stringify(name.slice(0, 128))}: not offered by the upstream Razorpay MCP server`,
    );

  const toCallResult = (name: string, outcome: UpstreamCallOutcome): CallToolResult => {
    if (outcome.kind === "ok") {
      const screened = screenResult(outcome.result, redact);
      if (screened === CREDENTIAL_LEAK_RESULT) {
        log(
          `upstream result for ${escapeForTerminal(name)} contained credential material; replaced with an error`,
        );
      }
      return screened;
    }
    return jsonErrorResult({
      error: outcome.error,
      message: redact(outcome.message),
      forwarded: outcome.forwarded,
    });
  };

  return {
    server,
    connect: async (transport) => {
      await server.connect(transport);
      agentConnected = true;
    },
    close: async () => {
      unsubscribe();
      agentConnected = false;
      await server.close();
    },
  };
}

function elapsedMs(start: number, end: number): number {
  const d = Math.round(end - start);
  return Number.isSafeInteger(d) && d > 0 ? d : 0;
}

/**
 * Defense in depth: if an upstream result contains the key id / secret in any known encoding ANYWHERE (values or
 * object keys), the whole result is replaced by `CREDENTIAL_LEAK_RESULT` — never patched, since a partially
 * redacted result can still leak structure or be mis-read. Results without credential material are returned as
 * the same object. `noRedact` (no keys configured) ⇒ unchanged.
 */
export function screenResult(result: CallToolResult, redact: Redactor): CallToolResult {
  if (redact === noRedact) return result;
  let text: string;
  try {
    text = JSON.stringify(result);
  } catch {
    return CREDENTIAL_LEAK_RESULT; // can't inspect ⇒ fail closed
  }
  return redact(text) === text ? result : CREDENTIAL_LEAK_RESULT;
}
