/**
 * Real adapters for the policy ports (T007): history / velocity from the audit store, payment lookups through the
 * upstream Razorpay MCP server, and system clock / timer. Also the firewall's own order lookup (`createOrderLookup`,
 * T008 INR invariant for order-based money tools; not a policy port).
 *
 * Semantics (D-023, amended by T010): an audited action counts toward history / velocity iff
 * - `countsTowardLimits({ decision, outcome, verification })` (executed, possibly executed, unknown, or pending;
 *   never denied / not forwarded / verified `not_happened`),
 * - its tool is one of the queried tools,
 * - its attempt id is not in `excludeAttemptIds` (e.g. the attempt being evaluated), and
 * - its activity time is in range:
 *   - CLOSED actions (an outcome was recorded): `activityTs(attempt.ts, outcome.ts, verification.ts)` is at or after
 *     `now − window`; an action whose latest verification is `unknown` counts regardless of time (T010, no age-out —
 *     within the rows the audit read returns);
 *   - OPEN actions (decision allow / transform / require_approval with NO outcome yet: in flight, awaiting or
 *     approved-but-not-executed approval) count for EVERY window as long as they are younger than
 *     `openLookbackMs` (default 24 h). A still-pending approval can execute at any moment, so it must keep
 *     blocking duplicates and counting toward velocity after the query window has passed;
 *   - an unparseable time counts (fail closed).
 *
 * Matching contract (T008, MUST hold for duplicate detection to be correct): every money attempt MUST be recorded
 * with the args that are actually forwarded upstream — i.e. AFTER any `transform` patch is applied — in
 * `RecordAttemptInput.args`. History matching and velocity sums read `argsRedacted` (top-level `amount`,
 * `payment_id`, …); recording the pre-transform args would make a transformed refund invisible to
 * `refund.duplicate` and mis-count `sumLast`.
 *
 * All history / stats queries of one `createPolicyDeps` bundle share ONE memoised audit read (see
 * `createPolicyDeps`).
 *
 * Every failure is an `err` Result (the engine then denies). Error messages and details never contain tool
 * arguments, payment payloads or other PII.
 */
import {
  activityTs,
  argsMatch,
  blocksIndefinitely,
  countsTowardLimits,
  err,
  ok,
  redact,
  type Args,
  type Clock,
  type HistoryPort,
  type HistoryQuery,
  type PaymentInfo,
  type PolicyDeps,
  type RazorpayLookupPort,
  type Result,
  type StatsPort,
  type StatsQuery,
  type StatsSummary,
  type Timer,
  type TimerHandle,
} from "@asf/core";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { AuditActivity, AuditStore } from "./audit-store.js";
import { countableOf } from "./idempotency.js";
import { CREDENTIAL_LEAK_RESULT, screenResult } from "./server.js";
import { classifyTool } from "./tool-classes.js";
import { noRedact, type CallOptions, type Redactor, type UpstreamCallOutcome } from "./upstream.js";

/** Upstream read tool used for payment lookups (classified `read`, D-019). */
export const FETCH_PAYMENT_TOOL = "fetch_payment";
export const DEFAULT_LOOKUP_TIMEOUT_MS = 1500;
/**
 * Max payment lookup timeout: below the engine's default whole-evaluation budget (`DEFAULT_POLICY_TIMEOUT_MS`,
 * 2000 ms) so a slow lookup surfaces as a lookup error rather than racing the engine timeout.
 */
export const MAX_LOOKUP_TIMEOUT_MS = 1900;
/** Default age limit for OPEN (no-outcome) attempts to keep counting regardless of the query window. */
export const DEFAULT_OPEN_LOOKBACK_MS = 24 * 60 * 60 * 1000;
/** Bounds for `openLookbackMs` (integer ms). */
export const MIN_OPEN_LOOKBACK_MS = 60_000;
export const MAX_OPEN_LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000;
/** Razorpay payment id accepted for lookups. Anything else is refused without calling upstream. */
export const PAYMENT_ID_PATTERN = /^pay_[A-Za-z0-9]{1,40}$/;
/** Upper bound on the text of a `fetch_payment` result we are willing to parse. */
export const MAX_LOOKUP_TEXT_CHARS = 256 * 1024;

/** The slice of `UpstreamPort` the lookup needs (narrow, so tests can fake it). */
export interface UpstreamPaymentPort {
  callTool(
    name: string,
    args: Record<string, unknown>,
    opts?: CallOptions,
  ): Promise<UpstreamCallOutcome>;
}

/** The slice of `AuditStore` the history / stats adapters need. */
export type ActivitySource = Pick<AuditStore, "readActivitySince">;

export interface AdapterOpts {
  readonly store: ActivitySource;
  readonly upstream: UpstreamPaymentPort;
  readonly clock: Clock;
  /** Upstream timeout for one payment lookup, integer ms 1..`MAX_LOOKUP_TIMEOUT_MS` (default 1500). */
  readonly lookupTimeoutMs?: number;
  /** Attempts never counted (e.g. the attempt currently being evaluated). */
  readonly excludeAttemptIds?: ReadonlySet<string>;
  /**
   * Credential redactor (same as the proxy's). A lookup result containing credential material is rejected.
   * Default: no screening.
   */
  readonly redact?: Redactor;
  /**
   * OPEN attempts (no outcome yet) younger than this count toward every history / stats window (default 24 h,
   * integer ms in `[MIN_OPEN_LOOKBACK_MS, MAX_OPEN_LOOKBACK_MS]`; anything else ⇒ every query fails closed).
   */
  readonly openLookbackMs?: number;
}

// ---------------------------------------------------------------------------------------------------------------
// System clock / timer
// ---------------------------------------------------------------------------------------------------------------

export const systemClock: Clock = Object.freeze({
  nowMs: (): number => Date.now(),
});

/** `setTimeout`-backed timer. Unref'd so a pending budget timer never keeps the process alive. */
export const systemTimer: Timer = Object.freeze({
  after(ms: number): TimerHandle {
    let handle: ReturnType<typeof setTimeout> | undefined;
    const promise = new Promise<void>((resolve) => {
      handle = setTimeout(resolve, ms);
      handle.unref();
    });
    return {
      promise,
      cancel(): void {
        if (handle !== undefined) clearTimeout(handle);
      },
    };
  },
});

// ---------------------------------------------------------------------------------------------------------------
// History / stats
// ---------------------------------------------------------------------------------------------------------------

function isPositiveSafeInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v > 0;
}

function nowMs(clock: Clock): Result<number> {
  try {
    const now = clock.nowMs();
    if (!Number.isSafeInteger(now) || now < 0)
      return err("context.clock_invalid", "clock returned an invalid time");
    return ok(now);
  } catch {
    return err("context.clock_invalid", "clock threw");
  }
}

/** Reads audit activity since a cutoff (epoch ms). */
export type ActivityReader = (sinceMs: number) => Result<AuditActivity[]>;

function directReader(store: ActivitySource): ActivityReader {
  return (sinceMs) => store.readActivitySince(sinceMs);
}

/**
 * Memoised reader shared by one evaluation's ports: the first call reads the store, later calls whose cutoff is at
 * or after the cached cutoff reuse that snapshot (callers re-filter by their own window). A read error is cached
 * too, so one evaluation never sees a mix of failed and successful reads. A cutoff earlier than the snapshot (a
 * window longer than the snapshot, or a clock regression) re-reads and replaces the snapshot.
 */
export function memoisedReader(store: ActivitySource): ActivityReader {
  let cached: { sinceMs: number; result: Result<AuditActivity[]> } | undefined;
  return (sinceMs) => {
    if (cached !== undefined && (!cached.result.ok || sinceMs >= cached.sinceMs)) {
      return cached.result;
    }
    const result = store.readActivitySince(sinceMs);
    cached = { sinceMs, result };
    return result;
  };
}

function openLookbackMs(o: AdapterOpts): Result<number> {
  const v = o.openLookbackMs ?? DEFAULT_OPEN_LOOKBACK_MS;
  if (!Number.isSafeInteger(v) || v < MIN_OPEN_LOOKBACK_MS || v > MAX_OPEN_LOOKBACK_MS) {
    return err("context.invalid_config", "invalid openLookbackMs");
  }
  return ok(v);
}

/** Activity counted for `tools` within `windowMs` of now, per the module-level semantics. */
function countedActivity(
  o: AdapterOpts,
  read: ActivityReader,
  tools: ReadonlySet<string>,
  windowMs: number,
): Result<AuditActivity[]> {
  const lookback = openLookbackMs(o);
  if (!lookback.ok) return lookback;
  const now = nowMs(o.clock);
  if (!now.ok) return now;
  const cutoff = now.value - windowMs;
  const openCutoff = now.value - lookback.value;
  const rows = read(Math.min(cutoff, openCutoff));
  if (!rows.ok) {
    return err("context.audit_unavailable", "audit activity could not be read", {
      cause: rows.error.code,
    });
  }
  const exclude = o.excludeAttemptIds;
  const counted: AuditActivity[] = [];
  for (const a of rows.value) {
    const open = a.outcome === undefined;
    const countable = countableOf(a);
    if (!countsTowardLimits(countable)) continue;
    if (!tools.has(a.attempt.tool)) continue;
    if (exclude?.has(a.attempt.id) === true) continue;
    if (!blocksIndefinitely(countable)) {
      const ts = activityTs(a.attempt.ts, a.outcome?.ts, a.verification?.ts);
      // Unparseable time ⇒ treat as inside every window (fail closed).
      if (ts !== undefined && ts < (open ? openCutoff : cutoff)) continue;
    }
    counted.push(a);
  }
  return ok(counted);
}

export function createHistoryPort(o: AdapterOpts): HistoryPort {
  return historyPort(o, directReader(o.store));
}

/**
 * True iff `redact` keeps every key of `match` unchanged. A renamed key (one that itself looks like PII, e.g. an
 * email address) can never equal a stored redacted key, so such a query would silently never match.
 */
function matchKeysSurviveRedaction(match: Args): boolean {
  const red: unknown = redact(match);
  if (typeof red !== "object" || red === null || Array.isArray(red)) return false;
  const before = Object.keys(match);
  const after = Object.keys(red);
  if (before.length !== after.length) return false;
  return before.every((k) => Object.hasOwn(red, k));
}

function historyPort(o: AdapterOpts, read: ActivityReader): HistoryPort {
  return {
    hasRecent(q: HistoryQuery): Promise<Result<boolean>> {
      try {
        if (typeof q !== "object" || q === null) return Promise.resolve(badQuery("history"));
        const { tool, match, withinMs } = q;
        if (typeof tool !== "string" || tool === "" || !isPositiveSafeInt(withinMs)) {
          return Promise.resolve(badQuery("history"));
        }
        if (typeof match !== "object" || match === null || Array.isArray(match)) {
          return Promise.resolve(badQuery("history"));
        }
        if (!matchKeysSurviveRedaction(match)) {
          return Promise.resolve(
            err("history.unmatchable_query", "a history match key is removed by redaction"),
          );
        }
        const rows = countedActivity(o, read, new Set([tool]), withinMs);
        if (!rows.ok) return Promise.resolve(rows);
        return Promise.resolve(
          ok(rows.value.some((a) => argsMatch(a.attempt.argsRedacted, match))),
        );
      } catch {
        return Promise.resolve(err("context.history_failed", "history lookup failed"));
      }
    },
  };
}

export function createStatsPort(o: AdapterOpts): StatsPort {
  return statsPort(o, directReader(o.store));
}

function statsPort(o: AdapterOpts, read: ActivityReader): StatsPort {
  return {
    sumLast(q: StatsQuery): Promise<Result<StatsSummary>> {
      try {
        if (typeof q !== "object" || q === null) return Promise.resolve(badQuery("stats"));
        const { tools, windowMs } = q;
        if (!Array.isArray(tools) || tools.length === 0 || !isPositiveSafeInt(windowMs)) {
          return Promise.resolve(badQuery("stats"));
        }
        const toolSet = new Set<string>();
        for (const t of tools as readonly unknown[]) {
          if (typeof t !== "string" || t === "") return Promise.resolve(badQuery("stats"));
          toolSet.add(t);
        }
        const rows = countedActivity(o, read, toolSet, windowMs);
        if (!rows.ok) return Promise.resolve(rows);
        let amountPaise = 0;
        for (const a of rows.value) {
          const amount = topLevelAmount(a.attempt.argsRedacted);
          if (amount === undefined) {
            // A counted action whose amount we can't read could be any size: refuse to under-count.
            return Promise.resolve(
              err("context.amount_unreadable", "a recent action has no readable amount", {
                seq: a.attempt.seq,
              }),
            );
          }
          amountPaise += amount;
          if (!Number.isSafeInteger(amountPaise)) {
            return Promise.resolve(err("context.amount_overflow", "recent amounts overflow"));
          }
        }
        return Promise.resolve(ok({ amountPaise, count: rows.value.length }));
      } catch {
        return Promise.resolve(err("context.stats_failed", "stats lookup failed"));
      }
    },
  };
}

function badQuery<T>(port: "history" | "stats"): Result<T> {
  return err("context.invalid_query", `invalid ${port} query`);
}

function topLevelAmount(args: unknown): number | undefined {
  if (typeof args !== "object" || args === null || Array.isArray(args)) return undefined;
  if (!Object.hasOwn(args, "amount")) return undefined;
  const v: unknown = (args as Record<string, unknown>)["amount"];
  return isPositiveSafeInt(v) ? v : undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Razorpay payment lookup (via upstream MCP `fetch_payment`)
// ---------------------------------------------------------------------------------------------------------------

const paymentSchema = z
  .looseObject({
    id: z.string(),
    status: z.string(),
    amount: z.int().nonnegative(),
    amount_refunded: z.int().nonnegative(),
    currency: z.string(),
  })
  .refine((p) => p.amount_refunded <= p.amount);

const lookupErr = <T>(code: string, message: string): Result<T> => err(`razorpay.${code}`, message);

function validTimeout(timeoutMs: number): boolean {
  return Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= MAX_LOOKUP_TIMEOUT_MS;
}

/**
 * Shared strict lookup through an upstream READ tool: the tool must classify as `read`, `id` must match `idPattern`,
 * the call is bounded by `timeoutMs`, the result is credential-screened and must be exactly one JSON text item.
 * Returns the parsed JSON (validated by the caller). `what` names the entity in error messages ("payment"/"order").
 */
async function strictLookup(
  o: AdapterOpts,
  tool: string,
  argName: string,
  id: string,
  idPattern: RegExp,
  what: string,
): Promise<Result<unknown>> {
  const timeoutMs = o.lookupTimeoutMs ?? DEFAULT_LOOKUP_TIMEOUT_MS;
  const redact = o.redact ?? noRedact;
  try {
    if (!validTimeout(timeoutMs)) {
      return lookupErr("invalid_config", `invalid ${what} lookup timeout`);
    }
    // Defense in depth: never route a lookup through a tool that isn't classified read-only.
    if (classifyTool(tool) !== "read") {
      return lookupErr("invalid_config", `${what} lookup tool is not a read tool`);
    }
    if (typeof id !== "string" || !idPattern.test(id)) {
      return lookupErr("invalid_id", `${what} id is not a Razorpay ${what} id`);
    }
    const outcome = await o.upstream.callTool(tool, { [argName]: id }, { timeoutMs });
    if (outcome.kind !== "ok") {
      return lookupErr(
        outcome.error === "upstream_timeout" ? "timeout" : "unavailable",
        `${what} lookup did not complete`,
      );
    }
    return parseSingleJson(screenResult(outcome.result, redact), what);
  } catch {
    return lookupErr("lookup_failed", `${what} lookup failed`);
  }
}

/**
 * Exactly one JSON text item of a (credential-screened) lookup result, parsed; `err` (`razorpay.*`) otherwise.
 * Shared with T010's action verifier.
 */
export function parseSingleJson(result: CallToolResult, what: string): Result<unknown> {
  if (result === CREDENTIAL_LEAK_RESULT) {
    return lookupErr("credential_leak", `${what} lookup result contained credential material`);
  }
  if (result.isError === true)
    return lookupErr("upstream_error", `${what} lookup returned an error`);
  const content: unknown = result.content;
  if (!Array.isArray(content) || content.length !== 1) {
    return lookupErr("malformed", `${what} lookup result has unexpected content`);
  }
  const item: unknown = content[0];
  if (typeof item !== "object" || item === null) {
    return lookupErr("malformed", `${what} lookup result has unexpected content`);
  }
  const { type, text } = item as { type?: unknown; text?: unknown };
  if (type !== "text" || typeof text !== "string" || text.length > MAX_LOOKUP_TEXT_CHARS) {
    return lookupErr("malformed", `${what} lookup result is not a JSON text`);
  }
  try {
    return ok(JSON.parse(text) as unknown);
  } catch {
    // Not JSON (e.g. an upstream error message without isError): fail closed, never echo the text.
    return lookupErr("malformed", `${what} lookup result is not valid JSON`);
  }
}

export function createRazorpayLookup(o: AdapterOpts): RazorpayLookupPort {
  return {
    async payment(id: string): Promise<Result<PaymentInfo>> {
      const json = await strictLookup(
        o,
        FETCH_PAYMENT_TOOL,
        "payment_id",
        id,
        PAYMENT_ID_PATTERN,
        "payment",
      );
      if (!json.ok) return json;
      const parsed = paymentSchema.safeParse(json.value);
      if (!parsed.success) return lookupErr("malformed", "payment lookup result failed validation");
      const p = parsed.data;
      if (p.id !== id)
        return lookupErr("id_mismatch", "payment lookup returned a different payment");
      return ok({
        id: p.id,
        status: p.status,
        amountPaise: p.amount,
        amountRefundedPaise: p.amount_refunded,
        currency: p.currency,
      });
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Razorpay order lookup (via upstream MCP `fetch_order`) — firewall INR invariant for order-based money tools
// ---------------------------------------------------------------------------------------------------------------

/** Upstream read tool used for order lookups (classified `read`, D-019). */
export const FETCH_ORDER_TOOL = "fetch_order";
/** Razorpay order id accepted for lookups. Anything else is refused without calling upstream. */
export const ORDER_ID_PATTERN = /^order_[A-Za-z0-9]{1,40}$/;

/** What the firewall needs from an order: its id, amount (integer paise) and currency (verbatim). */
export interface OrderInfo {
  readonly id: string;
  readonly amountPaise: number;
  /** Verbatim from Razorpay (never normalised): the INR check is an exact comparison. */
  readonly currency: string;
}

export interface OrderLookupPort {
  order(id: string): Promise<Result<OrderInfo>>;
}

const orderSchema = z.looseObject({
  id: z.string(),
  amount: z.int().nonnegative(),
  currency: z.string(),
});

/**
 * Order lookups with the same strictness as payment lookups: read-classified tool, `ORDER_ID_PATTERN`, bounded
 * timeout (`lookupTimeoutMs`, ≤ `MAX_LOOKUP_TIMEOUT_MS`), credential screen, exactly one JSON text item, zod
 * `{ id === requested, amount int ≥ 0, currency string }`. Every failure is an `err` (callers deny).
 */
export function createOrderLookup(o: AdapterOpts): OrderLookupPort {
  return {
    async order(id: string): Promise<Result<OrderInfo>> {
      const json = await strictLookup(
        o,
        FETCH_ORDER_TOOL,
        "order_id",
        id,
        ORDER_ID_PATTERN,
        "order",
      );
      if (!json.ok) return json;
      const parsed = orderSchema.safeParse(json.value);
      if (!parsed.success) return lookupErr("malformed", "order lookup result failed validation");
      const p = parsed.data;
      if (p.id !== id) return lookupErr("id_mismatch", "order lookup returned a different order");
      return ok({ id: p.id, amountPaise: p.amount, currency: p.currency });
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------------------------------------------

/**
 * Real `PolicyDeps`. Build a FRESH one per evaluation: history and stats share one lazily-read, memoised audit
 * snapshot (first port call reads, later calls reuse it; a read error is cached as an error), so reusing a bundle
 * across evaluations would serve stale activity. The engine caches payment lookups per evaluation itself;
 * `excludeAttemptIds` is usually per call.
 */
export function createPolicyDeps(
  o: AdapterOpts & {
    readonly timer: Timer;
    /**
     * Shared memoised reader (`memoisedReader`) so the firewall's duplicate check (T009) and the policy use ONE
     * audit read per call. Must be fresh per call. Default: a new `memoisedReader(o.store)`.
     */
    readonly read?: ActivityReader;
  },
): PolicyDeps {
  const read = o.read ?? memoisedReader(o.store);
  return {
    history: historyPort(o, read),
    stats: statsPort(o, read),
    razorpay: createRazorpayLookup(o),
    clock: o.clock,
    timer: o.timer,
  };
}
