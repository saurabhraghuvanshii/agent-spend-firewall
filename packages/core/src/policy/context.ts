import { canonicalJson } from "../audit/canonical-json.js";
import type { JsonValue } from "../audit/types.js";
import type { Result } from "../result.js";
import type {
  Args,
  HistoryQuery,
  PaymentInfo,
  PolicyContext,
  PolicyDeps,
  StatsQuery,
  StatsSummary,
} from "./types.js";

export type FaultCode = "engine-error" | "invalid-amount" | "invalid-args";

/**
 * Error thrown by context helpers. `safeMessage` never contains arg values.
 * The first fault is also recorded on the evaluation state, so a rule that catches it still
 * causes a deny (fail closed).
 */
export class PolicyFault extends Error {
  readonly code: FaultCode;
  readonly safeMessage: string;
  readonly ruleId: string;

  constructor(code: FaultCode, safeMessage: string, ruleId: string) {
    super(safeMessage);
    this.name = "PolicyFault";
    this.code = code;
    this.safeMessage = safeMessage;
    this.ruleId = ruleId;
  }
}

/** Mutable per-evaluation state shared by every context of one `evaluate` call. */
export interface EvalState {
  fault: PolicyFault | undefined;
  /** Set once the evaluation has a result (e.g. timed out); later port calls are refused. */
  closed: boolean;
  currentRuleId: string;
  /**
   * Every port call started during this evaluation (each already has a no-op rejection handler).
   * The engine awaits them all before returning a non-deny result, so a port fault in a call the
   * rule did not await still denies (fail closed).
   */
  readonly inflight: Promise<unknown>[];
  /**
   * Razorpay payment lookups started during this evaluation, keyed by payment id. Lives on the
   * per-evaluation state (not on a ctx), so it is shared by every rule and survives the context
   * rebuild between the transform and gate phases, but is never shared across `evaluate` calls.
   * Values are the shared lookup (resolving to a frozen `PaymentInfo`, or rejecting with a
   * neutral, unrecorded `PolicyFault`); each caller gets its own derived promise, which records
   * the fault attributed to the rule that called `payment(id)`.
   */
  readonly paymentCache: Map<string, Promise<PaymentInfo>>;
}

export function newEvalState(): EvalState {
  return {
    fault: undefined,
    closed: false,
    currentRuleId: "",
    inflight: [],
    paymentCache: new Map(),
  };
}

/**
 * Wait until every tracked port call has settled, including calls started while waiting.
 * Never rejects.
 */
export async function settleInflight(state: EvalState): Promise<void> {
  let seen = 0;
  while (seen < state.inflight.length) {
    const batch = state.inflight.slice(seen);
    seen = state.inflight.length;
    await Promise.allSettled(batch);
  }
}

export interface ContextInput {
  tool: string;
  args: Args;
  reason: string;
  sessionId: string;
}

export function createContext(
  state: EvalState,
  input: ContextInput,
  deps: PolicyDeps,
): PolicyContext {
  const { args } = input;

  const fault = (code: FaultCode, message: string): PolicyFault => {
    const f = new PolicyFault(code, message, state.currentRuleId);
    state.fault ??= f;
    return f;
  };
  const own = (field: string): JsonValue | undefined =>
    Object.hasOwn(args, field) ? args[field] : undefined;

  function callPort<T>(
    name: string,
    call: () => Promise<Result<T>>,
    check: (v: unknown) => v is T,
  ): Promise<T> {
    return track(runPort(name, call, check));
  }

  /** Mark handled (the fault is recorded on `state` regardless) and track for settleInflight. */
  function track<T>(p: Promise<T>): Promise<T> {
    state.inflight.push(p.then(noop, noop));
    return p;
  }

  /**
   * Memoised payment lookup: one port call per payment id per evaluation. Every caller gets its
   * own promise that (a) re-checks that the evaluation is still open when the shared lookup
   * settles, and (b) on failure records a fault attributed to the caller's rule, so a cached
   * failure denies for every rule that uses it (fail closed), not only the first.
   */
  function cachedPayment(id: string): Promise<PaymentInfo> {
    if (state.closed) return rejected(fault("engine-error", "evaluation already finished"));
    let shared = state.paymentCache.get(id);
    if (shared === undefined) {
      // Snapshot the port value (each field read once) before validating, then freeze it, so a
      // value with getters, or a rule mutating it, cannot change what a later rule sees.
      // The shared lookup is attributed to no rule and records nothing on `state`: whichever rule
      // is current when it settles may never have touched it. Each caller's derived promise below
      // re-raises the fault via `faultFor`, attributed to the rule that called `payment(id)`.
      shared = runPort(
        "razorpay payment",
        () => deps.razorpay.payment(id).then(snapshotPaymentResult),
        (v: unknown): v is PaymentInfo => isPaymentInfo(v) && v.id === id,
        neutralFault,
      ).then((v) => Object.freeze(v));
      void shared.then(noop, noop);
      state.paymentCache.set(id, shared);
    }
    const ruleId = state.currentRuleId;
    const faultFor = (code: FaultCode, message: string): PolicyFault => {
      const f = new PolicyFault(code, message, ruleId);
      state.fault ??= f;
      return f;
    };
    return track(
      shared.then(
        (v) => {
          if (state.closed) throw faultFor("engine-error", "evaluation already finished");
          return v;
        },
        (e: unknown) => {
          throw e instanceof PolicyFault
            ? faultFor(e.code, e.safeMessage)
            : faultFor("engine-error", "razorpay payment lookup failed");
        },
      ),
    );
  }

  /**
   * Run a port call and validate its result. `mk` builds (and, for the default `fault`, records)
   * the PolicyFault for any failure; the shared payment lookup passes `neutralFault` instead.
   */
  async function runPort<T>(
    name: string,
    call: () => Promise<Result<T>>,
    check: (v: unknown) => v is T,
    mk: (code: FaultCode, message: string) => PolicyFault = fault,
  ): Promise<T> {
    if (state.closed) throw mk("engine-error", "evaluation already finished");
    let r: Result<T>;
    try {
      r = await call();
    } catch {
      throw mk("engine-error", `${name} lookup threw`);
    }
    if (state.closed) throw mk("engine-error", "evaluation already finished");
    if (typeof r !== "object" || r === null)
      throw mk("engine-error", `${name} lookup returned a malformed result`);
    if (!r.ok) throw mk("engine-error", `${name} lookup failed`);
    if (!check(r.value)) throw mk("engine-error", `${name} lookup returned an invalid value`);
    return r.value;
  }

  const ctx: PolicyContext = {
    tool: input.tool,
    args,
    untrustedReason: input.reason,
    session: Object.freeze({ id: input.sessionId }),
    nowMs(): number {
      const now = deps.clock.nowMs();
      if (!Number.isSafeInteger(now) || now < 0)
        throw fault("engine-error", "clock returned an invalid time");
      return now;
    },
    amountPaise(field = "amount"): number {
      const v = own(field);
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= 0) {
        throw fault(
          "invalid-amount",
          `field ${safeField(field)} must be a positive integer amount in paise`,
        );
      }
      return v;
    },
    has(field: string): boolean {
      const v = own(field);
      return v !== undefined && v !== null;
    },
    string(field: string): string {
      const v = own(field);
      if (typeof v !== "string" || v === "") {
        throw fault("invalid-args", `field ${safeField(field)} must be a non-empty string`);
      }
      return v;
    },
    history: Object.freeze({
      hasRecent(q: HistoryQuery): Promise<boolean> {
        const query = sanitizeHistoryQuery(q);
        if (query === undefined) return rejected(fault("engine-error", "invalid history query"));
        return callPort("history", () => deps.history.hasRecent(query), isBoolean);
      },
    }),
    stats: Object.freeze({
      sumLast(q: StatsQuery): Promise<StatsSummary> {
        const query = sanitizeStatsQuery(q);
        if (query === undefined) return rejected(fault("engine-error", "invalid stats query"));
        return callPort("stats", () => deps.stats.sumLast(query), isStatsSummary);
      },
    }),
    razorpay: Object.freeze({
      payment(id: string): Promise<PaymentInfo> {
        if (typeof id !== "string" || id === "") {
          return rejected(fault("engine-error", "invalid payment id for lookup"));
        }
        return cachedPayment(id);
      },
    }),
  };
  return Object.freeze(ctx);
}

/**
 * Fault for a lookup shared by several rules: attributed to no rule and NOT recorded on the eval
 * state. Only safe where every consumer re-raises it through its own recording `faultFor`.
 */
function neutralFault(code: FaultCode, message: string): PolicyFault {
  return new PolicyFault(code, message, "");
}

/** Rejected promise pre-marked as handled; the fault is already recorded on the eval state. */
function rejected(f: PolicyFault): Promise<never> {
  const p = Promise.reject(f);
  void p.then(noop, noop);
  return p;
}

function noop(): void {
  // Intentionally empty: the rejection is already recorded as `state.fault`.
}

/** Field name for messages: shown only if it looks like an identifier (policy-authored, not agent data). */
function safeField(field: string): string {
  return /^[A-Za-z0-9_.-]{1,64}$/.test(field) ? `"${field}"` : "[field]";
}

function sanitizeHistoryQuery(q: unknown): HistoryQuery | undefined {
  if (typeof q !== "object" || q === null) return undefined;
  const { tool, match, withinMs } = q as Record<string, unknown>;
  if (typeof tool !== "string" || tool === "") return undefined;
  if (!isPositiveSafeInt(withinMs)) return undefined;
  const m = toFrozenJsonObject(match);
  if (m === undefined) return undefined;
  return Object.freeze({ tool, match: m, withinMs });
}

function sanitizeStatsQuery(q: unknown): StatsQuery | undefined {
  if (typeof q !== "object" || q === null) return undefined;
  const { tools, windowMs } = q as Record<string, unknown>;
  if (!Array.isArray(tools) || tools.length === 0) return undefined;
  const list: string[] = [];
  for (const t of tools as unknown[]) {
    if (typeof t !== "string" || t === "") return undefined;
    list.push(t);
  }
  if (!isPositiveSafeInt(windowMs)) return undefined;
  return Object.freeze({ tools: Object.freeze(list), windowMs });
}

const isBoolean = (v: unknown): v is boolean => typeof v === "boolean";

function isNonNegSafeInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function isPositiveSafeInt(v: unknown): v is number {
  return isNonNegSafeInt(v) && v > 0;
}

function isStatsSummary(v: unknown): v is StatsSummary {
  if (typeof v !== "object" || v === null) return false;
  const s = v as Record<string, unknown>;
  return isNonNegSafeInt(s["amountPaise"]) && isNonNegSafeInt(s["count"]);
}

/**
 * Replace an ok payment value with a detached plain copy of the `PaymentInfo` fields (read once).
 * Anything else is returned unchanged for `runPort` to reject. A throwing getter rejects (⇒ fault).
 */
function snapshotPaymentResult(r: Result<PaymentInfo>): Result<PaymentInfo> {
  const raw: unknown = r;
  if (typeof raw !== "object" || raw === null) return r;
  const res = raw as Record<string, unknown>;
  if (res["ok"] !== true) return r;
  const v: unknown = res["value"];
  if (typeof v !== "object" || v === null) return r;
  const p = v as Record<string, unknown>;
  const copy: Record<string, unknown> = {
    id: p["id"],
    status: p["status"],
    amountPaise: p["amountPaise"],
    amountRefundedPaise: p["amountRefundedPaise"],
    currency: p["currency"],
  };
  // Validated by `isPaymentInfo` in runPort before anyone sees it.
  return { ok: true, value: copy as unknown as PaymentInfo };
}

function isPaymentInfo(v: unknown): v is PaymentInfo {
  if (typeof v !== "object" || v === null) return false;
  const p = v as Record<string, unknown>;
  return (
    typeof p["id"] === "string" &&
    typeof p["status"] === "string" &&
    typeof p["currency"] === "string" &&
    isNonNegSafeInt(p["amountPaise"]) &&
    isNonNegSafeInt(p["amountRefundedPaise"])
  );
}

// ---------------------------------------------------------------------------------------------
// JSON helpers (shared with the engine)
// ---------------------------------------------------------------------------------------------

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * Validate `v` as a canonical-JSON plain object and return a deep-frozen copy (detached from the
 * caller's object, so later caller mutation cannot change what policies saw). Never throws.
 */
export function toFrozenJsonObject(v: unknown): Args | undefined {
  try {
    if (!isPlainObject(v)) return undefined;
    const enc = canonicalJson(v);
    if (!enc.ok) return undefined;
    const copy: unknown = JSON.parse(enc.value);
    if (!isPlainObject(copy)) return undefined;
    return deepFreeze(copy as Record<string, JsonValue>);
  } catch {
    return undefined;
  }
}

export function deepFreeze<T>(v: T): T {
  if (typeof v === "object" && v !== null && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const child of Object.values(v)) deepFreeze(child);
  }
  return v;
}
