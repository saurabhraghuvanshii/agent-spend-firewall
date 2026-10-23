import type { JsonValue } from "../audit/types.js";
import type { Result } from "../result.js";

/** Tool arguments as seen by policies: a JSON object whose numbers are safe integers (paise, ms, counts). */
export type Args = Readonly<Record<string, JsonValue>>;

export type ApprovalChannel = "telegram" | "dashboard";

/**
 * Serialisable policy decision (stored in the audit log). Never contains `undefined` fields, so
 * `JSON.parse(JSON.stringify(d))` deep-equals `d`.
 *
 * `ruleId` names the rule that decided, or a reserved id: `policy-default`, `engine-error`,
 * `engine-timeout`, `engine-invalid-patch`, `invalid-args`, `invalid-amount`.
 * `matchedRules` lists every evaluated rule whose predicate was true, in declaration order.
 */
export type Decision =
  | { type: "allow"; ruleId: string; matchedRules: string[] }
  | { type: "deny"; ruleId: string; message: string; matchedRules: string[] }
  | {
      type: "require_approval";
      ruleId: string;
      message: string;
      via: ApprovalChannel;
      timeoutMin: number;
      /** Present when transform rules changed the args; approval applies to the patched args. */
      patch?: Args;
      matchedRules: string[];
    }
  | { type: "transform"; ruleId: string; patch: Args; matchedRules: string[] };

export type DecisionType = Decision["type"];

// ---------------------------------------------------------------------------------------------
// Ports (injected; core does no I/O)
// ---------------------------------------------------------------------------------------------

export interface HistoryQuery {
  tool: string;
  /** Every key must equal (canonical JSON) the corresponding arg of a recorded action. */
  match: Args;
  withinMs: number;
}

export interface HistoryPort {
  hasRecent(q: HistoryQuery): Promise<Result<boolean>>;
}

export interface StatsQuery {
  tools: readonly string[];
  windowMs: number;
}

export interface StatsSummary {
  /** Sum of executed (forwarded and successful) actions in the window, integer paise. */
  amountPaise: number;
  count: number;
}

export interface StatsPort {
  /** Executed actions only (not denied / pending ones). */
  sumLast(q: StatsQuery): Promise<Result<StatsSummary>>;
}

export interface PaymentInfo {
  id: string;
  status: string;
  amountPaise: number;
  amountRefundedPaise: number;
  currency: string;
}

export interface RazorpayLookupPort {
  payment(id: string): Promise<Result<PaymentInfo>>;
}

export interface Clock {
  nowMs(): number;
}

export interface TimerHandle {
  /** Resolves when the timer fires. Never resolves if cancelled. */
  promise: Promise<void>;
  cancel(): void;
}

/** Timer port: core cannot call `setTimeout` (D-007). */
export interface Timer {
  after(ms: number): TimerHandle;
}

export interface PolicyDeps {
  history: HistoryPort;
  stats: StatsPort;
  razorpay: RazorpayLookupPort;
  clock: Clock;
  timer: Timer;
}

// ---------------------------------------------------------------------------------------------
// Context passed to predicates and transforms
// ---------------------------------------------------------------------------------------------

/**
 * What a rule can see. Port wrappers unwrap `Result`: an `err` (or a malformed value) throws and the
 * engine denies with `engine-error`, even if the rule catches the throw.
 */
export interface PolicyContext {
  readonly tool: string;
  /** Deep-frozen copy of the (possibly transformed) args. */
  readonly args: Args;
  /** Agent-supplied justification. UNTRUSTED: never base an allow on it (D-004). */
  readonly untrustedReason: string;
  readonly session: { readonly id: string };
  nowMs(): number;
  /** Positive safe-integer paise in `args[field]` (default `"amount"`), else deny `invalid-amount`. */
  amountPaise(field?: string): number;
  /** True if `args` has an own, non-null value for `field`. */
  has(field: string): boolean;
  /** Non-empty string in `args[field]`, else deny `invalid-args`. */
  string(field: string): string;
  readonly history: { hasRecent(q: HistoryQuery): Promise<boolean> };
  readonly stats: { sumLast(q: StatsQuery): Promise<StatsSummary> };
  readonly razorpay: { payment(id: string): Promise<PaymentInfo> };
}

// ---------------------------------------------------------------------------------------------
// Rules and policies
// ---------------------------------------------------------------------------------------------

export type Predicate = (ctx: PolicyContext) => boolean | Promise<boolean>;
export type TransformFn = (ctx: PolicyContext) => Args | Promise<Args>;

export interface ApprovalOptions {
  via: ApprovalChannel;
  /** Integer minutes, 1..1440. */
  timeoutMin: number;
  message: string;
}

export type RuleAction =
  | { readonly kind: "deny"; readonly message: string }
  | {
      readonly kind: "require_approval";
      readonly via: ApprovalChannel;
      readonly timeoutMin: number;
      readonly message: string;
    }
  | { readonly kind: "transform"; readonly fn: TransformFn }
  | { readonly kind: "allow" };

export type RuleActionKind = RuleAction["kind"];

/** A finished rule. Only produced by the builder's action methods; unfinished builders are not `Rule`s. */
export interface Rule {
  readonly kind: "rule";
  readonly id: string;
  readonly tools: readonly string[];
  readonly when?: Predicate;
  readonly action: RuleAction;
}

export type PolicyDefault = "deny" | "allow";

export interface PolicySpec {
  readonly rules: readonly Rule[];
  readonly default: PolicyDefault;
  /** Whole-evaluation budget in integer ms, 1..10000. Default 2000. */
  readonly timeoutMs?: number;
}

export interface CompiledRule {
  readonly index: number;
  readonly id: string;
  /** Frozen, de-duplicated tool names in declaration order. */
  readonly tools: readonly string[];
  readonly when?: Predicate;
  readonly action: RuleAction;
}

export interface CompiledPolicy {
  readonly kind: "compiled-policy";
  readonly rules: readonly CompiledRule[];
  readonly default: PolicyDefault;
  readonly timeoutMs: number;
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

export interface EvalInput {
  tool: string;
  /** Untrusted; validated by the engine (plain JSON object, integer numbers). */
  args: unknown;
  /** Untrusted agent justification. */
  reason: string;
  sessionId: string;
}

export interface RuleTrace {
  ruleId: string;
  action: RuleActionKind;
  result: "matched" | "not_matched" | "error";
}

export interface EvalResult {
  decision: Decision;
  /** Args after transforms (deep-frozen). `{}` if the input args were invalid. */
  finalArgs: Args;
  /** Rules evaluated, in evaluation order (transforms first, then gates). */
  trace: RuleTrace[];
}

/** Rule ids the engine emits itself. Policies may not use these (or the `engine-`/`policy-` prefixes). */
export const RESERVED_RULE_IDS = {
  default: "policy-default",
  engineError: "engine-error",
  engineTimeout: "engine-timeout",
  invalidPatch: "engine-invalid-patch",
  invalidArgs: "invalid-args",
  invalidAmount: "invalid-amount",
} as const;

export const DEFAULT_POLICY_TIMEOUT_MS = 2000;
