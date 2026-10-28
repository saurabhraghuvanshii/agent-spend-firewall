/**
 * The money pipeline (T008): validate → INR invariant → policy → audit → act, for every money tool call.
 *
 * Wiring: `createFirewallInterceptor(pipeline)` = `envelope(composeInterceptors(firewallChain(stage)))`, so
 * `moneyArgsStage` (T004) always runs first and the policy stage only sees validated args with `reason` stripped
 * (`ctx.untrustedReason`). Read tools pass straight through (`classifyTool` on the server's exact name; anything
 * unknown is money, D-019).
 *
 * Money stage, in order (every exit writes exactly one audit attempt + at most one outcome):
 *  0. Guards: the tool name must be the server's exact name (a stage may not rename it) ⇒ else deny
 *     `firewall.tool_mismatch`; `untrustedReason` must be set ⇒ else `firewall.internal_error`; the degraded latch
 *     (an outcome write failed earlier, or `startDegraded`: chain failed verification at startup) ⇒ deny `audit_unavailable` (re-checked right after the global lock is acquired and again immediately before
 *     forwarding, since the latch can be set while a call waits). The optional `preCheck` (T012 kill switch / shadow
 *     mode, `modes.ts`) runs FIRST among these state checks (right after the tool / reason guards), so a kill-switch
 *     deny wins over every other state; it runs again right before EVERY send (live forward, T010 retry, T011
 *     approved execution): a deny there ⇒ outcome `not_forwarded` + the deny, nothing sent.
 *  1. Per-resource locks keyed `payment:<id>` (top-level string `payment_id`) and `order:<id>` (top-level string
 *     `order_id`); a non-string id ⇒ deny `firewall.invalid_args`. When both are present they are acquired in SORTED
 *     key order; the global lock always comes last, and nothing waits on a resource lock while holding the global
 *     lock. Each acquire waits at most `lockWaitMs`. Resource locks are held through forwarding and outcome
 *     recording, so the same payment / order is never evaluated and forwarded concurrently.
 *  2. INR invariant (D-017, not disable-able by a policy): a call carrying `payment_id` looks the payment up via
 *     upstream `fetch_payment`; lookup failure ⇒ deny `firewall.payment_lookup_failed`. A call carrying `order_id`
 *     (`initiate_payment`, `update_order`, …) looks the order up via upstream `fetch_order` (`createOrderLookup`);
 *     failure ⇒ deny `firewall.order_lookup_failed`. Currency ≠ exactly "INR" ⇒ deny `firewall.currency_not_inr`.
 *     (`currency` ARGS are already checked by `moneyArgsStage`.)
 *  3. Global money lock (bounded wait `lockWaitMs` ⇒ deny `firewall.busy`) around the duplicate check + `evaluate` +
 *     `recordAttempt`, since velocity spans payments.
 *     DUPLICATE CHECK (T009, firewall invariant, not disable-able by a policy, every money tool): before `evaluate`
 *     the idempotency key of the agent's args (`idempotency.ts`) is matched against recent audit activity
 *     (`findDuplicate`: closed actions within `duplicateWindowMs`, open ones within 24 h). A hit ⇒ deny
 *     `firewall.duplicate` with `duplicateOf: {attemptId, status, upstreamRef?}` (status executed /
 *     may_have_executed / pending_approval / in_flight) — no upstream call, no approval, audited as a deny. In-flight
 *     duplicates are denied at once (never queued). If a transform changed the args, the key of `finalArgs` is
 *     checked too (after `checkFinalArgs`). Key error ⇒ `firewall.invalid_args`; audit read error / too many rows /
 *     invalid clock ⇒ `firewall.duplicate_check_failed`. The check and the policy share ONE memoised audit read.
 *     Deps are built fresh per evaluation. For a non-deny decision the args to forward are
 *     re-checked (`checkFinalArgs`), since a `transform` may have rewritten them: any top-level `*_id` key added,
 *     removed or changed ⇒ `firewall.transform_retarget`; unsafe keys / a `reason` key ⇒ `firewall.invalid_args`;
 *     a non-INR currency at any depth ⇒ `firewall.currency_not_inr`; an invalid amount at any depth ⇒
 *     `firewall.invalid_amount` (all audited as deny). Attempts record the FORWARDED (post-transform) args, plus
 *     `originalArgs` when a transform changed them (D-026), and the `idempotencyKey` of the recorded args (T010 uses
 *     it for verify-before-retry). Deny attempts record the agent's args (nothing is forwarded).
 *  4. `recordAttempt` error ⇒ never forward: `audit.invalid_args` ⇒ outcome `denied` on its trail row + deny
 *     `audit.invalid_args`; anything else ⇒ deny `audit_unavailable`.
 *  5. deny ⇒ outcome `denied` ⇒ `{ decision: "deny", ruleId, message }` (`isError: true`). Never echoes the reason.
 *  6. require_approval ⇒ `ApprovalPort.create` bound to `sha256(canonicalJson({tool, args: finalArgs}))`; the
 *     attempt stays OPEN (counts toward limits) ⇒ `{ decision: "pending_approval", approvalId, message }`
 *     (`isError: false`). Create failure ⇒ outcome `not_forwarded` + deny `firewall.approval_unavailable`.
 *     T011: approved ⇒ `executeApproved` (chained `approval` record, same locks, re-evaluation, forward, T010
 *     verification, outcome on THIS attempt); rejected / expired ⇒ `resolveApproval` (`approval` record + outcome
 *     `not_forwarded` `approval.rejected|approval.expired`, so it stops counting). See `MoneyPipeline`.
 *  7. allow / transform ⇒ forward exactly `finalArgs` and map the server's `ForwardReport` to an outcome (see
 *     `outcomeFor`). An outcome write failure latches the pipeline DEGRADED: every later money call is denied
 *     `audit_unavailable` until restart (the audit trail can no longer be trusted to be complete).
 *  8. Envelope: any `{decision:"deny"}` result for a money call that the stage did not produce (e.g. a
 *     `moneyArgsStage` deny) is audited as attempt `deny` (args minus `reason`, reason "", matchedRules [ruleId]) +
 *     outcome `denied`.
 *
 * T012 — shadow mode (`preCheck` returned `{shadow: true}` at the start of the call): the duplicate check and every
 * firewall invariant run as usual, the policy is evaluated, and if its decision is the POLICY's own
 * (`isShadowableDecision`: not an engine error / timeout / invalid patch) it is NOT enforced: the agent's original
 * validated args are re-checked (`checkFinalArgs`), stamped and forwarded exactly like an `allow`, and the attempt is
 * recorded `decision: "allow"`, `shadow: {wouldDecision}` with the policy's matched rules. Transforms are not applied
 * (would-transform is recorded), approvals are not requested. Engine errors stay real denies. Shadow attempts count
 * toward history / velocity / duplicates as the allows they are. T011 approved executions are never shadowed.
 *
 * T010 — verify before retry (see `failure.ts`):
 *  - Notes: an agent- or transform-supplied `notes` key starting with `asf_` (any case), more than 14 notes, or a
 *    non-object `notes` on `create_refund` ⇒ deny `firewall.invalid_args`. For a non-deny `create_refund` the attempt
 *    id is generated BEFORE `recordAttempt` and stamped as `notes.asf_attempt`; the stamped args are recorded and
 *    forwarded (the idempotency key ignores notes).
 *  - After a forward whose outcome may hide an execution (timeout incl. cancelled-after-send, sent-then-failed,
 *    tool error, credential-leak replacement, forward threw) the action is VERIFIED with Razorpay and one
 *    `verification` record is written: happened ⇒ `{outcome:"success", verifiedAfterTimeout:true, attemptId,
 *    upstreamRef?}` (`isError: false`); not_happened ⇒ for a timed-out `create_refund` whose LATE answer was a
 *    failure (and complete refund list without the marker), exactly ONE retry through the server's `RetryForward`
 *    (no policy re-run; firewall invariants + duplicate check under the global lock, excluding the original; new
 *    attempt id + marker, `retryOf` = original); a tool error keeps its upstream result; unknown ⇒
 *    `{outcome:"unknown", attemptId, flaggedForHuman:true}` (`isError: true`), a stderr line, and the action stays
 *    in an in-memory `unresolved` set merged into every duplicate check (no age-out) until a later verification
 *    settles it. A late answer arriving after the flag re-verifies in the background (trigger `late_response`) under
 *    the resource locks. A retry that times out is verified once and never retried again.
 *  - `startReconciling`: until `reconcile()` finishes every money call is denied `firewall.reconciling` (audited);
 *    reads work. `reconcile()` runs `reconcileAtStartup` and loads the still-unknown actions into `unresolved`; its
 *    failure latches the pipeline degraded.
 */
import {
  canonicalJson,
  err,
  ERROR_CODE_RE,
  evaluate,
  ok,
  type Clock,
  type CompiledPolicy,
  type Decision,
  type Args,
  type AuditRecord,
  type EvalResult,
  type Result,
  type Timer,
} from "@asf/core";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  approvalArgsHash,
  argsForDisplay,
  reasonForDisplay,
  type ApprovalPort,
} from "./approval-port.js";
import { escapeForTerminal } from "./cli/audit-verify.js";
import {
  upstreamRefSchema,
  type AuditActivity,
  type AuditAttemptRecord,
  type AuditOutcomeInput,
  type AuditOutcomeRecord,
  type AuditStore,
  type AuditVerificationRecord,
} from "./audit-store.js";
import {
  createOrderLookup,
  createPolicyDeps,
  createRazorpayLookup,
  DEFAULT_OPEN_LOOKBACK_MS,
  memoisedReader,
  type ActivityReader,
  type UpstreamPaymentPort,
} from "./context-adapters.js";
import {
  createActionVerifier,
  createLateResponseTracker,
  DEFAULT_VERIFY_WAIT_MS,
  handleUnsettled,
  lateKey,
  MAX_VERIFY_WAIT_MS,
  notesProblem,
  reconcileAtStartup,
  REJECTED_ERROR_CODE,
  RETRYABLE_TOOLS,
  stampAttemptMarker,
  type ActionVerifier,
  type LateResponseSource,
  type ReconcileSummary,
  type UnsettledDeps,
} from "./failure.js";
import { redactionSafeUuid } from "./ids.js";
import { composeInterceptors, firewallChain, type Next, type Stage } from "./interceptor-chain.js";
import {
  DEFAULT_DUPLICATE_WINDOW_MS,
  DUPLICATE_MESSAGES,
  findDuplicate,
  idempotencyKey,
  MAX_DUPLICATE_WINDOW_MS,
  mergeActivity,
  MIN_DUPLICATE_WINDOW_MS,
  type DuplicateHit,
} from "./idempotency.js";
import { createKeyedMutex, createMutex, type Release } from "./locks.js";
import { isShadowableDecision } from "./modes.js";
import {
  allCurrenciesInr,
  findInvalidAmount,
  hasSafeTopLevelKeys,
  isBounded,
} from "./money-args.js";
import {
  isSafeUpstreamRef,
  PENDING_APPROVAL_MESSAGE,
  UNKNOWN_OUTCOME_MESSAGE,
  VERIFIED_AFTER_TIMEOUT_MESSAGE,
  VERIFIED_AFTER_TIMEOUT_PENDING_MESSAGE,
  type UnknownOutcomeBody,
  type VerifiedSuccessBody,
} from "./result-redaction.js";
import { rewriteMoneySchema } from "./schema-rewrite.js";
import {
  denyResult,
  forwardReportOf,
  jsonErrorResult,
  retryForwardOf,
  type CallContext,
  type CallInterceptor,
  type DirectCall,
  type ForwardReport,
  type OpenDirectCall,
  type RetryForward,
} from "./server.js";
import { classifyTool } from "./tool-classes.js";
import { noRedact, type LateResponse, type Logger, type Redactor } from "./upstream.js";
import { classifyToolResultFailure, type UpstreamFailure } from "./upstream-failure.js";

export const DEFAULT_LOCK_WAIT_MS = 5000;

/** Reserved firewall rule ids emitted by the pipeline. */
export const FIREWALL_RULES = {
  internalError: "firewall.internal_error",
  toolMismatch: "firewall.tool_mismatch",
  auditUnavailable: "audit_unavailable",
  auditInvalidArgs: "audit.invalid_args",
  busy: "firewall.busy",
  cancelled: "firewall.cancelled",
  invalidArgs: "firewall.invalid_args",
  paymentLookupFailed: "firewall.payment_lookup_failed",
  orderLookupFailed: "firewall.order_lookup_failed",
  currencyNotInr: "firewall.currency_not_inr",
  transformRetarget: "firewall.transform_retarget",
  invalidAmount: "firewall.invalid_amount",
  forwardThrew: "firewall.forward_threw",
  approvalUnavailable: "firewall.approval_unavailable",
  duplicate: "firewall.duplicate",
  duplicateCheckFailed: "firewall.duplicate_check_failed",
  reconciling: "firewall.reconciling",
  shadowEnded: "firewall.shadow_ended",
} as const;

/** T012: a shadow call's policy did not allow it and shadow mode was turned off before it was sent. */
export const SHADOW_ENDED_MESSAGE =
  "shadow mode was turned off while this call was in progress and the policy does not allow it as sent; the call was not sent";

/** T011 codes for approved actions that were not executed / approvals that were closed (audit `errorCode`). */
export const APPROVAL_RULES = {
  rejected: "approval.rejected",
  expired: "approval.expired",
  argsMismatch: "approval.args_mismatch",
  policyDenied: "approval.policy_denied",
  policyChanged: "approval.policy_changed",
  reevaluationFailed: "approval.reevaluation_failed",
  attemptClosed: "approval.attempt_closed",
} as const;

export const RECONCILING_MESSAGE =
  "the firewall is checking earlier unsettled money actions with Razorpay after a restart; try again in a moment. The call was not sent";

/** Agent-facing body when a timed-out action was verified NOT executed but could not be retried. */
export const NOT_RETRIED_MESSAGE =
  "the upstream call did not answer in time; the firewall verified with Razorpay that the action was NOT executed and did not retry it. You may try again";

/** Store surface the pipeline needs. */
export type PipelineStore = Pick<
  AuditStore,
  | "recordAttempt"
  | "recordOutcome"
  | "readActivitySince"
  | "recordVerification"
  | "readUnsettled"
  | "recordApproval"
  | "readAttempt"
>;

export interface PreCheckDeny {
  readonly ruleId: string;
  readonly message: string;
}

/** T012: run this call in shadow mode (policy decisions observed and audited, not enforced). */
export interface PreCheckShadow {
  readonly shadow: true;
}

export type PreCheckVerdict = PreCheckDeny | PreCheckShadow;

function isPreCheckDeny(v: PreCheckVerdict): v is PreCheckDeny {
  return !("shadow" in v);
}

export interface MoneyPipelineOptions {
  /** Compiled policy (the CLI only accepts deny-by-default ones; tests may pass any). */
  readonly policy: CompiledPolicy;
  readonly store: PipelineStore;
  /** Upstream used for policy / INR payment lookups (`fetch_payment`), NOT filtered by `resultFilter`. */
  readonly upstream: UpstreamPaymentPort;
  readonly approvals: ApprovalPort;
  readonly clock: Clock;
  readonly timer: Timer;
  /** Credential redactor (same as the proxy's) for lookup screening. */
  readonly redact?: Redactor;
  readonly logger?: Logger;
  /** Max integer ms to wait for the per-payment or global money lock (default 5000). */
  readonly lockWaitMs?: number;
  /** Payment lookup timeout (see `AdapterOpts.lookupTimeoutMs`). */
  readonly lookupTimeoutMs?: number;
  /**
   * Duplicate window for CLOSED (executed / possibly executed) actions, integer ms in
   * `[MIN_DUPLICATE_WINDOW_MS, MAX_DUPLICATE_WINDOW_MS]` (default `DEFAULT_DUPLICATE_WINDOW_MS`, 10 min); anything
   * else ⇒ `createMoneyPipeline` throws. Open actions (in flight / pending approval) block for 24 h regardless.
   */
  readonly duplicateWindowMs?: number;
  /**
   * T012 seam (kill switch / shadow mode, see `createModePreCheck`): runs after the tool / reason guards and before
   * the degraded / reconciling checks and any lock. Returning a deny audits and returns it; `{shadow: true}` runs the
   * call in shadow mode; throwing ⇒ deny `firewall.internal_error`. Called again right before every send, where only
   * a deny (or a throw) matters.
   */
  readonly preCheck?: (
    ctx: CallContext,
  ) => PreCheckVerdict | undefined | Promise<PreCheckVerdict | undefined>;
  /**
   * Start with the degraded latch already SET (e.g. the audit chain failed `verify()` at startup): every money call is
   * denied `audit_unavailable` with `message` (agent-facing) and the deny is audited best-effort. `reason` is logged
   * once at creation for the operator. Read tools are unaffected.
   */
  readonly startDegraded?: { readonly reason: string; readonly message: string };
  /** T010: late-response events of the upstream (`Upstream`); without them no retry can ever happen. */
  readonly lateResponses?: LateResponseSource;
  /**
   * T010: how long to wait for the late answer of a timed-out refund before deciding, integer ms in
   * `[1, MAX_VERIFY_WAIT_MS]` (default `DEFAULT_VERIFY_WAIT_MS`); else `createMoneyPipeline` throws.
   */
  readonly verifyWaitMs?: number;
  /** Timer for that wait (default `timer`). */
  readonly verifyTimer?: Timer;
  /** Per-lookup timeout of verification lookups (see `VerifierOptions`). */
  readonly verifyLookupTimeoutMs?: number;
  /** Injected verifier (tests). Default: `createActionVerifier` over `upstream`. */
  readonly verifier?: ActionVerifier;
  /** T010: deny money calls `firewall.reconciling` until `reconcile()` has finished. */
  readonly startReconciling?: boolean;
  /** T011: approval id of an attempt (approval store), for the `expired` records startup reconciliation writes. */
  readonly approvalIdOf?: (attemptId: string) => string | undefined;
}

/** T011: an approved action to execute (from the approval store + the pending request the pipeline created). */
export interface ExecuteApprovedRequest {
  readonly approvalId: string;
  /** The OPEN `require_approval` attempt the approval belongs to. */
  readonly attemptId: string;
  /** `approvalArgsHash(tool, finalArgs)` the approval was bound to when it was created. */
  readonly argsHash: string;
  readonly tool: string;
  /** The approval's post-transform args, UNSTAMPED (no `notes.asf_attempt`). */
  readonly finalArgs: Args;
  readonly untrustedReason: string;
  readonly sessionId: string;
  /** Rule that required the approval. */
  readonly ruleId: string;
  /** Opaque approver id (`telegram:<id>`), recorded in the chained `approval` record. */
  readonly approver: string;
}

/**
 * What happened to an approved action: `executed` (Razorpay applied it, possibly verified after a timeout);
 * `failed` (Razorpay answered with an error); `unknown` (may have executed, flagged for a human); `not_executed`
 * (nothing was sent, or it was verified not executed — e.g. the policy now denies, args changed, duplicate, busy).
 */
export type ApprovedExecutionStatus = "executed" | "failed" | "unknown" | "not_executed";

export interface ExecuteApprovedResult {
  readonly status: ApprovedExecutionStatus;
  readonly attemptId: string;
  /** Razorpay id of the executed resource, when known and redaction-safe. */
  readonly upstreamRef?: string;
  /** Machine code (deny rule / audit error code) for `not_executed` / `failed`. */
  readonly code?: string;
  /** Result a live call would have returned (UNFILTERED: never hand it to an agent without the result filter). */
  readonly result: CallToolResult;
}

/** T011: a rejected / expired approval, closed as `not_forwarded` + `approval.rejected|approval.expired`. */
export interface ResolveApprovalRequest {
  readonly approvalId: string;
  readonly attemptId: string;
  readonly decision: "rejected" | "expired";
  /** Required for `rejected`, forbidden for `expired`. */
  readonly approver?: string;
}

export interface MoneyPipeline {
  readonly stage: Stage;
  /** Wrap the composed chain: binds the server's exact tool name and audits denies the stage didn't produce. */
  envelope(inner: CallInterceptor): CallInterceptor;
  /**
   * T011: execute an APPROVED action through the normal money path. Order:
   *  1. chain the `approval` record (approver, time) — before anything is sent; a write failure ⇒ nothing executes;
   *  2. degraded / reconciling ⇒ not executed; the attempt must be the open, unretried `require_approval` attempt of
   *     the same tool and session, and `approvalArgsHash(tool, finalArgs)`, the recorded (stamped, redacted) args and
   *     the recorded idempotency key must all still match ⇒ else `approval.args_mismatch`;
   *  3. the same locks as a live call (sorted resource locks → global), the INR invariant, the duplicate check
   *     excluding this attempt, and a policy RE-EVALUATION with `excludeAttemptIds: {attemptId}`: deny (incl. engine
   *     error / timeout) ⇒ not executed; `require_approval` by another rule ⇒ `approval.policy_changed`; the
   *     re-evaluated args must pass `checkFinalArgs` and hash to `argsHash`;
   *  4. stamp `notes.asf_attempt = attemptId` (after the `asf_*` check, so the firewall's own marker never trips it),
   *     forward via `openCall`, record the outcome on the ORIGINAL attempt and run T010 verify-before-retry (a retry
   *     records decision `require_approval` + `approver`, `retryOf` the original).
   * Every "not executed" exit records outcome `not_forwarded` (errorCode = the reason) so the attempt stops counting.
   * Never throws.
   */
  executeApproved(
    req: ExecuteApprovedRequest,
    openCall: OpenDirectCall,
  ): Promise<ExecuteApprovedResult>;
  /**
   * T011: close a rejected / expired approval: chained `approval` record, then outcome `not_forwarded` +
   * `approval.rejected` / `approval.expired` (D-023: it stops counting). Write failures latch the pipeline degraded.
   */
  resolveApproval(req: ResolveApprovalRequest): Result<null>;
  /** True once an outcome write failed; all later money calls are denied. */
  isDegraded(): boolean;
  /**
   * T010 startup reconciliation (`reconcileAtStartup`), once. Ends the `reconciling` state whatever happens; an error
   * latches the pipeline degraded. Skipped (err) when the pipeline is already degraded.
   */
  reconcile(): Promise<Result<ReconcileSummary>>;
  isReconciling(): boolean;
  /** Attempt ids flagged unknown and still unresolved (in memory). */
  unresolvedAttemptIds(): string[];
  /** Stop listening for late responses. */
  close(): void;
}

/**
 * Per-call bookkeeping shared by the envelope and the stage. Keyed by a fresh, private per-call token object that
 * the envelope stores on the context under `CALL_TOKEN` (stages that spread `{...ctx}` keep it). Not keyed by the
 * AbortSignal: a signal object may be shared between calls by a transport or a test.
 */
interface CallInfo {
  readonly tool: string;
  readonly audited: WeakSet<CallToolResult>;
}

interface DenyRecord {
  readonly sessionId: string;
  readonly args: unknown;
  readonly reason: string;
  readonly matchedRules?: readonly string[];
  /** Idempotency key of `args`, when known (stored on the deny attempt for forensics). */
  readonly idempotencyKey?: string;
}

/** Symbol-keyed slot on `CallContext` holding the envelope's per-call token (module-private). */
const CALL_TOKEN: unique symbol = Symbol("asf.callToken");
type TokenedContext = CallContext & { readonly [CALL_TOKEN]?: object };

function callTokenOf(ctx: CallContext): object | undefined {
  return (ctx as TokenedContext)[CALL_TOKEN];
}

/** Top-level keys that name a target resource (`payment_id`, `order_id`, `refund_id`, …). */
const TARGET_ID_KEY = /_id$/;

/** True iff some top-level `*_id` key was added, removed or changed between `before` and `after`. */
export function retargetsIds(
  before: Readonly<Record<string, unknown>>,
  after: Readonly<Record<string, unknown>>,
): boolean {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const k of keys) {
    if (!TARGET_ID_KEY.test(k)) continue;
    const inBefore = Object.hasOwn(before, k);
    if (inBefore !== Object.hasOwn(after, k)) return true;
    if (inBefore && !sameJson(before[k], after[k])) return true;
  }
  return false;
}

function withoutReason(args: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) if (k !== "reason") out[k] = v;
  return out;
}

/** An attempt that was (or was about to be) sent. */
interface SentAttempt {
  readonly id: string;
  readonly record: AuditAttemptRecord | undefined;
  /** Args as forwarded (stamped). */
  readonly args: Record<string, unknown>;
}

/** What a retry of the original attempt re-uses. */
interface RetryContext {
  /** `require_approval` only for an approved action (T011); the retry then carries `approver`. */
  readonly decision: "allow" | "transform" | "require_approval";
  readonly approver?: string;
  readonly matchedRules: string[];
  readonly recordedKey: string;
  /** Policy `finalArgs` (unstamped). */
  readonly finalArgs: Readonly<Record<string, unknown>>;
  readonly transformed: boolean;
  readonly reason: string;
  /** T012: the original was a shadow attempt; the retry is recorded the same way. */
  readonly shadow?: { readonly wouldDecision: Decision["type"] };
}

/** T011: what a settled send amounted to, reported by `settleForward` (the last report wins: a retry's). */
interface SettleStatus {
  readonly status: ApprovedExecutionStatus;
  readonly upstreamRef?: string;
  readonly code?: string;
}
type SettleSink = (s: SettleStatus) => void;

/** A flagged (unknown) action waiting for its late answer. */
interface FlaggedLate {
  readonly attemptId: string;
  readonly tool: string;
  readonly args: Record<string, unknown>;
  /** What the answer in hand at flag time proved; merged with the late answer (ambiguous always wins). */
  readonly failure: UpstreamFailure;
}

/** Max flagged actions remembered for late answers (oldest evicted; they stay flagged, only the auto-settle is lost). */
const MAX_FLAGGED_LATE = 1024;

/** Resource targets (top-level string `payment_id` / `order_id`) of forwarded args. */
function targetsOf(args: Readonly<Record<string, unknown>>): { payment?: string; order?: string } {
  const t: { payment?: string; order?: string } = {};
  if (typeof args["payment_id"] === "string") t.payment = args["payment_id"];
  if (typeof args["order_id"] === "string") t.order = args["order_id"];
  return t;
}

interface OutcomeSpec {
  readonly outcome: AuditOutcomeInput;
  readonly errorCode?: string;
  readonly latencyMs: number;
  readonly upstreamRef?: string;
}

export function pendingApprovalResult(approvalId: string): CallToolResult {
  return {
    isError: false,
    content: [
      {
        type: "text",
        text: JSON.stringify({
          decision: "pending_approval",
          approvalId,
          message: PENDING_APPROVAL_MESSAGE,
        }),
      },
    ],
  };
}

/** `{decision:"deny", ruleId}` body of a result, if it is a structured deny. */
export function denyRuleOf(r: CallToolResult): string | undefined {
  if (r.isError !== true) return undefined;
  const first = r.content[0];
  if (first?.type !== "text") return undefined;
  let body: unknown;
  try {
    body = JSON.parse(first.text);
  } catch {
    // Not a JSON body ⇒ not a structured deny.
    return undefined;
  }
  if (typeof body !== "object" || body === null) return undefined;
  const { decision, ruleId } = body as { decision?: unknown; ruleId?: unknown };
  return decision === "deny" && typeof ruleId === "string" ? ruleId : undefined;
}

/** Top-level `id` of the first JSON text item, if it is a valid upstream reference. */
export function upstreamRefOf(r: CallToolResult): string | undefined {
  const first = r.content[0];
  if (first?.type !== "text") return undefined;
  let body: unknown;
  try {
    body = JSON.parse(first.text);
  } catch {
    // A non-JSON success body simply has no reference.
    return undefined;
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) return undefined;
  const id = (body as { id?: unknown }).id;
  return upstreamRefSchema.safeParse(id).success ? (id as string) : undefined;
}

/** Map a forwarded call's report (+ result) to the audit outcome. Exported for the mapping-table test. */
export function outcomeFor(r: CallToolResult, report: ForwardReport | undefined): OutcomeSpec {
  if (report === undefined) {
    // Should never happen (forward tags every result): unknown ⇒ assume it may have executed.
    return { outcome: "upstream_error", errorCode: "firewall.forward_unknown", latencyMs: 0 };
  }
  const latencyMs = report.latencyMs;
  switch (report.kind) {
    case "ok": {
      if (r.isError === true) {
        // A definite Razorpay rejection is recorded distinctly so startup reconciliation can tell it apart.
        const errorCode =
          classifyToolResultFailure(r) === "definite_rejection"
            ? REJECTED_ERROR_CODE
            : "upstream.tool_error";
        return { outcome: "upstream_error", errorCode, latencyMs };
      }
      const ref = upstreamRefOf(r);
      return ref === undefined
        ? { outcome: "success", latencyMs }
        : { outcome: "success", latencyMs, upstreamRef: ref };
    }
    case "credential_leak":
      return { outcome: "upstream_error", errorCode: "upstream.credential_leak", latencyMs };
    case "upstream_timeout":
      return { outcome: "timeout", errorCode: "upstream.timeout", latencyMs };
    case "cancelled":
      return report.sent
        ? { outcome: "timeout", errorCode: "upstream.cancelled", latencyMs }
        : { outcome: "not_forwarded", errorCode: "agent.cancelled", latencyMs: 0 };
    case "upstream_unavailable":
      return report.sent
        ? { outcome: "upstream_error", errorCode: "upstream.unavailable", latencyMs }
        : { outcome: "not_forwarded", errorCode: "upstream.unavailable", latencyMs: 0 };
    case "upstream_error":
      return report.sent
        ? { outcome: "upstream_error", errorCode: "upstream.error", latencyMs }
        : { outcome: "not_forwarded", errorCode: "upstream.error", latencyMs: 0 };
    case "refused":
      return { outcome: "not_forwarded", errorCode: "firewall.forward_refused", latencyMs: 0 };
  }
}

function sameJson(a: unknown, b: unknown): boolean {
  const ca = canonicalJson(a);
  const cb = canonicalJson(b);
  return ca.ok && cb.ok && ca.value === cb.value;
}

/** Existing resources a money call acts on (top-level `payment_id` / `order_id` strings). */
interface ResourceTargets {
  payment?: string;
  order?: string;
}

/**
 * Lock keys for a call's targets: `payment:<id>` / `order:<id>`, SORTED, so every call acquires its resource locks
 * in the same global order (no lock-order deadlock between a call holding an order and one holding a payment). The
 * global money lock is always taken after all of them.
 */
export function resourceLockKeys(targets: {
  readonly payment?: string;
  readonly order?: string;
}): string[] {
  const keys: string[] = [];
  if (targets.payment !== undefined) keys.push(`payment:${targets.payment}`);
  if (targets.order !== undefined) keys.push(`order:${targets.order}`);
  return keys.sort();
}

interface FinalArgsProblem {
  readonly ruleId: string;
  readonly message: string;
}

/**
 * Re-check the args a non-deny decision would forward (a policy `transform` may have rewritten them): the same
 * invariants `moneyArgsStage` enforced on the agent's args must still hold, and the call must still target the same
 * resources. `undefined` = OK.
 */
export function checkFinalArgs(
  ctx: Pick<CallContext, "args" | "inputSchema"> & { readonly tool?: string },
  finalArgs: Readonly<Record<string, unknown>>,
): FinalArgsProblem | undefined {
  if (retargetsIds(ctx.args, finalArgs)) {
    return {
      ruleId: FIREWALL_RULES.transformRetarget,
      message:
        "a policy transform changed the target resource (an *_id argument); the call was denied",
    };
  }
  if (
    !isBounded(finalArgs) ||
    !hasSafeTopLevelKeys(finalArgs) ||
    Object.hasOwn(finalArgs, "reason")
  ) {
    return {
      ruleId: FIREWALL_RULES.invalidArgs,
      message: "a policy transform produced invalid arguments; the call was denied",
    };
  }
  const notes = notesProblem(ctx.tool ?? "", finalArgs);
  if (notes !== undefined) {
    return {
      ruleId: FIREWALL_RULES.invalidArgs,
      message: `a policy transform produced invalid notes (${notes}); the call was denied`,
    };
  }
  if (!allCurrenciesInr(finalArgs)) {
    return {
      ruleId: FIREWALL_RULES.currencyNotInr,
      message: "a policy transform set a currency other than INR; the call was denied",
    };
  }
  const schema = rewriteMoneySchema(ctx.inputSchema);
  // moneyArgsStage already required a rewritable schema; if that changed, check without it (stricter).
  const bad = findInvalidAmount(finalArgs, schema.ok ? schema.value : undefined);
  if (bad !== undefined) {
    return {
      ruleId: FIREWALL_RULES.invalidAmount,
      message: `a policy transform set field ${bad} to an invalid amount (must be a positive whole number of paise); the call was denied`,
    };
  }
  return undefined;
}

/** Audit `errorCode` for a pre-send gate deny: its rule id if it is a valid machine code. */
function gateCode(gate: PreCheckDeny): string {
  return ERROR_CODE_RE.test(gate.ruleId) ? gate.ruleId : "firewall.precheck_denied";
}

function withRuleId(d: Decision): string[] {
  // The deciding rule is always listed (e.g. `policy-default`, `engine-timeout` match no predicate).
  return d.matchedRules.includes(d.ruleId) ? [...d.matchedRules] : [...d.matchedRules, d.ruleId];
}

/** Structured `firewall.duplicate` deny (shape passed through verbatim by `redactSensitiveResult`). */
export function duplicateDenyResult(hit: DuplicateHit): CallToolResult {
  return jsonErrorResult({
    decision: "deny",
    ruleId: FIREWALL_RULES.duplicate,
    message: DUPLICATE_MESSAGES[hit.status],
    duplicateOf: {
      attemptId: hit.attemptId,
      status: hit.status,
      // Only a Razorpay-shaped id nothing would redact is shown (else omitted).
      ...(isSafeUpstreamRef(hit.upstreamRef) ? { upstreamRef: hit.upstreamRef } : {}),
    },
  });
}

/** T010 `verifiedAfterTimeout` success (shape passed through verbatim by `redactSensitiveResult`). */
export function verifiedSuccessResult(
  attemptId: string,
  upstreamRef?: string,
  refundStatus?: string,
): CallToolResult {
  const body: VerifiedSuccessBody = {
    outcome: "success",
    verifiedAfterTimeout: true,
    attemptId,
    ...(isSafeUpstreamRef(upstreamRef) ? { upstreamRef } : {}),
    message:
      refundStatus === "pending"
        ? VERIFIED_AFTER_TIMEOUT_PENDING_MESSAGE
        : VERIFIED_AFTER_TIMEOUT_MESSAGE,
  };
  return { isError: false, content: [{ type: "text", text: JSON.stringify(body) }] };
}

/** T010 unknown outcome (shape passed through verbatim by `redactSensitiveResult`). */
export function unknownOutcomeResult(attemptId: string): CallToolResult {
  const body: UnknownOutcomeBody = {
    outcome: "unknown",
    attemptId,
    flaggedForHuman: true,
    message: UNKNOWN_OUTCOME_MESSAGE,
  };
  return { isError: true, content: [{ type: "text", text: JSON.stringify(body) }] };
}

/** Why a forwarded call's outcome is unsettled (needs verification), or `undefined` if it is settled. */
export function unsettledTriggerOf(
  r: CallToolResult,
  report: ForwardReport | undefined,
):
  | {
      readonly trigger: "timeout" | "upstream_error";
      readonly toolError: boolean;
      /** What the answer in hand proves (only a direct tool error carries one; see `upstream-failure.ts`). */
      readonly failure: UpstreamFailure;
    }
  | undefined {
  const noAnswer = (trigger: "timeout" | "upstream_error") =>
    ({ trigger, toolError: false, failure: "none" }) as const;
  if (report === undefined) return noAnswer("upstream_error");
  switch (report.kind) {
    case "ok":
      return r.isError === true
        ? { trigger: "upstream_error", toolError: true, failure: classifyToolResultFailure(r) }
        : undefined;
    case "credential_leak":
      // The upstream body was replaced: nothing in hand can be classified.
      return noAnswer("upstream_error");
    case "upstream_timeout":
    case "cancelled":
      return report.sent ? noAnswer("timeout") : undefined;
    case "upstream_unavailable":
    case "upstream_error":
      return report.sent ? noAnswer("upstream_error") : undefined;
    case "refused":
      return undefined;
  }
}

/** Valid `duplicateWindowMs` (integer ms within bounds). */
export function isValidDuplicateWindowMs(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isSafeInteger(v) &&
    v >= MIN_DUPLICATE_WINDOW_MS &&
    v <= MAX_DUPLICATE_WINDOW_MS
  );
}

/**
 * @throws RangeError if `o.duplicateWindowMs` is out of range (a configuration error: refuse to build a pipeline
 * that would silently use a different window).
 */
export function createMoneyPipeline(o: MoneyPipelineOptions): MoneyPipeline {
  const log: Logger = o.logger ?? (() => undefined);
  const redact = o.redact ?? noRedact;
  const lockWaitMs = o.lockWaitMs ?? DEFAULT_LOCK_WAIT_MS;
  const duplicateWindowMs = o.duplicateWindowMs ?? DEFAULT_DUPLICATE_WINDOW_MS;
  if (!isValidDuplicateWindowMs(duplicateWindowMs)) {
    throw new RangeError(
      `duplicateWindowMs must be an integer between ${String(MIN_DUPLICATE_WINDOW_MS)} and ${String(MAX_DUPLICATE_WINDOW_MS)}`,
    );
  }
  const verifyWaitMs = o.verifyWaitMs ?? DEFAULT_VERIFY_WAIT_MS;
  if (
    !Number.isSafeInteger(verifyWaitMs) ||
    verifyWaitMs < 1 ||
    verifyWaitMs > MAX_VERIFY_WAIT_MS
  ) {
    throw new RangeError(
      `verifyWaitMs must be an integer between 1 and ${String(MAX_VERIFY_WAIT_MS)}`,
    );
  }
  const resourceLocks = createKeyedMutex();
  const globalLock = createMutex();
  const calls = new WeakMap<object, CallInfo>();
  let degraded = o.startDegraded !== undefined;
  const degradedMessage =
    o.startDegraded?.message ??
    "the audit log is unavailable; money actions are disabled until the firewall is restarted. The call was not sent";
  if (o.startDegraded !== undefined) {
    log(
      `AUDIT DEGRADED AT STARTUP: ${o.startDegraded.reason}. All money calls are denied (audit_unavailable); read tools still work.`,
    );
  }

  const adapterBase = {
    store: o.store,
    upstream: o.upstream,
    clock: o.clock,
    redact,
    ...(o.lookupTimeoutMs === undefined ? {} : { lookupTimeoutMs: o.lookupTimeoutMs }),
  };

  // ---- T010 state ----
  const verifier =
    o.verifier ??
    createActionVerifier({
      upstream: o.upstream,
      redact,
      ...(o.verifyLookupTimeoutMs === undefined
        ? {}
        : { lookupTimeoutMs: o.verifyLookupTimeoutMs }),
    });
  const tracker = createLateResponseTracker({
    source: o.lateResponses,
    timer: o.verifyTimer ?? o.timer,
    logger: log,
  });
  const unsettledDeps: UnsettledDeps = {
    store: o.store,
    verifier,
    tracker,
    verifyWaitMs,
    logger: log,
  };
  let reconciling = o.startReconciling === true;
  let reconcileStarted = false;
  /** Actions whose latest verification is `unknown`: they block duplicates with no age-out. */
  const unresolved = new Map<string, AuditActivity>();
  /** Flagged actions waiting for their late answer, keyed by `lateKey(generation, requestId)`. */
  const flaggedLate = new Map<string, FlaggedLate>();

  const latch = (why: string): void => {
    if (!degraded) {
      log(
        `AUDIT DEGRADED: ${why}. All further money calls are denied (audit_unavailable) until the proxy restarts.`,
      );
    }
    degraded = true;
  };

  /** Record an outcome; the record, or `undefined` (and a log line) on failure. */
  const writeOutcome = (attemptId: string, spec: OutcomeSpec): AuditOutcomeRecord | undefined => {
    const r = o.store.recordOutcome({
      attemptId,
      outcome: spec.outcome,
      latencyMs: spec.latencyMs,
      ...(spec.errorCode === undefined ? {} : { errorCode: spec.errorCode }),
      ...(spec.upstreamRef === undefined ? {} : { upstreamRef: spec.upstreamRef }),
    });
    if (!r.ok) {
      log(`audit outcome write failed for attempt ${attemptId}: ${r.error.code}`);
      return undefined;
    }
    if (r.value.kind !== "outcome") {
      log(`audit outcome write for attempt ${attemptId} returned an unexpected record`);
      return undefined;
    }
    return r.value;
  };

  /** Record an outcome. `false` (and a log line) on failure. */
  const recordOutcome = (attemptId: string, spec: OutcomeSpec): boolean =>
    writeOutcome(attemptId, spec) !== undefined;

  /** Write attempt `deny` + outcome `denied`. Audit write failures are logged (the call is denied regardless). */
  const recordDenied = (info: CallInfo, rec: DenyRecord, ruleId: string): void => {
    // Args that can't be audited (floats, …) are replaced by a marker so the deny keeps its own rule id.
    const canon = canonicalJson(rec.args);
    const att = o.store.recordAttempt({
      sessionId: rec.sessionId,
      tool: info.tool,
      args: canon.ok ? rec.args : { _unauditable: canon.error.code },
      reason: rec.reason,
      decision: "deny",
      matchedRules: rec.matchedRules ?? [ruleId],
      ...(rec.idempotencyKey === undefined ? {} : { idempotencyKey: rec.idempotencyKey }),
    });
    if (att.ok) {
      recordOutcome(att.value.id, { outcome: "denied", latencyMs: 0 });
    } else {
      const trail = att.error.details?.["attemptId"];
      if (att.error.code === "audit.invalid_args" && typeof trail === "string") {
        recordOutcome(trail, { outcome: "denied", latencyMs: 0 });
      } else {
        log(
          `audit attempt write failed for a denied ${escapeForTerminal(info.tool)} call: ${att.error.code}`,
        );
      }
    }
  };

  /** Audit a firewall/policy deny and return the structured deny (marked as audited). */
  const auditedDeny = (
    info: CallInfo,
    rec: DenyRecord,
    ruleId: string,
    message: string,
  ): CallToolResult => {
    recordDenied(info, rec, ruleId);
    return mark(info, denyResult(ruleId, message));
  };

  const mark = (info: CallInfo, r: CallToolResult): CallToolResult => {
    info.audited.add(r);
    return r;
  };

  /**
   * T012: re-run `preCheck` right before a send. A deny (or a throw ⇒ `firewall.internal_error`) is returned. For a
   * shadow call (`would` = the policy decision it is NOT enforcing) whose policy did not allow it, shadow mode must
   * still be ON: otherwise ⇒ deny `firewall.shadow_ended` (the operator turned shadow off mid-call; the policy's
   * decision applies again, so the call is not sent).
   */
  const sendGate = async (
    ctx: CallContext,
    would?: Decision["type"],
  ): Promise<PreCheckDeny | undefined> => {
    if (o.preCheck === undefined) return undefined;
    try {
      const pre = await o.preCheck(ctx);
      if (pre !== undefined && isPreCheckDeny(pre)) return pre;
      if (would !== undefined && would !== "allow" && pre === undefined) {
        return { ruleId: FIREWALL_RULES.shadowEnded, message: SHADOW_ENDED_MESSAGE };
      }
      return undefined;
    } catch (e: unknown) {
      log(`preCheck threw ${e instanceof Error ? e.name : typeof e} before a send; not sent`);
      return {
        ruleId: FIREWALL_RULES.internalError,
        message: "the firewall pre-check failed; the call was not sent",
      };
    }
  };

  /** Audit a `firewall.duplicate` deny and return it. */
  const duplicateDenied = (info: CallInfo, rec: DenyRecord, hit: DuplicateHit): CallToolResult => {
    recordDenied(info, rec, FIREWALL_RULES.duplicate);
    return mark(info, duplicateDenyResult(hit));
  };

  /**
   * Everything `findDuplicate` needs, read once per call through the call's shared memoised reader. `undefined` +
   * a log line on any failure (caller denies `firewall.duplicate_check_failed`).
   */
  const duplicateScope = (
    read: ActivityReader,
  ): { rows: Parameters<typeof findDuplicate>[0]; nowMs: number } | { failed: string } => {
    let now: number;
    try {
      now = o.clock.nowMs();
    } catch (e: unknown) {
      return { failed: `clock threw ${e instanceof Error ? e.name : typeof e}` };
    }
    if (!Number.isSafeInteger(now) || now < 0) return { failed: "clock returned an invalid time" };
    const rows = read(now - Math.max(duplicateWindowMs, DEFAULT_OPEN_LOOKBACK_MS));
    if (!rows.ok) return { failed: `audit activity read failed: ${rows.error.code}` };
    // T010: unresolved (unknown) actions older than the scan still block.
    return { rows: mergeActivity(rows.value, unresolved.values()), nowMs: now };
  };

  const duplicateCheckFailed = (info: CallInfo, base: DenyRecord, why: string): CallToolResult => {
    log(`duplicate check failed for ${escapeForTerminal(info.tool)}: ${why}; denied`);
    return auditedDeny(
      info,
      base,
      FIREWALL_RULES.duplicateCheckFailed,
      "the firewall could not check for a duplicate of this action; the call was not sent",
    );
  };

  const keyDenied = (info: CallInfo, base: DenyRecord): CallToolResult =>
    auditedDeny(
      info,
      base,
      FIREWALL_RULES.invalidArgs,
      "the arguments could not be keyed for duplicate detection (only integers, strings, booleans, null, arrays and objects); the call was not sent",
    );

  const stage: Stage = async (ctx: CallContext, next: Next): Promise<CallToolResult> => {
    const token = callTokenOf(ctx);
    const info = token === undefined ? undefined : calls.get(token);
    if (info === undefined) {
      // Stage used without the envelope: can't bind the exact tool name ⇒ fail closed (not audited: no binding).
      log("money stage invoked without its envelope; denied");
      return denyResult(
        FIREWALL_RULES.internalError,
        "the firewall is misconfigured; the call was denied",
      );
    }
    const isMoney = classifyTool(info.tool) === "money" || ctx.toolClass === "money";
    if (!isMoney) {
      if (ctx.tool !== info.tool) {
        return denyResult(
          FIREWALL_RULES.toolMismatch,
          "tool name changed inside the firewall; denied",
        );
      }
      return next(ctx);
    }
    const reason = ctx.untrustedReason ?? "";
    const base = { sessionId: ctx.sessionId, args: ctx.args, reason };

    if (ctx.tool !== info.tool) {
      return auditedDeny(
        info,
        base,
        FIREWALL_RULES.toolMismatch,
        "tool name changed inside the firewall; the call was denied",
      );
    }
    if (ctx.untrustedReason === undefined) {
      return auditedDeny(
        info,
        base,
        FIREWALL_RULES.internalError,
        "the firewall could not validate this call's reason; it was denied",
      );
    }
    // T012: kill switch / shadow mode first, so a kill-switch deny wins over every other state.
    let shadow = false;
    if (o.preCheck !== undefined) {
      let pre: PreCheckVerdict | undefined;
      try {
        pre = await o.preCheck(ctx);
      } catch (e: unknown) {
        log(`preCheck threw ${e instanceof Error ? e.name : typeof e}; denied`);
        return auditedDeny(
          info,
          base,
          FIREWALL_RULES.internalError,
          "the firewall pre-check failed; the call was denied",
        );
      }
      if (pre !== undefined) {
        if (isPreCheckDeny(pre)) return auditedDeny(info, base, pre.ruleId, pre.message);
        shadow = true;
      }
    }
    if (degraded) {
      return auditedDeny(info, base, FIREWALL_RULES.auditUnavailable, degradedMessage);
    }
    if (reconciling) {
      return auditedDeny(info, base, FIREWALL_RULES.reconciling, RECONCILING_MESSAGE);
    }
    // T010: `asf_*` notes are the firewall's marker namespace.
    const notes = notesProblem(info.tool, ctx.args);
    if (notes !== undefined) {
      return auditedDeny(info, base, FIREWALL_RULES.invalidArgs, `${notes}; the call was not sent`);
    }

    // 1. Per-resource locks (payment and/or order), in sorted key order.
    const targets: ResourceTargets = {};
    for (const [field, prefix] of [
      ["payment_id", "payment"],
      ["order_id", "order"],
    ] as const) {
      if (!Object.hasOwn(ctx.args, field)) continue;
      const v: unknown = ctx.args[field];
      if (typeof v !== "string") {
        return auditedDeny(
          info,
          base,
          FIREWALL_RULES.invalidArgs,
          `${field} must be a string; the call was not sent`,
        );
      }
      targets[prefix] = v;
    }
    const lockKeys = resourceLockKeys(targets);
    const releases: Release[] = [];
    try {
      for (const key of lockKeys) {
        const got = await resourceLocks.acquire(key, {
          timeoutMs: lockWaitMs,
          signal: ctx.signal,
        });
        if (!got.ok) return lockDenied(info, base, got.error.code);
        releases.push(got.value);
      }
      return await underResourceLocks(ctx, next, info, base, targets, shadow);
    } finally {
      // Release in reverse acquisition order.
      for (const release of releases.reverse()) release();
    }
  };

  const lockDenied = (info: CallInfo, base: DenyRecord, code: string): CallToolResult =>
    code === "firewall.cancelled"
      ? auditedDeny(
          info,
          base,
          FIREWALL_RULES.cancelled,
          "the request was cancelled; the call was not sent",
        )
      : auditedDeny(
          info,
          base,
          FIREWALL_RULES.busy,
          "another money action is in progress; try again shortly. The call was not sent",
        );

  /** INR invariant (D-017) for the payment / order a call acts on; `undefined` = OK. */
  const inrProblem = async (targets: ResourceTargets): Promise<FinalArgsProblem | undefined> => {
    if (targets.payment !== undefined) {
      const payment = await createRazorpayLookup(adapterBase).payment(targets.payment);
      if (!payment.ok) {
        return {
          ruleId: FIREWALL_RULES.paymentLookupFailed,
          message: "the payment could not be looked up to verify it; the call was not sent",
        };
      }
      if (payment.value.currency !== "INR") {
        return {
          ruleId: FIREWALL_RULES.currencyNotInr,
          message: "only INR payments are supported through the firewall; the call was not sent",
        };
      }
    }
    if (targets.order !== undefined) {
      const order = await createOrderLookup(adapterBase).order(targets.order);
      if (!order.ok) {
        return {
          ruleId: FIREWALL_RULES.orderLookupFailed,
          message: "the order could not be looked up to verify it; the call was not sent",
        };
      }
      if (order.value.currency !== "INR") {
        return {
          ruleId: FIREWALL_RULES.currencyNotInr,
          message: "only INR orders are supported through the firewall; the call was not sent",
        };
      }
    }
    return undefined;
  };

  const underResourceLocks = async (
    ctx: CallContext,
    next: Next,
    info: CallInfo,
    base: DenyRecord,
    targets: ResourceTargets,
    shadow: boolean,
  ): Promise<CallToolResult> => {
    const reason = base.reason;

    // 2. INR invariant for calls acting on an existing payment and/or order.
    const inr = await inrProblem(targets);
    if (inr !== undefined) return auditedDeny(info, base, inr.ruleId, inr.message);
    if (ctx.signal.aborted) {
      return auditedDeny(
        info,
        base,
        FIREWALL_RULES.cancelled,
        "the request was cancelled; the call was not sent",
      );
    }

    // 3. Global lock around evaluate + recordAttempt.
    const got = await globalLock.acquire({ timeoutMs: lockWaitMs, signal: ctx.signal });
    if (!got.ok) return lockDenied(info, base, got.error.code);
    // The latch may have been set (another call's outcome write failed) while this call waited for the lock.
    if (degraded) {
      try {
        return auditedDeny(info, base, FIREWALL_RULES.auditUnavailable, degradedMessage);
      } finally {
        got.value();
      }
    }
    let res: EvalResult;
    /** The decision acted on: the policy's, or (T012 shadow) an `allow` standing in for it. */
    let decision: Decision;
    /** Args acted on: the policy's `finalArgs`, or (T012 shadow) the agent's original args. */
    let finalArgs: Readonly<Record<string, unknown>>;
    /** T012: the policy decision a shadow call did not enforce. */
    let would: Decision["type"] | undefined;
    let attempt: Result<AuditRecord>;
    /** Args recorded and (for allow / transform) forwarded: `finalArgs` + the T010 marker. */
    let forwardArgs: Record<string, unknown> = {};
    let recordedKey: string;
    let transformed: boolean;
    try {
      // 3a. Duplicate check (T009) on the agent's args, sharing one audit read with the policy.
      const agentKey = idempotencyKey(info.tool, ctx.args);
      if (!agentKey.ok) return keyDenied(info, base);
      const read = memoisedReader(o.store);
      const scope = duplicateScope(read);
      if ("failed" in scope) return duplicateCheckFailed(info, base, scope.failed);
      const dupOpts = {
        nowMs: scope.nowMs,
        windowMs: duplicateWindowMs,
        openLookbackMs: DEFAULT_OPEN_LOOKBACK_MS,
      };
      const keyedBase: DenyRecord = { ...base, idempotencyKey: agentKey.value };
      const dup = findDuplicate(scope.rows, info.tool, new Set([agentKey.value]), dupOpts);
      if (!dup.ok) return duplicateCheckFailed(info, keyedBase, dup.error.code);
      if (dup.value !== undefined) return duplicateDenied(info, keyedBase, dup.value);

      const deps = createPolicyDeps({ ...adapterBase, timer: o.timer, read });
      res = await evaluate(
        o.policy,
        { tool: info.tool, args: ctx.args, reason, sessionId: ctx.sessionId },
        deps,
      );
      decision = res.decision;
      finalArgs = res.finalArgs;
      // T012: shadow mode observes a POLICY decision instead of enforcing it; engine errors stay real denies.
      if (shadow && isShadowableDecision(o.policy, res)) {
        would = res.decision.type;
        decision = {
          type: "allow",
          ruleId: res.decision.ruleId,
          matchedRules: withRuleId(res.decision),
        };
        finalArgs = ctx.args;
        log(
          `shadow mode: ${escapeForTerminal(info.tool)} would ${would} (${escapeForTerminal(res.decision.ruleId)}); forwarding the original args`,
        );
      }
      recordedKey = agentKey.value;
      if (decision.type !== "deny") {
        const bad = checkFinalArgs({ ...ctx, tool: info.tool }, finalArgs);
        if (bad !== undefined) {
          return auditedDeny(
            info,
            { ...keyedBase, matchedRules: [...decision.matchedRules, bad.ruleId] },
            bad.ruleId,
            bad.message,
          );
        }
        // 3b. A transform changed the args: the forwarded action must not duplicate an earlier one either.
        const finalKey = idempotencyKey(info.tool, finalArgs);
        if (!finalKey.ok) {
          return keyDenied(info, {
            ...keyedBase,
            matchedRules: [...decision.matchedRules, FIREWALL_RULES.invalidArgs],
          });
        }
        if (finalKey.value !== agentKey.value) {
          const dup2 = findDuplicate(
            scope.rows,
            info.tool,
            new Set([agentKey.value, finalKey.value]),
            dupOpts,
          );
          if (!dup2.ok) return duplicateCheckFailed(info, keyedBase, dup2.error.code);
          if (dup2.value !== undefined) {
            return duplicateDenied(
              info,
              {
                ...keyedBase,
                matchedRules: [...decision.matchedRules, FIREWALL_RULES.duplicate],
              },
              dup2.value,
            );
          }
        }
        recordedKey = finalKey.value;
      }
      const d = decision;
      transformed = d.type !== "deny" && !sameJson(finalArgs, ctx.args);
      // T010: pre-generate the attempt id and stamp it into the forwarded args (notes marker).
      let presetId: string | undefined;
      if (d.type !== "deny") {
        presetId = redactionSafeUuid();
        const stamped = stampAttemptMarker(info.tool, finalArgs, presetId);
        if (!stamped.ok) {
          return auditedDeny(
            info,
            { ...keyedBase, matchedRules: [...d.matchedRules, FIREWALL_RULES.invalidArgs] },
            FIREWALL_RULES.invalidArgs,
            "notes must be an object of key-value pairs; the call was not sent",
          );
        }
        forwardArgs = stamped.value;
      }
      attempt = o.store.recordAttempt({
        sessionId: ctx.sessionId,
        tool: info.tool,
        args: d.type === "deny" ? ctx.args : forwardArgs,
        ...(transformed ? { originalArgs: ctx.args } : {}),
        reason,
        decision: d.type,
        matchedRules: withRuleId(d),
        // Key of the recorded args (the forwarded ones for a non-deny decision; notes are never part of it).
        idempotencyKey: recordedKey,
        ...(presetId === undefined ? {} : { id: presetId }),
        ...(would === undefined ? {} : { shadow: { wouldDecision: would } }),
      });
    } finally {
      got.value();
    }

    // 4. Attempt not recorded ⇒ never forward.
    if (!attempt.ok && attempt.error.code === "audit.invalid_shadow") {
      // T012: shadow mode was turned off between the mode read and the attempt write.
      return auditedDeny(info, base, FIREWALL_RULES.shadowEnded, SHADOW_ENDED_MESSAGE);
    }
    if (!attempt.ok) {
      const trail = attempt.error.details?.["attemptId"];
      if (attempt.error.code === "audit.invalid_args" && typeof trail === "string") {
        recordOutcome(trail, { outcome: "denied", latencyMs: 0 });
        return mark(
          info,
          denyResult(
            FIREWALL_RULES.auditInvalidArgs,
            "the arguments could not be recorded in the audit log (only integers, strings, booleans, null, arrays and objects); the call was not sent",
          ),
        );
      }
      log(
        `audit attempt write failed for ${escapeForTerminal(info.tool)}: ${attempt.error.code}; denied`,
      );
      return mark(
        info,
        denyResult(
          FIREWALL_RULES.auditUnavailable,
          "the audit log is unavailable; the call was not sent",
        ),
      );
    }
    const attemptId = attempt.value.id;
    const attemptRecord = attempt.value.kind === "attempt" ? attempt.value : undefined;
    const d = decision;

    // 5. Deny.
    if (d.type === "deny") {
      recordOutcome(attemptId, { outcome: "denied", latencyMs: 0 });
      return mark(info, denyResult(d.ruleId, d.message));
    }

    // 6. Require approval: the attempt stays open; nothing is executed.
    if (d.type === "require_approval") {
      const hash = approvalArgsHash(info.tool, res.finalArgs);
      let created: Result<{ approvalId: string }>;
      if (!hash.ok) {
        created = hash;
      } else {
        try {
          created = await o.approvals.create({
            attemptId,
            tool: info.tool,
            finalArgs: res.finalArgs,
            finalArgsRedacted: argsForDisplay(res.finalArgs),
            argsHash: hash.value,
            untrustedReason: reason,
            reasonForDisplay: reasonForDisplay(reason),
            sessionId: ctx.sessionId,
            ruleId: d.ruleId,
            message: d.message,
            via: d.via,
            timeoutMin: d.timeoutMin,
            matchedRules: [...d.matchedRules],
          });
        } catch (e: unknown) {
          created = err(
            "approval.unavailable",
            `approval store threw ${e instanceof Error ? e.name : typeof e}`,
          );
        }
      }
      if (!created.ok) {
        log(`approval request failed for attempt ${attemptId}: ${created.error.code}`);
        if (
          !recordOutcome(attemptId, {
            outcome: "not_forwarded",
            errorCode: "approval.unavailable",
            latencyMs: 0,
          })
        ) {
          latch("an approval outcome could not be recorded");
        }
        return mark(
          info,
          denyResult(
            FIREWALL_RULES.approvalUnavailable,
            "this action needs human approval but the approval service is unavailable; the call was not sent",
          ),
        );
      }
      return mark(info, pendingApprovalResult(created.value.approvalId));
    }

    // 7. allow / transform ⇒ forward exactly finalArgs.
    if (ctx.signal.aborted) {
      if (
        !recordOutcome(attemptId, {
          outcome: "not_forwarded",
          errorCode: "agent.cancelled",
          latencyMs: 0,
        })
      ) {
        latch("a not_forwarded outcome could not be recorded");
      }
      return mark(
        info,
        jsonErrorResult({
          error: "cancelled",
          message: "the request was cancelled; the call was not sent",
          forwarded: false,
        }),
      );
    }
    // T012: the kill switch may have been turned on (or shadow mode off) while this call waited.
    const gate = await sendGate(ctx, would);
    if (gate !== undefined) {
      if (
        !recordOutcome(attemptId, {
          outcome: "not_forwarded",
          errorCode: gateCode(gate),
          latencyMs: 0,
        })
      ) {
        latch("a not_forwarded outcome could not be recorded");
      }
      return mark(info, denyResult(gate.ruleId, gate.message));
    }
    // Last check before the send: the latch may have been set after the global lock was released (e.g. by a
    // concurrent call on another resource). The outcome write is best-effort (the audit log is already degraded).
    if (degraded) {
      recordOutcome(attemptId, {
        outcome: "not_forwarded",
        errorCode: FIREWALL_RULES.auditUnavailable,
        latencyMs: 0,
      });
      return mark(info, denyResult(FIREWALL_RULES.auditUnavailable, degradedMessage));
    }
    // Razorpay's MCP tools take no idempotency header: the attempt's `idempotencyKey` (duplicate check) and the notes
    // marker (verification, T010) identify this logical action.
    let r: CallToolResult | undefined;
    try {
      r = await next({ ...ctx, args: forwardArgs });
    } catch (e: unknown) {
      log(
        `forwarding ${escapeForTerminal(info.tool)} threw ${e instanceof Error ? e.name : typeof e}`,
      );
      r = undefined;
    }
    const retryCtx: RetryContext = {
      decision: d.type,
      matchedRules: withRuleId(d),
      recordedKey,
      finalArgs,
      transformed,
      reason,
      ...(would === undefined ? {} : { shadow: { wouldDecision: would } }),
    };
    return settleForward(
      ctx,
      info,
      { id: attemptId, record: attemptRecord, args: forwardArgs },
      r,
      retryCtx,
    );
  };

  /** Result when `forward` threw (the call may have reached Razorpay). */
  const forwardThrewResult = (): CallToolResult =>
    jsonErrorResult({
      error: "upstream_error",
      message:
        "the firewall failed while sending this call; it may have reached Razorpay — check its status before retrying",
      forwarded: true,
    });

  const notRetriedResult = (): CallToolResult =>
    jsonErrorResult({ error: "upstream_timeout", message: NOT_RETRIED_MESSAGE, forwarded: true });

  /**
   * Record the outcome of a send (`r` undefined: forward threw) and, if it may hide an execution, verify it (T010)
   * and map the verification to the agent's result. `retryCtx` is given only for the ORIGINAL send.
   */
  const settleForward = async (
    ctx: CallContext,
    info: CallInfo,
    sent: SentAttempt,
    r: CallToolResult | undefined,
    retryCtx: RetryContext | undefined,
    sink: SettleSink = () => undefined,
  ): Promise<CallToolResult> => {
    const report = r === undefined ? undefined : forwardReportOf(r);
    const spec: OutcomeSpec =
      r === undefined
        ? { outcome: "upstream_error", errorCode: FIREWALL_RULES.forwardThrew, latencyMs: 0 }
        : outcomeFor(r, report);
    const fallback = r ?? forwardThrewResult();
    const outcomeRec = writeOutcome(sent.id, spec);
    if (outcomeRec === undefined) {
      latch(`the outcome of attempt ${sent.id} (${spec.outcome}) could not be recorded`);
      sink(
        spec.outcome === "not_forwarded"
          ? { status: "not_executed", code: spec.errorCode ?? "upstream.not_sent" }
          : { status: "unknown", code: FIREWALL_RULES.auditUnavailable },
      );
      return mark(info, fallback);
    }
    const trig =
      r === undefined
        ? { trigger: "upstream_error" as const, toolError: false, failure: "none" as const }
        : unsettledTriggerOf(r, report);
    // Settled, or the audit log is degraded (verification records can't be trusted to land): result as is.
    if (trig === undefined || degraded) {
      if (spec.outcome === "success") {
        sink({
          status: "executed",
          ...(spec.upstreamRef === undefined ? {} : { upstreamRef: spec.upstreamRef }),
        });
      } else if (spec.outcome === "not_forwarded") {
        sink({ status: "not_executed", code: spec.errorCode ?? "upstream.not_sent" });
      } else {
        sink({ status: "unknown", code: FIREWALL_RULES.auditUnavailable });
      }
      return mark(info, fallback);
    }

    const token: RetryForward | undefined =
      r !== undefined && retryCtx !== undefined && RETRYABLE_TOOLS.has(info.tool)
        ? retryForwardOf(r)
        : undefined;
    const waitLate =
      token !== undefined &&
      report?.kind === "upstream_timeout" &&
      report.requestId !== undefined &&
      report.generation !== undefined &&
      !ctx.signal.aborted
        ? { generation: report.generation, requestId: report.requestId }
        : undefined;
    const res = await handleUnsettled(unsettledDeps, {
      attemptId: sent.id,
      tool: info.tool,
      args: sent.args,
      trigger: trig.trigger,
      failure: trig.failure,
      ...(waitLate === undefined ? {} : { waitLate }),
    });
    if (res.auditFailed) {
      latch(`the verification of attempt ${sent.id} could not be recorded`);
      sink({ status: "unknown", code: FIREWALL_RULES.auditUnavailable });
      return mark(info, unknownOutcomeResult(sent.id));
    }
    const f = res.finding;
    if (f.result === "happened") {
      sink({
        status: "executed",
        ...(f.upstreamRef === undefined ? {} : { upstreamRef: f.upstreamRef }),
      });
      return mark(info, verifiedSuccessResult(sent.id, f.upstreamRef, f.refundStatus));
    }
    if (f.result === "not_happened") {
      if (trig.toolError) {
        sink({ status: "failed", code: spec.errorCode ?? "upstream.tool_error" });
        return mark(info, fallback);
      }
      // Retry preconditions: a timed-out refund (token + waitLate) whose LATE answer was a failure. `retryOnce`
      // re-checks cancellation and the degraded latch.
      if (
        token !== undefined &&
        retryCtx !== undefined &&
        waitLate !== undefined &&
        res.lateRejection
      ) {
        return retryOnce(ctx, info, sent.id, retryCtx, token, sink);
      }
      log(
        `attempt ${sent.id} was verified not executed; not retried (no late definite-rejection answer)`,
      );
      sink({ status: "not_executed", code: "upstream.not_executed" });
      return mark(info, notRetriedResult());
    }
    flagUnresolved(info.tool, sent, outcomeRec, res.record, report, trig);
    sink({ status: "unknown", code: "verify.unknown" });
    return mark(info, unknownOutcomeResult(sent.id));
  };

  /** Keep an unknown action blocking (no age-out) and listen for its late answer. */
  const flagUnresolved = (
    tool: string,
    sent: SentAttempt,
    outcome: AuditOutcomeRecord,
    verification: AuditVerificationRecord | undefined,
    report: ForwardReport | undefined,
    trig: { readonly trigger: "timeout" | "upstream_error"; readonly failure: UpstreamFailure },
  ): void => {
    if (sent.record !== undefined && verification !== undefined) {
      unresolved.set(sent.id, { attempt: sent.record, outcome, verification });
    }
    // Only a timed-out / cancelled send can still get a late answer; a direct answer (tool error) already arrived.
    if (trig.trigger !== "timeout") return;
    if (report?.requestId === undefined || report.generation === undefined) return;
    if (flaggedLate.size >= MAX_FLAGGED_LATE) {
      const oldest = flaggedLate.keys().next();
      if (oldest.done !== true) flaggedLate.delete(oldest.value);
    }
    const key = lateKey(report.generation, report.requestId);
    const entry: FlaggedLate = { attemptId: sent.id, tool, args: sent.args, failure: trig.failure };
    flaggedLate.set(key, entry);
    // The answer may already have arrived (between the wait and now).
    const already = tracker.take(report.generation, report.requestId);
    if (already !== undefined) void settleLate(key, entry, already);
  };

  /** Background re-verification of a flagged action whose late answer arrived (trigger `late_response`). */
  const settleLate = async (
    key: string,
    entry: FlaggedLate,
    late: Pick<LateResponse, "isError" | "failure">,
  ): Promise<void> => {
    flaggedLate.delete(key);
    const releases: Release[] = [];
    try {
      const keys = resourceLockKeys(targetsOf(entry.args));
      for (const k of keys) {
        const got = await resourceLocks.acquire(k, { timeoutMs: lockWaitMs });
        if (!got.ok) {
          log(
            `late answer for attempt ${entry.attemptId} not re-verified (${got.error.code}); it stays flagged for a human`,
          );
          return;
        }
        releases.push(got.value);
      }
      if (degraded || !unresolved.has(entry.attemptId)) return;
      const res = await handleUnsettled(unsettledDeps, {
        attemptId: entry.attemptId,
        tool: entry.tool,
        args: entry.args,
        trigger: "late_response",
        failure: entry.failure,
        late,
        recordUnknown: false,
      });
      if (res.auditFailed) {
        latch(`the late-response verification of attempt ${entry.attemptId} could not be recorded`);
        return;
      }
      if (res.record !== undefined && res.finding.result !== "unknown") {
        unresolved.delete(entry.attemptId);
        log(
          `late answer settled attempt ${entry.attemptId} (${escapeForTerminal(entry.tool)}): ${res.finding.result}`,
        );
      } else {
        log(
          `late answer for attempt ${entry.attemptId} did not settle it; still flagged for a human`,
        );
      }
    } catch (e: unknown) {
      log(
        `late-response verification failed (${e instanceof Error ? e.name : typeof e}); still flagged`,
      );
    } finally {
      for (const release of releases.reverse()) release();
    }
  };

  tracker.onUnclaimed((e) => {
    const key = lateKey(e.generation, e.requestId);
    const entry = flaggedLate.get(key);
    if (entry === undefined) return;
    tracker.take(e.generation, e.requestId);
    void settleLate(key, entry, e);
  });

  /**
   * The single retry (T010) after the original was verified NOT executed on a late failure answer. No policy re-run:
   * the firewall invariants and the duplicate check (excluding the original) run under the global lock; the retry
   * gets a new attempt id + marker and `retryOf` = original. Its own unclear outcome is verified once, never retried.
   */
  const retryOnce = async (
    ctx: CallContext,
    info: CallInfo,
    originalId: string,
    rc: RetryContext,
    token: RetryForward,
    sink: SettleSink,
  ): Promise<CallToolResult> => {
    const notRetried = (why: string): CallToolResult => {
      log(`attempt ${originalId} was verified not executed but not retried: ${why}`);
      sink({ status: "not_executed", code: "upstream.not_executed" });
      return mark(info, notRetriedResult());
    };
    if (ctx.signal.aborted) return notRetried("the request was cancelled");
    const gate0 = await sendGate(ctx, rc.shadow?.wouldDecision);
    if (gate0 !== undefined) return notRetried(gate0.ruleId);
    if (degraded) return notRetried("the audit log is degraded");
    const bad = checkFinalArgs({ ...ctx, tool: info.tool }, rc.finalArgs);
    if (bad !== undefined) return notRetried(bad.ruleId);
    const got = await globalLock.acquire({ timeoutMs: lockWaitMs, signal: ctx.signal });
    if (!got.ok) return notRetried(got.error.code);
    let att: Result<AuditRecord> | undefined;
    let stamped: Record<string, unknown>;
    try {
      if (degraded) return notRetried("the audit log is degraded");
      const scope = duplicateScope(memoisedReader(o.store));
      if ("failed" in scope) return notRetried(scope.failed);
      const dup = findDuplicate(scope.rows, info.tool, new Set([rc.recordedKey]), {
        nowMs: scope.nowMs,
        windowMs: duplicateWindowMs,
        openLookbackMs: DEFAULT_OPEN_LOOKBACK_MS,
        excludeAttemptIds: new Set([originalId]),
      });
      if (!dup.ok) return notRetried(dup.error.code);
      if (dup.value !== undefined) {
        log(`retry of attempt ${originalId} skipped: duplicate of ${dup.value.attemptId}`);
        sink({ status: "not_executed", code: FIREWALL_RULES.duplicate });
        return mark(info, duplicateDenyResult(dup.value));
      }
      const retryId = redactionSafeUuid();
      const s = stampAttemptMarker(info.tool, rc.finalArgs, retryId);
      if (!s.ok) return notRetried(s.error.code);
      stamped = s.value;
      att = o.store.recordAttempt({
        id: retryId,
        retryOf: originalId,
        sessionId: ctx.sessionId,
        tool: info.tool,
        args: stamped,
        ...(rc.transformed ? { originalArgs: ctx.args } : {}),
        reason: rc.reason,
        decision: rc.decision,
        matchedRules: rc.matchedRules,
        idempotencyKey: rc.recordedKey,
        ...(rc.approver === undefined ? {} : { approver: rc.approver }),
        ...(rc.shadow === undefined ? {} : { shadow: { wouldDecision: rc.shadow.wouldDecision } }),
      });
    } finally {
      got.value();
    }
    if (!att.ok) return notRetried(`retry attempt not recorded (${att.error.code})`);
    const retryAttempt = att.value;
    const gate = await sendGate(ctx, rc.shadow?.wouldDecision);
    if (gate !== undefined) {
      if (
        !recordOutcome(retryAttempt.id, {
          outcome: "not_forwarded",
          errorCode: gateCode(gate),
          latencyMs: 0,
        })
      ) {
        latch("a retry's not_forwarded outcome could not be recorded");
      }
      return notRetried(gate.ruleId);
    }
    if (ctx.signal.aborted || degraded) {
      const cancelled = ctx.signal.aborted;
      if (
        !recordOutcome(retryAttempt.id, {
          outcome: "not_forwarded",
          errorCode: cancelled ? "agent.cancelled" : FIREWALL_RULES.auditUnavailable,
          latencyMs: 0,
        })
      ) {
        latch("a retry's not_forwarded outcome could not be recorded");
      }
      return notRetried(cancelled ? "the request was cancelled" : "the audit log is degraded");
    }
    log(`retrying attempt ${originalId} once as ${retryAttempt.id} (verified not executed)`);
    let r2: CallToolResult | undefined;
    try {
      r2 = await token(stamped);
    } catch (e: unknown) {
      log(
        `retry of ${escapeForTerminal(info.tool)} threw ${e instanceof Error ? e.name : typeof e}`,
      );
      r2 = undefined;
    }
    return settleForward(
      ctx,
      info,
      {
        id: retryAttempt.id,
        record: retryAttempt.kind === "attempt" ? retryAttempt : undefined,
        args: stamped,
      },
      r2,
      undefined,
      sink,
    );
  };

  // ---- T011: approved actions ----

  /** Close an approved action without sending it: outcome `not_forwarded` + `code` (latch on write failure). */
  const approvedNotExecuted = (
    attemptId: string,
    code: string,
    message: string,
    writeOutcome = true,
  ): ExecuteApprovedResult => {
    log(`approved attempt ${attemptId} not executed: ${code}`);
    if (
      writeOutcome &&
      !recordOutcome(attemptId, { outcome: "not_forwarded", errorCode: code, latencyMs: 0 })
    ) {
      latch(`the not_forwarded outcome of approved attempt ${attemptId} could not be recorded`);
    }
    return { status: "not_executed", attemptId, code, result: denyResult(code, message) };
  };

  const executeApproved = async (
    req: ExecuteApprovedRequest,
    openCall: OpenDirectCall,
  ): Promise<ExecuteApprovedResult> => {
    const attemptId = req.attemptId;
    // 1. The decision is chained BEFORE anything else (and before any outcome).
    const appr = o.store.recordApproval({
      attemptId,
      approvalId: req.approvalId,
      decision: "approved",
      approver: req.approver,
    });
    if (!appr.ok) {
      if (appr.error.code === "audit.write_failed") {
        latch(`the approval of attempt ${attemptId} could not be recorded`);
      }
      // Not chained ⇒ never executed. The attempt may already be closed, so no outcome is forced on it.
      return approvedNotExecuted(
        attemptId,
        appr.error.code === "audit.write_failed"
          ? FIREWALL_RULES.auditUnavailable
          : appr.error.code,
        "the approval could not be recorded in the audit log; the action was not executed",
        false,
      );
    }
    if (degraded) {
      return approvedNotExecuted(attemptId, FIREWALL_RULES.auditUnavailable, degradedMessage);
    }
    if (reconciling) {
      return approvedNotExecuted(attemptId, FIREWALL_RULES.reconciling, RECONCILING_MESSAGE);
    }
    const mismatch = (): ExecuteApprovedResult =>
      approvedNotExecuted(
        attemptId,
        APPROVAL_RULES.argsMismatch,
        "the approved action no longer matches what was recorded; it was not executed",
      );

    // 2. Binding checks against the audit log.
    const act = o.store.readAttempt(attemptId);
    if (!act.ok) {
      return approvedNotExecuted(
        attemptId,
        FIREWALL_RULES.auditUnavailable,
        "the audit log could not be read; the action was not executed",
      );
    }
    const a = act.value;
    if (
      a === undefined ||
      a.attempt.tool !== req.tool ||
      a.attempt.decision !== "require_approval" ||
      a.attempt.retryOf !== undefined ||
      a.attempt.sessionId !== req.sessionId ||
      a.outcome !== undefined ||
      a.approval?.decision !== "approved"
    ) {
      return mismatch();
    }
    if (classifyTool(req.tool) !== "money") return mismatch();
    const hash = approvalArgsHash(req.tool, req.finalArgs);
    if (!hash.ok || hash.value !== req.argsHash) return mismatch();
    const stamped = stampAttemptMarker(req.tool, req.finalArgs, attemptId);
    if (!stamped.ok || !sameJson(argsForDisplay(stamped.value as Args), a.attempt.argsRedacted))
      return mismatch();
    const key = idempotencyKey(req.tool, req.finalArgs);
    if (!key.ok) return mismatch();
    if (a.attempt.idempotencyKey !== undefined && a.attempt.idempotencyKey !== key.value) {
      return mismatch();
    }
    const recordedKey = a.attempt.idempotencyKey ?? key.value;
    /** `undefined` iff the attempt still has no outcome; else the not-executed result (nothing more written). */
    const stillOpen = (): ExecuteApprovedResult | undefined => {
      const now = o.store.readAttempt(attemptId);
      if (now.ok && now.value !== undefined && now.value.outcome === undefined) return undefined;
      return approvedNotExecuted(
        attemptId,
        now.ok ? APPROVAL_RULES.attemptClosed : FIREWALL_RULES.auditUnavailable,
        "the approved action's audit attempt was closed meanwhile; it was not executed",
        false,
      );
    };

    // 3. Same locks as a live call: sorted resource locks, then the global lock.
    const signal = new AbortController().signal;
    const releases: Release[] = [];
    let call: DirectCall | undefined;
    try {
      for (const k of resourceLockKeys(targetsOf(req.finalArgs))) {
        const got = await resourceLocks.acquire(k, { timeoutMs: lockWaitMs });
        if (!got.ok) {
          return approvedNotExecuted(
            attemptId,
            FIREWALL_RULES.busy,
            "another money action is in progress; the approved action was not executed",
          );
        }
        releases.push(got.value);
      }
      const inr = await inrProblem(targetsOf(req.finalArgs));
      if (inr !== undefined) return approvedNotExecuted(attemptId, inr.ruleId, inr.message);
      const opened = await openCall(req.tool, signal);
      if (!opened.ok) {
        return approvedNotExecuted(
          attemptId,
          "upstream.unavailable",
          "the upstream Razorpay MCP server is unavailable; the approved action was not executed",
        );
      }
      call = opened.value;
      const ctx: CallContext = {
        tool: req.tool,
        toolClass: "money",
        args: req.finalArgs,
        inputSchema: call.inputSchema,
        untrustedReason: req.untrustedReason,
        sessionId: req.sessionId,
        signal,
      };
      const info: CallInfo = { tool: req.tool, audited: new WeakSet<CallToolResult>() };
      // Same T012 pre-check (kill switch / shadow mode) as a live call; a deny or a throw ⇒ not executed.
      // A shadow verdict is ignored: an approved action is a real, non-shadow action (D-035).
      if (o.preCheck !== undefined) {
        let pre: PreCheckVerdict | undefined;
        try {
          pre = await o.preCheck(ctx);
        } catch (e: unknown) {
          log(`preCheck threw ${e instanceof Error ? e.name : typeof e} for an approved action`);
          return approvedNotExecuted(
            attemptId,
            FIREWALL_RULES.internalError,
            "the firewall pre-check failed; the approved action was not executed",
          );
        }
        if (pre !== undefined && isPreCheckDeny(pre)) {
          return approvedNotExecuted(attemptId, pre.ruleId, pre.message);
        }
      }

      const got = await globalLock.acquire({ timeoutMs: lockWaitMs });
      if (!got.ok) {
        return approvedNotExecuted(
          attemptId,
          FIREWALL_RULES.busy,
          "another money action is in progress; the approved action was not executed",
        );
      }
      let res: EvalResult;
      try {
        if (degraded) {
          return approvedNotExecuted(attemptId, FIREWALL_RULES.auditUnavailable, degradedMessage);
        }
        const read = memoisedReader(o.store);
        const scope = duplicateScope(read);
        if ("failed" in scope) {
          return approvedNotExecuted(
            attemptId,
            FIREWALL_RULES.duplicateCheckFailed,
            "the firewall could not check for a duplicate of this action; it was not executed",
          );
        }
        const dup = findDuplicate(scope.rows, req.tool, new Set([recordedKey]), {
          nowMs: scope.nowMs,
          windowMs: duplicateWindowMs,
          openLookbackMs: DEFAULT_OPEN_LOOKBACK_MS,
          excludeAttemptIds: new Set([attemptId]),
        });
        if (!dup.ok) {
          return approvedNotExecuted(
            attemptId,
            FIREWALL_RULES.duplicateCheckFailed,
            "the firewall could not check for a duplicate of this action; it was not executed",
          );
        }
        if (dup.value !== undefined) {
          return approvedNotExecuted(
            attemptId,
            FIREWALL_RULES.duplicate,
            DUPLICATE_MESSAGES[dup.value.status],
          );
        }
        const deps = createPolicyDeps({
          ...adapterBase,
          timer: o.timer,
          read,
          excludeAttemptIds: new Set([attemptId]),
        });
        try {
          res = await evaluate(
            o.policy,
            {
              tool: req.tool,
              args: req.finalArgs,
              reason: req.untrustedReason,
              sessionId: req.sessionId,
            },
            deps,
          );
        } catch (e: unknown) {
          log(`re-evaluation threw ${e instanceof Error ? e.name : typeof e}`);
          return approvedNotExecuted(
            attemptId,
            APPROVAL_RULES.reevaluationFailed,
            "the policy could not re-check the approved action; it was not executed",
          );
        }
        const d = res.decision;
        if (d.type === "deny") {
          return approvedNotExecuted(
            attemptId,
            APPROVAL_RULES.policyDenied,
            `the policy now denies this action (${d.ruleId}); it was not executed`,
          );
        }
        if (d.type === "require_approval" && d.ruleId !== req.ruleId) {
          return approvedNotExecuted(
            attemptId,
            APPROVAL_RULES.policyChanged,
            "the policy now requires a different approval for this action; it was not executed",
          );
        }
        const bad = checkFinalArgs({ ...ctx, tool: req.tool }, res.finalArgs);
        if (bad !== undefined) return approvedNotExecuted(attemptId, bad.ruleId, bad.message);
        const reHash = approvalArgsHash(req.tool, res.finalArgs);
        if (!reHash.ok || reHash.value !== req.argsHash) return mismatch();
        const closed = stillOpen();
        if (closed !== undefined) return closed;
      } finally {
        got.value();
      }

      // 4. Forward the stamped args; the outcome goes on the ORIGINAL attempt; T010 handles unclear outcomes.
      if (degraded) {
        return approvedNotExecuted(attemptId, FIREWALL_RULES.auditUnavailable, degradedMessage);
      }
      // Re-read synchronously right before the send: if anything closed the attempt meanwhile (e.g. the approval
      // request was reported failed), it must not be sent.
      const closedNow = stillOpen();
      if (closedNow !== undefined) return closedNow;
      // T012: the kill switch may have been turned on while this approved action waited for its locks.
      const gate = await sendGate(ctx);
      if (gate !== undefined) return approvedNotExecuted(attemptId, gateCode(gate), gate.message);
      let r: CallToolResult | undefined;
      try {
        r = await call.forward(stamped.value);
      } catch (e: unknown) {
        log(
          `forwarding approved ${escapeForTerminal(req.tool)} threw ${e instanceof Error ? e.name : typeof e}`,
        );
        r = undefined;
      }
      let settledStatus: SettleStatus | undefined;
      const settled = await settleForward(
        ctx,
        info,
        {
          id: attemptId,
          record: a.attempt,
          args: stamped.value,
        },
        r,
        {
          decision: "require_approval",
          approver: req.approver,
          matchedRules: [...a.attempt.matchedRules],
          recordedKey,
          finalArgs: req.finalArgs,
          transformed: false,
          reason: req.untrustedReason,
        },
        (st) => {
          settledStatus = st;
        },
      );
      // The firewall's own settle result decides the status, never parsed upstream text.
      const st: SettleStatus = settledStatus ?? {
        status: "unknown",
        code: "firewall.internal_error",
      };
      return {
        status: st.status,
        attemptId,
        ...(isSafeUpstreamRef(st.upstreamRef) ? { upstreamRef: st.upstreamRef } : {}),
        ...(st.code === undefined ? {} : { code: st.code }),
        result: settled,
      };
    } catch (e: unknown) {
      // Defensive: every step above returns typed results. Unknown (the attempt stays open and keeps counting).
      log(
        `executing approved attempt ${attemptId} failed: ${e instanceof Error ? e.name : typeof e}`,
      );
      return {
        status: "unknown",
        attemptId,
        code: FIREWALL_RULES.internalError,
        result: unknownOutcomeResult(attemptId),
      };
    } finally {
      call?.settle();
      for (const release of releases.reverse()) release();
    }
  };

  const resolveApproval = (req: ResolveApprovalRequest): Result<null> => {
    const appr = o.store.recordApproval({
      attemptId: req.attemptId,
      approvalId: req.approvalId,
      decision: req.decision,
      ...(req.approver === undefined ? {} : { approver: req.approver }),
    });
    if (!appr.ok) {
      log(`approval ${req.decision} of attempt ${req.attemptId} not recorded: ${appr.error.code}`);
      if (appr.error.code === "audit.write_failed") {
        latch(`the ${req.decision} approval of attempt ${req.attemptId} could not be recorded`);
      }
      return err(appr.error.code, appr.error.message);
    }
    if (
      !recordOutcome(req.attemptId, {
        outcome: "not_forwarded",
        errorCode: req.decision === "rejected" ? APPROVAL_RULES.rejected : APPROVAL_RULES.expired,
        latencyMs: 0,
      })
    ) {
      latch(`the ${req.decision} outcome of attempt ${req.attemptId} could not be recorded`);
      return err("audit.write_failed", "the approval outcome could not be recorded");
    }
    return ok(null);
  };

  const reconcile = async (): Promise<Result<ReconcileSummary>> => {
    if (reconcileStarted) return err("firewall.reconcile_twice", "reconciliation already ran");
    reconcileStarted = true;
    try {
      if (degraded) {
        log("startup reconciliation skipped: the audit log is degraded");
        return err("audit_unavailable", "the audit log is degraded");
      }
      const r = await reconcileAtStartup({
        store: o.store,
        verifier,
        logger: log,
        ...(o.approvalIdOf === undefined ? {} : { approvalIdOf: o.approvalIdOf }),
      });
      if (!r.ok) {
        latch(`startup reconciliation failed (${r.error.code})`);
        return r;
      }
      for (const a of r.value.unresolved) unresolved.set(a.attempt.id, a);
      log(
        `startup reconciliation: ${String(r.value.orphaned)} orphaned, ${String(r.value.happened)} happened, ${String(r.value.notHappened)} not happened, ${String(r.value.unresolved.length)} need a human (${String(r.value.lookups)} lookups)`,
      );
      return r;
    } catch (e: unknown) {
      latch(`startup reconciliation threw ${e instanceof Error ? e.name : typeof e}`);
      return err("firewall.reconcile_failed", "startup reconciliation failed");
    } finally {
      reconciling = false;
    }
  };

  const envelope = (inner: CallInterceptor): CallInterceptor => ({
    intercept: async (ctx, forward) => {
      const info: CallInfo = { tool: ctx.tool, audited: new WeakSet<CallToolResult>() };
      const token = Object.freeze({});
      calls.set(token, info);
      const tokened: TokenedContext = { ...ctx, [CALL_TOKEN]: token };
      let r: CallToolResult;
      try {
        r = await inner.intercept(tokened, forward);
      } finally {
        calls.delete(token);
      }
      if (classifyTool(info.tool) !== "money" && ctx.toolClass !== "money") return r;
      if (info.audited.has(r)) return r;
      const ruleId = denyRuleOf(r);
      if (ruleId === undefined) {
        log(
          `money call ${escapeForTerminal(info.tool)} returned a result the policy stage did not handle; check wiring`,
        );
        return r;
      }
      // A deny produced before / around the policy stage (e.g. moneyArgsStage): leave an audit trail.
      const rest = withoutReason(ctx.args);
      const args = isBounded(rest) ? rest : { _omitted: "arguments too large to audit" };
      recordDenied(info, { sessionId: ctx.sessionId, args, reason: "" }, ruleId);
      return r;
    },
  });

  return {
    stage,
    envelope,
    executeApproved,
    resolveApproval,
    isDegraded: () => degraded,
    reconcile,
    isReconciling: () => reconciling,
    unresolvedAttemptIds: () => [...unresolved.keys()],
    close: () => {
      tracker.close();
    },
  };
}

/** The firewall interceptor: envelope ∘ chain(moneyArgsStage, money stage). */
export function createFirewallInterceptor(
  p: MoneyPipeline,
  opts: { readonly logger?: Logger } = {},
): CallInterceptor {
  return p.envelope(composeInterceptors(firewallChain(p.stage), opts));
}
