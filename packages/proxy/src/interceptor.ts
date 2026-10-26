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
 *     forwarding, since the latch can be set while a call waits); optional `preCheck` (T012 kill switch seam).
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
 *  3. Global money lock (bounded wait `lockWaitMs` ⇒ deny `firewall.busy`) around `evaluate` + `recordAttempt`, since
 *     velocity spans payments. Deps are built fresh per evaluation. For a non-deny decision the args to forward are
 *     re-checked (`checkFinalArgs`), since a `transform` may have rewritten them: any top-level `*_id` key added,
 *     removed or changed ⇒ `firewall.transform_retarget`; unsafe keys / a `reason` key ⇒ `firewall.invalid_args`;
 *     a non-INR currency at any depth ⇒ `firewall.currency_not_inr`; an invalid amount at any depth ⇒
 *     `firewall.invalid_amount` (all audited as deny). Attempts record the FORWARDED (post-transform) args, plus
 *     `originalArgs` when a transform changed them (D-026). Deny attempts record the agent's args (nothing is
 *     forwarded).
 *  4. `recordAttempt` error ⇒ never forward: `audit.invalid_args` ⇒ outcome `denied` on its trail row + deny
 *     `audit.invalid_args`; anything else ⇒ deny `audit_unavailable`.
 *  5. deny ⇒ outcome `denied` ⇒ `{ decision: "deny", ruleId, message }` (`isError: true`). Never echoes the reason.
 *  6. require_approval ⇒ `ApprovalPort.create` bound to `sha256(canonicalJson({tool, args: finalArgs}))`; the
 *     attempt stays OPEN (counts toward limits) ⇒ `{ decision: "pending_approval", approvalId, message }`
 *     (`isError: false`). Create failure ⇒ outcome `not_forwarded` + deny `firewall.approval_unavailable`.
 *  7. allow / transform ⇒ forward exactly `finalArgs` and map the server's `ForwardReport` to an outcome (see
 *     `outcomeFor`). An outcome write failure latches the pipeline DEGRADED: every later money call is denied
 *     `audit_unavailable` until restart (the audit trail can no longer be trusted to be complete).
 *  8. Envelope: any `{decision:"deny"}` result for a money call that the stage did not produce (e.g. a
 *     `moneyArgsStage` deny) is audited as attempt `deny` (args minus `reason`, reason "", matchedRules [ruleId]) +
 *     outcome `denied`.
 */
import {
  canonicalJson,
  err,
  evaluate,
  type Clock,
  type CompiledPolicy,
  type Decision,
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
import { upstreamRefSchema, type AuditStore, type AuditOutcomeInput } from "./audit-store.js";
import {
  createOrderLookup,
  createPolicyDeps,
  createRazorpayLookup,
  type UpstreamPaymentPort,
} from "./context-adapters.js";
import { composeInterceptors, firewallChain, type Next, type Stage } from "./interceptor-chain.js";
import { createKeyedMutex, createMutex, type Release } from "./locks.js";
import {
  allCurrenciesInr,
  findInvalidAmount,
  hasSafeTopLevelKeys,
  isBounded,
} from "./money-args.js";
import { PENDING_APPROVAL_MESSAGE } from "./result-redaction.js";
import { rewriteMoneySchema } from "./schema-rewrite.js";
import {
  denyResult,
  forwardReportOf,
  jsonErrorResult,
  type CallContext,
  type CallInterceptor,
  type ForwardReport,
} from "./server.js";
import { classifyTool } from "./tool-classes.js";
import { noRedact, type Logger, type Redactor } from "./upstream.js";

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
  notImplemented: "firewall.not_implemented",
} as const;

/** Store surface the pipeline needs. */
export type PipelineStore = Pick<
  AuditStore,
  "recordAttempt" | "recordOutcome" | "readActivitySince"
>;

export interface PreCheckDeny {
  readonly ruleId: string;
  readonly message: string;
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
   * T012 seam (kill switch / shadow mode): runs after the guards and before any lock. Returning a deny audits and
   * returns it; throwing ⇒ deny `firewall.internal_error`.
   */
  readonly preCheck?: (
    ctx: CallContext,
  ) => PreCheckDeny | undefined | Promise<PreCheckDeny | undefined>;
  /**
   * Start with the degraded latch already SET (e.g. the audit chain failed `verify()` at startup): every money call is
   * denied `audit_unavailable` with `message` (agent-facing) and the deny is audited best-effort. `reason` is logged
   * once at creation for the operator. Read tools are unaffected.
   */
  readonly startDegraded?: { readonly reason: string; readonly message: string };
}

export interface ExecuteApprovedRequest {
  readonly approvalId: string;
  readonly attemptId: string;
  readonly argsHash: string;
}

export interface MoneyPipeline {
  readonly stage: Stage;
  /** Wrap the composed chain: binds the server's exact tool name and audits denies the stage didn't produce. */
  envelope(inner: CallInterceptor): CallInterceptor;
  /**
   * T011 seam — NOT IMPLEMENTED: always denies `firewall.not_implemented`.
   *
   * Intended behaviour: take the same locks as a live call (sorted resource keys (`order:` / `payment:`) → global),
   * re-evaluate the approved attempt's `finalArgs` with `excludeAttemptIds: {attemptId}` (so the pending attempt
   * doesn't count against itself), require the re-evaluated args to hash to `argsHash` (else deny), require a non-deny decision, then forward and record the
   * outcome on the ORIGINAL attempt id (D-023).
   */
  executeApproved(req: ExecuteApprovedRequest): Promise<CallToolResult>;
  /** True once an outcome write failed; all later money calls are denied. */
  isDegraded(): boolean;
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
        return { outcome: "upstream_error", errorCode: "upstream.tool_error", latencyMs };
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
  ctx: Pick<CallContext, "args" | "inputSchema">,
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

function withRuleId(d: Decision): string[] {
  // The deciding rule is always listed (e.g. `policy-default`, `engine-timeout` match no predicate).
  return d.matchedRules.includes(d.ruleId) ? [...d.matchedRules] : [...d.matchedRules, d.ruleId];
}

export function createMoneyPipeline(o: MoneyPipelineOptions): MoneyPipeline {
  const log: Logger = o.logger ?? (() => undefined);
  const redact = o.redact ?? noRedact;
  const lockWaitMs = o.lockWaitMs ?? DEFAULT_LOCK_WAIT_MS;
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

  const latch = (why: string): void => {
    if (!degraded) {
      log(
        `AUDIT DEGRADED: ${why}. All further money calls are denied (audit_unavailable) until the proxy restarts.`,
      );
    }
    degraded = true;
  };

  /** Record an outcome. `false` (and a log line) on failure. */
  const recordOutcome = (attemptId: string, spec: OutcomeSpec): boolean => {
    const r = o.store.recordOutcome({
      attemptId,
      outcome: spec.outcome,
      latencyMs: spec.latencyMs,
      ...(spec.errorCode === undefined ? {} : { errorCode: spec.errorCode }),
      ...(spec.upstreamRef === undefined ? {} : { upstreamRef: spec.upstreamRef }),
    });
    if (!r.ok) {
      log(`audit outcome write failed for attempt ${attemptId}: ${r.error.code}`);
      return false;
    }
    return true;
  };

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
    if (degraded) {
      return auditedDeny(info, base, FIREWALL_RULES.auditUnavailable, degradedMessage);
    }
    if (o.preCheck !== undefined) {
      let pre: PreCheckDeny | undefined;
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
      if (pre !== undefined) return auditedDeny(info, base, pre.ruleId, pre.message);
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
      return await underResourceLocks(ctx, next, info, base, targets);
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

  const underResourceLocks = async (
    ctx: CallContext,
    next: Next,
    info: CallInfo,
    base: DenyRecord,
    targets: ResourceTargets,
  ): Promise<CallToolResult> => {
    const reason = base.reason;

    // 2. INR invariant for calls acting on an existing payment and/or order.
    if (targets.payment !== undefined) {
      const payment = await createRazorpayLookup(adapterBase).payment(targets.payment);
      if (!payment.ok) {
        return auditedDeny(
          info,
          base,
          FIREWALL_RULES.paymentLookupFailed,
          "the payment could not be looked up to verify it; the call was not sent",
        );
      }
      if (payment.value.currency !== "INR") {
        return auditedDeny(
          info,
          base,
          FIREWALL_RULES.currencyNotInr,
          "only INR payments are supported through the firewall; the call was not sent",
        );
      }
    }
    if (targets.order !== undefined) {
      const order = await createOrderLookup(adapterBase).order(targets.order);
      if (!order.ok) {
        return auditedDeny(
          info,
          base,
          FIREWALL_RULES.orderLookupFailed,
          "the order could not be looked up to verify it; the call was not sent",
        );
      }
      if (order.value.currency !== "INR") {
        return auditedDeny(
          info,
          base,
          FIREWALL_RULES.currencyNotInr,
          "only INR orders are supported through the firewall; the call was not sent",
        );
      }
    }
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
    let attempt: Result<{ id: string }>;
    try {
      const deps = createPolicyDeps({ ...adapterBase, timer: o.timer });
      res = await evaluate(
        o.policy,
        { tool: info.tool, args: ctx.args, reason, sessionId: ctx.sessionId },
        deps,
      );
      if (res.decision.type !== "deny") {
        const bad = checkFinalArgs(ctx, res.finalArgs);
        if (bad !== undefined) {
          return auditedDeny(
            info,
            { ...base, matchedRules: [...res.decision.matchedRules, bad.ruleId] },
            bad.ruleId,
            bad.message,
          );
        }
      }
      const d = res.decision;
      const transformed = d.type !== "deny" && !sameJson(res.finalArgs, ctx.args);
      attempt = o.store.recordAttempt({
        sessionId: ctx.sessionId,
        tool: info.tool,
        args: d.type === "deny" ? ctx.args : res.finalArgs,
        ...(transformed ? { originalArgs: ctx.args } : {}),
        reason,
        decision: d.type,
        matchedRules: withRuleId(d),
      });
    } finally {
      got.value();
    }

    // 4. Attempt not recorded ⇒ never forward.
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
    const d = res.decision;

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
    // T009 seam: `beforeForward(finalArgs, attemptId)` attaches the idempotency key here (before the send).
    let r: CallToolResult;
    try {
      r = await next({ ...ctx, args: res.finalArgs });
    } catch (e: unknown) {
      log(
        `forwarding ${escapeForTerminal(info.tool)} threw ${e instanceof Error ? e.name : typeof e}`,
      );
      if (
        !recordOutcome(attemptId, {
          outcome: "upstream_error",
          errorCode: FIREWALL_RULES.forwardThrew,
          latencyMs: 0,
        })
      ) {
        latch("an outcome could not be recorded after a failed forward");
      }
      return mark(
        info,
        jsonErrorResult({
          error: "upstream_error",
          message:
            "the firewall failed while sending this call; it may have reached Razorpay — check its status before retrying",
          forwarded: true,
        }),
      );
    }
    const spec = outcomeFor(r, forwardReportOf(r));
    if (!recordOutcome(attemptId, spec)) {
      latch(`the outcome of attempt ${attemptId} (${spec.outcome}) could not be recorded`);
    }
    return mark(info, r);
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
    executeApproved: () =>
      Promise.resolve(
        denyResult(
          FIREWALL_RULES.notImplemented,
          "executing approved actions is not implemented yet (T011)",
        ),
      ),
    isDegraded: () => degraded,
  };
}

/** The firewall interceptor: envelope ∘ chain(moneyArgsStage, money stage). */
export function createFirewallInterceptor(
  p: MoneyPipeline,
  opts: { readonly logger?: Logger } = {},
): CallInterceptor {
  return p.envelope(composeInterceptors(firewallChain(p.stage), opts));
}
