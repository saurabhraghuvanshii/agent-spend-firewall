/**
 * Verify before retry (T010): what the firewall does when a money call was SENT but its outcome is unclear (upstream
 * timeout, connection lost, tool error, credential-leak replacement, a crash before the outcome was written).
 *
 * Rule: nothing is ever retried, and nothing is reported as "not executed", on a guess. Razorpay is asked first.
 *
 * - MARKER: every forwarded `create_refund` carries `notes.asf_attempt = <attempt id>` (`stampAttemptMarker`). The
 *   agent / a policy transform may not supply any `asf_*` notes key (any case) nor more than `MAX_AGENT_NOTES` notes
 *   (`notesProblem` ⇒ deny `firewall.invalid_args`), so a marker can only come from the firewall.
 * - VERIFIER (`createActionVerifier`):
 *   - `create_refund`: `fetch_multiple_refunds_for_payment {payment_id, count:100, skip}` pages; the list is COMPLETE
 *     only when a page returns fewer than 100 items, at most `MAX_REFUND_PAGES` pages (else unknown). Every page and
 *     every refund is zod-validated (one bad item ⇒ unknown). Marker found + same amount + same payment ⇒ `happened`
 *     (ref `rfnd_…`) if its `status` is `processed` / `pending`; `failed` ⇒ unknown (`verify.refund_failed`, a human
 *     must look); any other / missing status ⇒ unknown. Marker found with a different amount / payment ⇒ unknown.
 *     A page of exactly `REFUND_LIST_SHORT_PAGE` items (the server may be ignoring `count`) is treated as incomplete.
 *     Complete list without the marker ⇒ `absent`, which is `not_happened` ONLY when upstream answered THIS request
 *     with a DEFINITE Razorpay rejection (`upstream-failure.ts`: e.g. `BAD_REQUEST_ERROR`, no timeout / server /
 *     cancel wording). Any other failure answer (JSON-RPC error, "context canceled", gateway error, unrecognised
 *     text) is ambiguous — Razorpay may still be processing — so the result is unknown + flagged, never retried.
 *   - `capture_payment`: `fetch_payment` status `captured` ⇒ happened; `authorized` + a definite rejection ⇒
 *     not_happened; anything else ⇒ unknown.
 *   - every other money tool ⇒ unknown (method `none`), except that a late SUCCESS answer ⇒ happened.
 *   Lookups ignore the agent's cancel signal, are credential-screened, and never throw.
 * - LATE RESPONSES (`createLateResponseTracker`): payload-free `LateResponse` events keyed by (generation, request id);
 *   a waiter gets the event, or it is buffered (bounded) and offered to `onUnclaimed` listeners.
 * - `handleUnsettled`: verify; if the caller may retry (it passes `waitLate`) and the list was complete without the
 *   marker, wait up to `verifyWaitMs` for the late answer and verify again; then write ONE verification record
 *   (`needsHuman` iff unknown). The caller (interceptor) decides about the single retry.
 * - `reconcileAtStartup`: open allow/transform attempts get outcome `upstream_error` / `firewall.orphaned`; then
 *   every `timeout` / `upstream_error` outcome without a final verification is verified (trigger `startup`, never
 *   retried), within a lookup budget; upstream down (unavailable, or `STARTUP_MAX_CONSECUTIVE_TIMEOUTS` lookup
 *   timeouts in a row) / over budget ⇒ unknown + flag (keeps blocking duplicates). Only an outcome recorded as
 *   `upstream.rejected` (a tool error classified as a definite rejection when it happened) counts as a rejection.
 *
 * Logs never include args, notes, reasons or upstream payloads.
 */
import {
  err,
  ok,
  type AuditVerificationMethod,
  type AuditVerificationResult,
  type AuditVerificationTrigger,
  type Result,
  type Timer,
} from "@asf/core";
import type { RequestId } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type {
  AuditActivity,
  AuditStore,
  AuditVerificationRecord,
  RecordVerificationInput,
} from "./audit-store.js";
import { escapeForTerminal } from "./cli/audit-verify.js";
import {
  FETCH_PAYMENT_TOOL,
  PAYMENT_ID_PATTERN,
  parseSingleJson,
  type UpstreamPaymentPort,
} from "./context-adapters.js";
import { CREDENTIAL_LEAK_RESULT, screenResult } from "./server.js";
import { classifyTool } from "./tool-classes.js";
import { noRedact, type LateResponse, type Logger, type Redactor } from "./upstream.js";
import { containsRejectionCode, mergeFailure, type UpstreamFailure } from "./upstream-failure.js";

/** Default wait for the late answer of a timed-out call before deciding (`ASF_VERIFY_WAIT_MS`). */
export const DEFAULT_VERIFY_WAIT_MS = 15_000;
export const MIN_VERIFY_WAIT_MS = 1_000;
export const MAX_VERIFY_WAIT_MS = 120_000;
/** Timeout of one verification lookup (not bound by the policy engine's 2 s budget). */
export const DEFAULT_VERIFY_LOOKUP_TIMEOUT_MS = 5_000;
export const REFUND_LIST_TOOL = "fetch_multiple_refunds_for_payment";
export const REFUND_PAGE_SIZE = 100;
export const MAX_REFUND_PAGES = 5;
/** Notes key carrying the firewall's attempt id on forwarded refunds. */
export const ATTEMPT_MARKER_KEY = "asf_attempt";
/** Razorpay allows 15 notes; the firewall needs one. */
export const MAX_AGENT_NOTES = 14;
/** Max upstream lookups during startup reconciliation. */
export const STARTUP_LOOKUP_BUDGET = 50;
/** Consecutive `verify.timeout` lookups after which startup treats upstream as down (~3 × lookup timeout). */
export const STARTUP_MAX_CONSECUTIVE_TIMEOUTS = 3;
/**
 * A refund page of exactly this many items when `REFUND_PAGE_SIZE` was asked for suggests the server ignored `count`
 * (Razorpay's default page size): the list can't be proven complete.
 */
export const REFUND_LIST_SHORT_PAGE = 10;
/** Outcome error code of a tool error that was a definite Razorpay rejection (vs `upstream.tool_error`). */
export const REJECTED_ERROR_CODE = "upstream.rejected";
/** Refund statuses meaning the refund exists and was not failed. */
const LIVE_REFUND_STATUSES: ReadonlySet<string> = new Set(["processed", "pending"]);
/** Tools whose forwarded args get the notes marker. */
export const MARKED_TOOLS: ReadonlySet<string> = new Set(["create_refund"]);
/** Tools the verifier can look up (others are always unknown). */
export const VERIFIABLE_TOOLS: ReadonlySet<string> = new Set(["create_refund", "capture_payment"]);
/** Tools that may be retried once after a verified not-happened (T010: refunds only). */
export const RETRYABLE_TOOLS: ReadonlySet<string> = new Set(["create_refund"]);

const RESERVED_NOTES_PREFIX = /^asf_/i;
const REFUND_ID = /^rfnd_[A-Za-z0-9]{1,40}$/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// ---------------------------------------------------------------------------------------------------------------
// Notes marker
// ---------------------------------------------------------------------------------------------------------------

/**
 * Problem with money-call args supplied by the agent or a policy transform, or `undefined`: any string (key or value,
 * any depth) containing an allowlisted rejection code (`containsRejectionCode`, case-insensitive) is refused; in the
 * top-level `notes`, any key starting with `asf_` (any case) is reserved for the firewall; more than `MAX_AGENT_NOTES` keys leave no
 * room for the marker; on a marked tool `notes` must be a plain object. Never echoes keys or values.
 */
export function notesProblem(
  tool: string,
  args: Readonly<Record<string, unknown>>,
): string | undefined {
  // An agent-chosen string echoed in an upstream error must never pass for a Razorpay rejection code.
  if (containsRejectionCode(args)) {
    return "argument values may not contain a Razorpay error code";
  }
  if (!Object.hasOwn(args, "notes")) return undefined;
  const notes = args["notes"];
  if (!isPlainObject(notes)) {
    return MARKED_TOOLS.has(tool) ? "notes must be an object of key-value pairs" : undefined;
  }
  const keys = Object.keys(notes);
  if (keys.some((k) => RESERVED_NOTES_PREFIX.test(k))) {
    return 'notes keys starting with "asf_" are reserved for the firewall';
  }
  if (keys.length > MAX_AGENT_NOTES) {
    return `at most ${String(MAX_AGENT_NOTES)} notes are allowed (the firewall adds one)`;
  }
  return undefined;
}

/**
 * Args to forward: for a marked tool a fresh copy with `notes.asf_attempt = attemptId` (existing notes kept); other
 * tools unchanged. `err` if `notes` is present and not a plain object (callers check `notesProblem` first).
 */
export function stampAttemptMarker(
  tool: string,
  args: Readonly<Record<string, unknown>>,
  attemptId: string,
): Result<Record<string, unknown>> {
  if (!MARKED_TOOLS.has(tool)) return ok({ ...args });
  const notes: unknown = Object.hasOwn(args, "notes") ? args["notes"] : {};
  if (!isPlainObject(notes)) return err("firewall.invalid_args", "notes must be an object");
  return ok({ ...args, notes: { ...notes, [ATTEMPT_MARKER_KEY]: attemptId } });
}

// ---------------------------------------------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------------------------------------------

export interface VerifyRequest {
  /** Attempt id = the marker value. */
  readonly attemptId: string;
  readonly tool: string;
  /** The args as forwarded (stamped) — or as stored (`argsRedacted`) at startup. */
  readonly args: unknown;
  /** What upstream's failure answer for this request proves (`none`: no failure answer known). */
  readonly failure: UpstreamFailure;
  /** Max upstream calls this verification may make (startup budget). Default unlimited (≤ `MAX_REFUND_PAGES`). */
  readonly maxLookups?: number;
}

export interface Finding {
  readonly result: AuditVerificationResult;
  readonly method: AuditVerificationMethod;
  readonly upstreamRef?: string;
  readonly errorCode?: string;
  /** Refund status of a `happened` refund (`processed` / `pending`). */
  readonly refundStatus?: string;
  /** The lookup was complete and found no trace of the action (basis for not_happened once a failure is known). */
  readonly absent: boolean;
  /** Upstream calls made. */
  readonly lookups: number;
}

export interface ActionVerifier {
  verify(req: VerifyRequest): Promise<Finding>;
}

export interface VerifierOptions {
  readonly upstream: UpstreamPaymentPort;
  readonly redact?: Redactor;
  /** Per-lookup timeout, integer ms (default `DEFAULT_VERIFY_LOOKUP_TIMEOUT_MS`). */
  readonly lookupTimeoutMs?: number;
}

const refundPageSchema = z.looseObject({ items: z.array(z.unknown()) });
const refundSchema = z.looseObject({
  id: z.string().regex(REFUND_ID),
  amount: z.int().nonnegative(),
  payment_id: z.string().optional(),
  status: z.string().max(40).optional(),
  // Razorpay returns `[]` for empty notes.
  notes: z.union([z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional(),
});
const paymentStatusSchema = z.looseObject({ id: z.string(), status: z.string() });

function unknown(method: AuditVerificationMethod, errorCode: string, lookups: number): Finding {
  return { result: "unknown", method, errorCode, absent: false, lookups };
}

/**
 * A complete lookup found no trace of the action: `not_happened` ONLY with a definite rejection; an ambiguous failure
 * (Razorpay may still be processing) or no answer at all ⇒ unknown.
 */
function absentFinding(
  method: AuditVerificationMethod,
  failure: UpstreamFailure,
  lookups: number,
): Finding {
  if (failure === "definite_rejection")
    return { result: "not_happened", method, absent: true, lookups };
  const errorCode = failure === "ambiguous" ? "verify.ambiguous_failure" : "verify.not_found";
  return { result: "unknown", method, errorCode, absent: true, lookups };
}

/** Verification method used for `tool`. */
export function methodFor(tool: string): AuditVerificationMethod {
  if (tool === "create_refund") return "refund_notes_marker";
  if (tool === "capture_payment") return "payment_status";
  return "none";
}

type LookupJson = { ok: true; json: unknown } | { ok: false; errorCode: string };

export function createActionVerifier(o: VerifierOptions): ActionVerifier {
  const redact = o.redact ?? noRedact;
  const timeoutMs = o.lookupTimeoutMs ?? DEFAULT_VERIFY_LOOKUP_TIMEOUT_MS;

  const lookup = async (tool: string, args: Record<string, unknown>): Promise<LookupJson> => {
    // Defense in depth: verification only ever goes through read tools.
    if (classifyTool(tool) !== "read") return { ok: false, errorCode: "verify.invalid_config" };
    const outcome = await o.upstream.callTool(tool, args, { timeoutMs });
    if (outcome.kind !== "ok") {
      return {
        ok: false,
        errorCode: outcome.error === "upstream_timeout" ? "verify.timeout" : "verify.unavailable",
      };
    }
    const screened = screenResult(outcome.result, redact);
    if (screened === CREDENTIAL_LEAK_RESULT)
      return { ok: false, errorCode: "verify.credential_leak" };
    const json = parseSingleJson(screened, "verification");
    return json.ok ? { ok: true, json: json.value } : { ok: false, errorCode: "verify.malformed" };
  };

  const verifyRefund = async (req: VerifyRequest): Promise<Finding> => {
    const method: AuditVerificationMethod = "refund_notes_marker";
    const a = req.args;
    if (!isPlainObject(a)) return unknown(method, "verify.bad_args", 0);
    const paymentId = a["payment_id"];
    const amount = a["amount"];
    const notes = a["notes"];
    if (typeof paymentId !== "string" || !PAYMENT_ID_PATTERN.test(paymentId)) {
      return unknown(method, "verify.bad_args", 0);
    }
    if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount < 1) {
      return unknown(method, "verify.bad_args", 0);
    }
    // Without our own marker in what was sent there is nothing to look for.
    if (!isPlainObject(notes) || notes[ATTEMPT_MARKER_KEY] !== req.attemptId) {
      return unknown(method, "verify.no_marker", 0);
    }
    const max = req.maxLookups ?? MAX_REFUND_PAGES;
    let lookups = 0;
    for (let page = 0; page < MAX_REFUND_PAGES; page++) {
      if (lookups >= max) return unknown(method, "verify.budget", lookups);
      lookups++;
      const res = await lookup(REFUND_LIST_TOOL, {
        payment_id: paymentId,
        count: REFUND_PAGE_SIZE,
        skip: page * REFUND_PAGE_SIZE,
      });
      if (!res.ok) return unknown(method, res.errorCode, lookups);
      const parsed = refundPageSchema.safeParse(res.json);
      if (!parsed.success || parsed.data.items.length > REFUND_PAGE_SIZE) {
        return unknown(method, "verify.malformed", lookups);
      }
      for (const item of parsed.data.items) {
        const r = refundSchema.safeParse(item);
        // One unreadable refund could be ours: can't conclude anything.
        if (!r.success) return unknown(method, "verify.malformed", lookups);
        const n = r.data.notes;
        if (n === undefined || Array.isArray(n) || n[ATTEMPT_MARKER_KEY] !== req.attemptId)
          continue;
        if (r.data.amount !== amount) return unknown(method, "verify.amount_mismatch", lookups);
        if (r.data.payment_id !== undefined && r.data.payment_id !== paymentId) {
          return unknown(method, "verify.payment_mismatch", lookups);
        }
        const status = r.data.status;
        if (status === "failed") return unknown(method, "verify.refund_failed", lookups);
        if (status === undefined || !LIVE_REFUND_STATUSES.has(status)) {
          return unknown(method, "verify.unexpected_status", lookups);
        }
        return {
          result: "happened",
          method,
          upstreamRef: r.data.id,
          refundStatus: status,
          absent: false,
          lookups,
        };
      }
      const n = parsed.data.items.length;
      // Exactly the server's default page size although we asked for more: `count` may have been ignored.
      if (n === REFUND_LIST_SHORT_PAGE) return unknown(method, "verify.incomplete", lookups);
      if (n < REFUND_PAGE_SIZE) {
        // Complete list, no marker.
        return absentFinding(method, req.failure, lookups);
      }
    }
    return unknown(method, "verify.incomplete", lookups);
  };

  const verifyCapture = async (req: VerifyRequest): Promise<Finding> => {
    const method: AuditVerificationMethod = "payment_status";
    const a = req.args;
    if (!isPlainObject(a)) return unknown(method, "verify.bad_args", 0);
    const paymentId = a["payment_id"];
    if (typeof paymentId !== "string" || !PAYMENT_ID_PATTERN.test(paymentId)) {
      return unknown(method, "verify.bad_args", 0);
    }
    if ((req.maxLookups ?? 1) < 1) return unknown(method, "verify.budget", 0);
    const res = await lookup(FETCH_PAYMENT_TOOL, { payment_id: paymentId });
    if (!res.ok) return unknown(method, res.errorCode, 1);
    const p = paymentStatusSchema.safeParse(res.json);
    if (!p.success) return unknown(method, "verify.malformed", 1);
    if (p.data.id !== paymentId) return unknown(method, "verify.payment_mismatch", 1);
    if (p.data.status === "captured") {
      return { result: "happened", method, upstreamRef: paymentId, absent: false, lookups: 1 };
    }
    if (p.data.status === "authorized") return absentFinding(method, req.failure, 1);
    return unknown(method, "verify.unexpected_status", 1);
  };

  return {
    async verify(req: VerifyRequest): Promise<Finding> {
      try {
        if (req.tool === "create_refund") return await verifyRefund(req);
        if (req.tool === "capture_payment") return await verifyCapture(req);
        return unknown("none", "verify.unsupported_tool", 0);
      } catch {
        // Never throw into the money path: an exception is simply "could not verify" (fails closed: unknown).
        return unknown(methodFor(req.tool), "verify.failed", 0);
      }
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Late responses
// ---------------------------------------------------------------------------------------------------------------

/** Source of late-response events (`Upstream`). */
export interface LateResponseSource {
  onLateResponse(listener: (e: LateResponse) => void): () => void;
}

export interface LateResponseTracker {
  /** The late answer for (generation, requestId): already buffered, or arriving within `timeoutMs`; else undefined. */
  waitFor(
    generation: number,
    requestId: RequestId,
    timeoutMs: number,
  ): Promise<LateResponse | undefined>;
  /** Remove and return a buffered answer, if any. */
  take(generation: number, requestId: RequestId): LateResponse | undefined;
  /** Events nobody was waiting for (after buffering). Returns an unsubscribe function. */
  onUnclaimed(listener: (e: LateResponse) => void): () => void;
  close(): void;
}

/** Max buffered unclaimed events (oldest evicted). */
export const MAX_BUFFERED_LATE = 256;

export function lateKey(generation: number, requestId: RequestId): string {
  return `${String(generation)}|${typeof requestId}|${String(requestId)}`;
}

export function createLateResponseTracker(o: {
  readonly source: LateResponseSource | undefined;
  readonly timer: Timer;
  readonly logger?: Logger;
}): LateResponseTracker {
  const log: Logger = o.logger ?? (() => undefined);
  const buffered = new Map<string, LateResponse>();
  const waiters = new Map<string, (e: LateResponse) => void>();
  const listeners = new Set<(e: LateResponse) => void>();
  const unsubscribe =
    o.source?.onLateResponse((e) => {
      const key = lateKey(e.generation, e.requestId);
      const waiter = waiters.get(key);
      if (waiter !== undefined) {
        waiters.delete(key);
        waiter(e);
        return;
      }
      if (buffered.size >= MAX_BUFFERED_LATE) {
        const oldest = buffered.keys().next();
        if (oldest.done !== true) buffered.delete(oldest.value);
      }
      buffered.set(key, e);
      for (const l of [...listeners]) {
        try {
          l(e);
        } catch (err: unknown) {
          log(`late-response handler failed (${err instanceof Error ? err.name : typeof err})`);
        }
      }
    }) ?? (() => undefined);

  return {
    take(generation, requestId) {
      const key = lateKey(generation, requestId);
      const e = buffered.get(key);
      if (e !== undefined) buffered.delete(key);
      return e;
    },
    async waitFor(generation, requestId, timeoutMs) {
      const key = lateKey(generation, requestId);
      const ready = buffered.get(key);
      if (ready !== undefined) {
        buffered.delete(key);
        return ready;
      }
      if (o.source === undefined || waiters.has(key)) return undefined;
      const handle = o.timer.after(timeoutMs);
      try {
        return await new Promise<LateResponse | undefined>((resolve) => {
          waiters.set(key, resolve);
          void handle.promise.then(() => {
            if (waiters.get(key) === resolve) waiters.delete(key);
            resolve(undefined);
          });
        });
      } finally {
        handle.cancel();
      }
    },
    onUnclaimed(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    close() {
      unsubscribe();
      listeners.clear();
      waiters.clear();
      buffered.clear();
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// handleUnsettled
// ---------------------------------------------------------------------------------------------------------------

export interface UnsettledDeps {
  readonly store: Pick<AuditStore, "recordVerification">;
  readonly verifier: ActionVerifier;
  readonly tracker: LateResponseTracker;
  readonly verifyWaitMs: number;
  readonly logger?: Logger;
}

export interface UnsettledAction {
  readonly attemptId: string;
  readonly tool: string;
  /** Args as forwarded (stamped), or as stored. */
  readonly args: unknown;
  readonly trigger: AuditVerificationTrigger;
  /** What a failure answer already in hand (direct tool error) proves; `none` if there is none. */
  readonly failure: UpstreamFailure;
  /** A late answer already in hand (trigger `late_response`). */
  readonly late?: Pick<LateResponse, "isError" | "failure">;
  /**
   * Only for a call that may be retried: wait up to `verifyWaitMs` for this request's late answer when the first
   * lookup was complete and found nothing.
   */
  readonly waitLate?: { readonly generation: number; readonly requestId: RequestId };
  /** Write an `unknown` verification (false: only write if the action settles). Default true. */
  readonly recordUnknown?: boolean;
  readonly maxLookups?: number;
}

export interface UnsettledResolution {
  readonly finding: Finding;
  /** A late DEFINITE-REJECTION answer for this request was seen (precondition for a retry). */
  readonly lateRejection: boolean;
  /** The verification written; `undefined` if none was written (`recordUnknown: false`) or the write failed. */
  readonly record?: AuditVerificationRecord;
  /** The verification write failed (the caller latches the pipeline degraded). */
  readonly auditFailed: boolean;
}

/** A late SUCCESS answer for an unverifiable tool ⇒ happened (method none); otherwise the finding unchanged. */
function withLateAnswer(
  f: Finding,
  late: Pick<LateResponse, "isError" | "failure"> | undefined,
): Finding {
  if (
    f.result === "unknown" &&
    f.method === "none" &&
    late !== undefined &&
    !late.isError &&
    late.failure === "none"
  ) {
    return { result: "happened", method: "none", absent: false, lookups: f.lookups };
  }
  return f;
}

/** See module doc. Never throws. */
export async function handleUnsettled(
  deps: UnsettledDeps,
  action: UnsettledAction,
): Promise<UnsettledResolution> {
  const log: Logger = deps.logger ?? (() => undefined);
  const req = (failure: UpstreamFailure): VerifyRequest => ({
    attemptId: action.attemptId,
    tool: action.tool,
    args: action.args,
    failure,
    ...(action.maxLookups === undefined ? {} : { maxLookups: action.maxLookups }),
  });
  const known = mergeFailure(action.failure, action.late?.failure);
  let finding = withLateAnswer(await deps.verifier.verify(req(known)), action.late);
  let lateRejection = action.late !== undefined && known === "definite_rejection";
  // Only worth waiting when no failure answer is in hand yet (an ambiguous one can't become definite).
  if (
    finding.result === "unknown" &&
    finding.absent &&
    action.waitLate !== undefined &&
    known === "none"
  ) {
    const late = await deps.tracker.waitFor(
      action.waitLate.generation,
      action.waitLate.requestId,
      deps.verifyWaitMs,
    );
    const failure = mergeFailure(known, late?.failure);
    lateRejection = late !== undefined && failure === "definite_rejection";
    // Look again either way: the action may have shown up while we waited.
    finding = withLateAnswer(await deps.verifier.verify(req(failure)), late);
  }
  if (finding.result === "unknown" && action.recordUnknown === false) {
    return { finding, lateRejection, auditFailed: false };
  }
  const input: RecordVerificationInput = {
    attemptId: action.attemptId,
    trigger: action.trigger,
    result: finding.result,
    method: finding.method,
    needsHuman: finding.result === "unknown",
    ...(finding.upstreamRef === undefined ? {} : { upstreamRef: finding.upstreamRef }),
    ...(finding.errorCode === undefined ? {} : { errorCode: finding.errorCode }),
  };
  const written = deps.store.recordVerification(input);
  if (!written.ok) {
    log(`audit verification write failed for attempt ${action.attemptId}: ${written.error.code}`);
    return { finding, lateRejection, auditFailed: true };
  }
  if (written.value.kind !== "verification") {
    log(`audit verification write returned an unexpected record for attempt ${action.attemptId}`);
    return { finding, lateRejection, auditFailed: true };
  }
  if (finding.result === "unknown") logNeedsHuman(log, action.tool, action.attemptId);
  return { finding, lateRejection, record: written.value, auditFailed: false };
}

/** The operator line for an action flagged for a human (ids and tool only, no payload). */
export function logNeedsHuman(log: Logger, tool: string, attemptId: string): void {
  log(
    `MONEY ACTION NEEDS A HUMAN: ${escapeForTerminal(tool)} attempt ${escapeForTerminal(attemptId)} may have executed and could not be verified; identical actions stay blocked until it is resolved`,
  );
}

// ---------------------------------------------------------------------------------------------------------------
// Startup reconciliation
// ---------------------------------------------------------------------------------------------------------------

export interface ReconcileDeps {
  readonly store: Pick<
    AuditStore,
    "readUnsettled" | "recordOutcome" | "recordVerification" | "recordApproval"
  >;
  readonly verifier: ActionVerifier;
  readonly logger?: Logger;
  /** Max upstream lookups (default `STARTUP_LOOKUP_BUDGET`). */
  readonly lookupBudget?: number;
  /** T011: approval id of a stale approval's attempt (approval store), for its `expired` record. */
  readonly approvalIdOf?: (attemptId: string) => string | undefined;
}

export interface ReconcileSummary {
  /** Open (possibly sent) attempts given an `upstream_error` / `firewall.orphaned` outcome. */
  readonly orphaned: number;
  /**
   * T011: approvals left undecided (or decided without their terminal outcome) by an earlier run, closed as
   * `not_forwarded` + `approval.expired` / `approval.rejected`. Their args lived in memory only, so they can never run.
   */
  readonly approvalsClosed: number;
  readonly happened: number;
  readonly notHappened: number;
  /** Actions still unknown (incl. ones left unknown from an earlier run), to keep blocking duplicates. */
  readonly unresolved: readonly AuditActivity[];
  readonly lookups: number;
}

/** What a recorded outcome's error code proves about upstream's failure answer (see `REJECTED_ERROR_CODE`). */
export function startupFailureOf(errorCode: string | undefined): UpstreamFailure {
  if (errorCode === REJECTED_ERROR_CODE) return "definite_rejection";
  if (errorCode === "upstream.tool_error") return "ambiguous";
  return "none";
}

/**
 * See module doc. `err` (caller latches degraded) when the log can't be scanned or an orphan outcome / verification
 * can't be written. Never retries anything.
 */
export async function reconcileAtStartup(deps: ReconcileDeps): Promise<Result<ReconcileSummary>> {
  const log: Logger = deps.logger ?? (() => undefined);
  const budget = deps.lookupBudget ?? STARTUP_LOOKUP_BUDGET;
  const scan = deps.store.readUnsettled();
  if (!scan.ok) return scan;
  const work: AuditActivity[] = [];
  let orphaned = 0;
  let approvalsClosed = 0;
  for (const a of scan.value.staleApprovals) {
    let decision = a.approval?.decision;
    if (decision === undefined) {
      const rec = deps.store.recordApproval({
        attemptId: a.attempt.id,
        approvalId: deps.approvalIdOf?.(a.attempt.id) ?? "unknown",
        decision: "expired",
      });
      if (!rec.ok) return err(rec.error.code, "could not expire a stale approval");
      decision = "expired";
    }
    if (decision === "approved") continue; // not possible: approved rows are `open`
    const out = deps.store.recordOutcome({
      attemptId: a.attempt.id,
      outcome: "not_forwarded",
      errorCode: decision === "rejected" ? "approval.rejected" : "approval.expired",
      latencyMs: 0,
    });
    if (!out.ok) return err(out.error.code, "could not close a stale approval");
    approvalsClosed++;
    log(
      `startup: approval for attempt ${escapeForTerminal(a.attempt.id)} (${escapeForTerminal(a.attempt.tool)}) was not executed before the restart; closed as ${decision}`,
    );
  }
  for (const a of scan.value.open) {
    const out = deps.store.recordOutcome({
      attemptId: a.attempt.id,
      outcome: "upstream_error",
      errorCode: "firewall.orphaned",
      latencyMs: 0,
    });
    if (!out.ok) return err(out.error.code, "could not record an orphaned attempt's outcome");
    if (out.value.kind !== "outcome") {
      return err("audit.write_failed", "orphan outcome write returned an unexpected record");
    }
    orphaned++;
    log(
      `startup: attempt ${escapeForTerminal(a.attempt.id)} (${escapeForTerminal(a.attempt.tool)}) had no outcome (proxy stopped mid-call); recorded upstream_error firewall.orphaned`,
    );
    work.push({ attempt: a.attempt, outcome: out.value });
  }
  work.push(...scan.value.unsettled);
  work.sort((x, y) => x.attempt.seq - y.attempt.seq);

  let lookups = 0;
  let upstreamDown = false;
  let consecutiveTimeouts = 0;
  let happened = 0;
  let notHappened = 0;
  const unresolved: AuditActivity[] = [];
  for (const a of work) {
    const outcome = a.outcome;
    if (outcome === undefined) continue; // not possible: open rows got an outcome above
    let finding: Finding;
    if (upstreamDown || lookups >= budget) {
      finding = unknown(
        methodFor(a.attempt.tool),
        upstreamDown ? "verify.unavailable" : "verify.budget",
        0,
      );
    } else {
      finding = await deps.verifier.verify({
        attemptId: a.attempt.id,
        tool: a.attempt.tool,
        args: a.attempt.argsRedacted,
        // Only a tool error classified as a definite rejection when it was recorded; everything else (timeouts,
        // connection loss, ambiguous tool errors, orphans) can never become not_happened.
        failure: startupFailureOf(outcome.errorCode),
        maxLookups: budget - lookups,
      });
      lookups += finding.lookups;
      if (finding.errorCode === "verify.unavailable") upstreamDown = true;
      consecutiveTimeouts = finding.errorCode === "verify.timeout" ? consecutiveTimeouts + 1 : 0;
      if (consecutiveTimeouts >= STARTUP_MAX_CONSECUTIVE_TIMEOUTS) {
        if (!upstreamDown) {
          log(
            `startup: ${String(consecutiveTimeouts)} verification lookups timed out in a row; treating upstream as down`,
          );
        }
        upstreamDown = true;
      }
    }
    const alreadyUnknown = a.verification?.result === "unknown";
    if (finding.result === "unknown" && alreadyUnknown) {
      unresolved.push(a);
      continue;
    }
    const written = deps.store.recordVerification({
      attemptId: a.attempt.id,
      trigger: "startup",
      result: finding.result,
      method: finding.method,
      needsHuman: finding.result === "unknown",
      ...(finding.upstreamRef === undefined ? {} : { upstreamRef: finding.upstreamRef }),
      ...(finding.errorCode === undefined ? {} : { errorCode: finding.errorCode }),
    });
    if (!written.ok) return err(written.error.code, "could not record a startup verification");
    if (written.value.kind !== "verification") {
      return err("audit.write_failed", "verification write returned an unexpected record");
    }
    if (finding.result === "happened") happened++;
    else if (finding.result === "not_happened") notHappened++;
    else {
      logNeedsHuman(log, a.attempt.tool, a.attempt.id);
      unresolved.push({ attempt: a.attempt, outcome, verification: written.value });
    }
  }
  return ok({ orphaned, approvalsClosed, happened, notHappened, unresolved, lookups });
}
