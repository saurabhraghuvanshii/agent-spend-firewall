/** JSON value as stored in the audit log. All numbers must be safe integers (paise, ms, seq). */
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

/** `prevHash` of the first record in a chain. */
export const GENESIS_PREV_HASH: string = "0".repeat(64);

/** Shape of `AuditAttemptBody.idempotencyKey`: exactly 64 lowercase hex chars. */
export const IDEMPOTENCY_KEY_RE: RegExp = /^[0-9a-f]{64}$/;

/**
 * Hashing port. Core has no access to `node:crypto`; adapters inject an implementation.
 * Must return the lowercase hex SHA-256 (64 chars) of the UTF-8 encoding of `input`.
 */
export interface Hasher {
  sha256Hex(input: string): string;
}

/**
 * Shape rules shared by the core chain validator and storage adapters (the proxy's zod schemas mirror these).
 * Record / attempt id: printable ASCII token (UUIDs, `att-1`, `rfnd_x:1`).
 */
export const RECORD_ID_RE: RegExp = /^[A-Za-z0-9_.:-]{1,128}$/;
/** Upstream resource id, e.g. `rfnd_ABC123xyz`. */
export const UPSTREAM_REF_RE: RegExp = /^[A-Za-z0-9_.:-]{1,128}$/;
/** Lowercase machine code, e.g. `upstream.timeout`. */
export const ERROR_CODE_RE: RegExp = /^[a-z0-9_.:-]{1,64}$/;
/** Opaque approver / resolver id: `telegram:<1-20 digits>` or `dashboard:<[a-z0-9_-]{1,32}>`. Never PII. */
export const APPROVER_RE: RegExp = /^(?:telegram:[0-9]{1,20}|dashboard:[a-z0-9_-]{1,32})$/;

export type AuditKind = "attempt" | "outcome" | "verification" | "approval";

export type AuditDecision = "allow" | "deny" | "require_approval" | "transform";

export type AuditOutcome = "success" | "upstream_error" | "timeout" | "denied" | "not_forwarded";

/** Written *before* a money action is forwarded (or denied). */
export interface AuditAttemptBody {
  kind: "attempt";
  id: string;
  /** ISO-8601 timestamp from the injected clock. */
  ts: string;
  sessionId: string;
  tool: string;
  /** Tool arguments after `redact()`. Amounts are integer paise. */
  argsRedacted: JsonValue;
  /**
   * The agent's ORIGINAL tool arguments after `redact()`, present only when a `transform` decision changed them
   * (`argsRedacted` then holds the transformed args that were forwarded). Omitted otherwise; older rows written
   * before this field existed have no such key and still verify, since `canonicalJson` drops absent/undefined keys.
   */
  originalArgsRedacted?: JsonValue;
  /**
   * Idempotency key forwarded upstream for this money action (T009). When present it MUST be exactly 64 lowercase
   * hex chars (`IDEMPOTENCY_KEY_RE`); `buildRecord` rejects and `verifyChain` reports `invalid_row` otherwise.
   * Part of the hashed body when present; omitted otherwise, so older rows without it hash exactly as before.
   * Only attempts carry it — an outcome record with this key is invalid.
   */
  idempotencyKey?: string;
  /** Agent-supplied justification after `redactText()`. */
  reason: string;
  decision: AuditDecision;
  matchedRules: string[];
  approver?: string;
  /**
   * T010: id of an earlier attempt of the same tool that this attempt retries (same format as attempt ids,
   * `RECORD_ID_RE`). Only allowed when the original's latest verification is `not_happened`, at most one retry per
   * original, and a retry is never itself retried (`verifyChain` ⇒ `bad_retry_of`). Hashed only when present, so
   * rows without it hash exactly as before. Only attempts may carry it.
   */
  retryOf?: string;
}

/** Chained record describing what happened to an earlier attempt. */
export interface AuditOutcomeBody {
  kind: "outcome";
  id: string;
  attemptId: string;
  ts: string;
  outcome: AuditOutcome;
  errorCode?: string;
  /** Integer milliseconds. */
  latencyMs: number;
  upstreamRef?: string;
}

/** What triggered a verification of an unsettled money action (T010). */
export type AuditVerificationTrigger =
  "timeout" | "upstream_error" | "late_response" | "startup" | "human";
export const AUDIT_VERIFICATION_TRIGGERS: readonly AuditVerificationTrigger[] = [
  "timeout",
  "upstream_error",
  "late_response",
  "startup",
  "human",
];

/** Whether the upstream applied the action. Only `unknown` may be followed by further verifications. */
export type AuditVerificationResult = "happened" | "not_happened" | "unknown";
export const AUDIT_VERIFICATION_RESULTS: readonly AuditVerificationResult[] = [
  "happened",
  "not_happened",
  "unknown",
];

/** How the result was established. `none`: no lookup possible (result is then `unknown`, or a human decided). */
export type AuditVerificationMethod = "refund_notes_marker" | "payment_status" | "none";
export const AUDIT_VERIFICATION_METHODS: readonly AuditVerificationMethod[] = [
  "refund_notes_marker",
  "payment_status",
  "none",
];

/**
 * Chained record (T010) settling — or failing to settle — an attempt whose outcome left it unclear whether the
 * upstream applied it (timeout, sent-then-failed). Several may exist per attempt, but only while the latest is
 * `unknown`. Validated strictly in `computeHash`: no extra keys; enums exact; `needsHuman` boolean;
 * `upstreamRef` ⇒ `UPSTREAM_REF_RE`; `errorCode` ⇒ `ERROR_CODE_RE`; `resolver` ⇒ `APPROVER_RE`, required iff
 * `trigger === "human"`.
 */
export interface AuditVerificationBody {
  kind: "verification";
  id: string;
  attemptId: string;
  ts: string;
  trigger: AuditVerificationTrigger;
  result: AuditVerificationResult;
  method: AuditVerificationMethod;
  needsHuman: boolean;
  upstreamRef?: string;
  errorCode?: string;
  resolver?: string;
}

/** A human's (or the clock's) decision on a `require_approval` attempt (T011). */
export type AuditApprovalDecision = "approved" | "rejected" | "expired";
export const AUDIT_APPROVAL_DECISIONS: readonly AuditApprovalDecision[] = [
  "approved",
  "rejected",
  "expired",
];

/** Approval id shape (`apr_<uuid>` from the proxy; any `RECORD_ID_RE` token is accepted by the chain). */
export const APPROVAL_ID_RE: RegExp = RECORD_ID_RE;

/**
 * Chained record (T011) of the decision on a `require_approval` attempt, written BEFORE anything is executed (approved)
 * or before the terminal `not_forwarded` outcome (rejected / expired). At most one per attempt, never after the
 * attempt's outcome, only for a `require_approval` attempt that is not a retry. Validated strictly in `computeHash`:
 * no extra keys; `decision` exact; `approvalId` ⇒ `APPROVAL_ID_RE`; `approver` ⇒ `APPROVER_RE`, required for
 * `approved` / `rejected` and forbidden for `expired`.
 *
 * `verifyChain` then requires: a forwarded outcome (`success` / `upstream_error` / `timeout`) of a `require_approval`
 * attempt (or of a retry of one) has an earlier `approved` record; a `rejected` / `expired` attempt's outcome is
 * `not_forwarded`.
 */
export interface AuditApprovalBody {
  kind: "approval";
  id: string;
  attemptId: string;
  ts: string;
  approvalId: string;
  decision: AuditApprovalDecision;
  approver?: string;
}

export type AuditBody =
  AuditAttemptBody | AuditOutcomeBody | AuditVerificationBody | AuditApprovalBody;

export type AuditRecord = AuditBody & { seq: number; prevHash: string; hash: string };

/** Placeholder for a stored row that could not be parsed into an `AuditRecord`. */
export interface InvalidAuditRow {
  invalid: true;
  seq: number;
}

export type VerifyBreakReason =
  | "prev_hash_mismatch"
  | "hash_mismatch"
  | "seq_gap"
  | "genesis_mismatch"
  | "invalid_row"
  | "orphan_outcome"
  | "duplicate_outcome"
  | "duplicate_id"
  | "hasher_error"
  | "orphan_verification"
  | "verification_before_outcome"
  | "verification_after_settled"
  | "bad_retry_of"
  | "orphan_approval"
  | "approval_not_required"
  | "approval_after_outcome"
  | "duplicate_approval"
  | "approval_missing"
  | "approval_outcome_mismatch";

export type VerifyResult =
  | { ok: true; count: number; headHash: string; danglingAttempts: string[] }
  | {
      ok: false;
      brokenAt: { index: number; seq: number; id: string | null; reason: VerifyBreakReason };
    };
