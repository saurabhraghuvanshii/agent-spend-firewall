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

export type AuditKind = "attempt" | "outcome";

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

export type AuditBody = AuditAttemptBody | AuditOutcomeBody;

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
  | "hasher_error";

export type VerifyResult =
  | { ok: true; count: number; headHash: string; danglingAttempts: string[] }
  | {
      ok: false;
      brokenAt: { index: number; seq: number; id: string | null; reason: VerifyBreakReason };
    };
