/**
 * Ports the dashboard API runs over (T013, D-036). `@asf/api` never opens a database or talks to Telegram itself: the
 * proxy process injects adapters over ITS audit store, mode store and approval service, so an approve / reject from
 * the dashboard goes through exactly the same `decide()` path as a Telegram button (single-use store transition,
 * re-evaluation, args hash, locks, kill switch) and the in-memory pending args (D-034) are reachable.
 *
 * Every method returns a `Result` and must not throw; the API still treats a throw as a 500 (never a success).
 */
import type { AuditRecord, InvalidAuditRow, Result, VerifyResult } from "@asf/core";

export type AuditRow = AuditRecord | InvalidAuditRow;

export interface AuditPort {
  /** Newest first below `beforeSeq` (or from the head), or oldest first above `afterSeq`; at most `limit`. */
  readPage(query: {
    readonly limit: number;
    readonly beforeSeq?: number;
    readonly afterSeq?: number;
  }): Result<AuditRow[]>;
  /** A session's attempts plus the records that reference them, oldest first, at most `limit`. */
  readSession(sessionId: string, limit: number): Result<AuditRow[]>;
  /** The attempt record with this id (`undefined` if none). */
  readAttempt(attemptId: string): Result<AuditRecord | undefined>;
  /** Full hash-chain verification (`verifyChain`). */
  verify(): Result<VerifyResult>;
}

export interface ModeSnapshot {
  readonly killSwitch: boolean;
  readonly shadow: boolean;
  readonly changedAt?: string;
  readonly actor?: string;
  readonly recordId?: string;
}

/** Structurally the proxy's `ModeStore` (chained `mode` records, D-035). */
export interface ModesPort {
  read(): Result<ModeSnapshot>;
  set(change: {
    readonly killSwitch?: boolean;
    readonly shadow?: boolean;
    /** `dashboard:<slug>`. */
    readonly actor: string;
  }): Result<{ readonly changed: boolean; readonly mode: ModeSnapshot }>;
}

/** A pending approval as the API may show it: ids, rule and deadline only (never the callback nonce or args). */
export interface ApprovalSummary {
  readonly approvalId: string;
  readonly attemptId: string;
  readonly sessionId: string;
  readonly tool: string;
  readonly ruleId: string;
  readonly state: "pending" | "approved" | "rejected" | "expired";
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}

/** What one decision did. Only `approved` / `rejected` mean THIS request decided it. */
export type DecisionStatus =
  "approved" | "rejected" | "expired" | "already_decided" | "not_found" | "unavailable";

export interface ApprovalsPort {
  listPending(limit: number): Result<ApprovalSummary[]>;
  /**
   * Decide through the approval service (`ApprovalService.decide`). `approver` is `dashboard:<slug>`. Execution of an
   * approved action continues in the background (tracked by the service), exactly like a Telegram press.
   */
  decide(req: {
    readonly approvalId: string;
    readonly decision: "approved" | "rejected";
    readonly approver: string;
  }): Promise<DecisionStatus>;
}
