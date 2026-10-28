/**
 * SQLite pending-approval store (T011).
 *
 * States: `pending → approved | rejected | expired`. Every transition is ONE conditional `UPDATE … WHERE state =
 * 'pending'` (atomic in SQLite), so a decision is single-use: of two concurrent / replayed decisions exactly one wins,
 * and a `BEFORE UPDATE OF state` trigger aborts any change of a non-pending state even if code were wrong. A pending
 * approval whose `expires_at_ms` has passed can no longer be approved or rejected (the conditional update requires
 * `expires_at_ms > now`); it can only become `expired`, which the firewall treats as rejected.
 *
 * Holds NO tool arguments, reasons or PII: only ids, the args hash, the rule id, timestamps, the opaque approver id
 * and the execution status. The args to execute live in the proxy's memory only (a restart expires every pending
 * approval, see D-034).
 *
 * Methods never throw: failures are `err` Results (callers fail closed).
 */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { z } from "zod";
import { err, ok, type Result } from "@asf/core";

export type ApprovalState = "pending" | "approved" | "rejected" | "expired";
export const APPROVAL_STATES: readonly ApprovalState[] = [
  "pending",
  "approved",
  "rejected",
  "expired",
];

/** What happened to an approved action (mirrors the proxy's `ApprovedExecutionStatus` + `executing`). */
export type ExecutionStatus = "executing" | "executed" | "failed" | "unknown" | "not_executed";
export const EXECUTION_STATUSES: readonly ExecutionStatus[] = [
  "executing",
  "executed",
  "failed",
  "unknown",
  "not_executed",
];

/** Opaque ids (`apr_<uuid>`, attempt UUIDs, `rfnd_…`): printable ASCII tokens, never PII. */
export const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
/** Approver: `telegram:<numeric id>` or `dashboard:<slug>` (same as the audit log's `APPROVER_RE`). */
export const DECIDED_BY_RE = /^(?:telegram:[0-9]{1,20}|dashboard:[a-z0-9_-]{1,32})$/;
/** Machine code, e.g. `approval.policy_denied`. */
export const CODE_RE = /^[a-z0-9_.:-]{1,64}$/;
/** Callback nonce: 16 random bytes, base64url (22 chars). */
export const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;

export interface ApprovalExecution {
  readonly status: ExecutionStatus;
  readonly upstreamRef?: string;
  readonly code?: string;
}

export interface ApprovalRow {
  readonly approvalId: string;
  readonly attemptId: string;
  readonly sessionId: string;
  readonly tool: string;
  readonly argsHash: string;
  readonly ruleId: string;
  readonly callbackNonce: string;
  readonly state: ApprovalState;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly decidedAtMs?: number;
  readonly decidedBy?: string;
  /** Telegram message id of the approval request, once sent. */
  readonly messageId?: number;
  readonly execution?: ApprovalExecution;
}

export interface CreateApprovalInput {
  readonly approvalId: string;
  readonly attemptId: string;
  readonly sessionId: string;
  readonly tool: string;
  readonly argsHash: string;
  readonly ruleId: string;
  readonly callbackNonce: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}

/** Result of a transition attempt: `won` iff THIS call moved the row out of `pending`; `row` is the state after. */
export interface Transition {
  readonly won: boolean;
  readonly row: ApprovalRow;
}

export interface ApprovalStore {
  readonly path: string;
  create(input: CreateApprovalInput): Result<ApprovalRow>;
  get(approvalId: string): Result<ApprovalRow | undefined>;
  getByNonce(nonce: string): Result<ApprovalRow | undefined>;
  getByAttempt(attemptId: string): Result<ApprovalRow | undefined>;
  setMessageId(approvalId: string, messageId: number): Result<null>;
  /**
   * `pending → approved | rejected`, only while `expires_at_ms > nowMs`. `err` `approval.not_found` if no such row.
   * A lost race / replay / expired row ⇒ `{ won: false, row }` (row unchanged).
   */
  decide(
    approvalId: string,
    decision: "approved" | "rejected",
    decidedBy: string,
    nowMs: number,
  ): Result<Transition>;
  /**
   * `pending → expired` when `expires_at_ms <= nowMs`, or unconditionally with `force` (restart, notification
   * failure). `{ won: false }` if it was not pending (or not yet due).
   */
  expire(approvalId: string, nowMs: number, force?: boolean): Result<Transition>;
  /** Pending approvals whose deadline has passed (oldest first, at most `limit`, default 100). */
  listDue(nowMs: number, limit?: number): Result<ApprovalRow[]>;
  /** Every pending approval (oldest first, at most `limit`, default 1000). */
  listPending(limit?: number): Result<ApprovalRow[]>;
  /**
   * Approved rows whose execution never finished (no status or `executing`), oldest first, at most `limit`
   * (default 1000): after a restart these may or may not have run.
   */
  listUnfinished(limit?: number): Result<ApprovalRow[]>;
  /**
   * Record what happened to an APPROVED action. Only while no final status is recorded (none or `executing`): a
   * final status is never overwritten ⇒ `err` `approval.not_approved` (also if the row is not `approved`).
   */
  setExecution(approvalId: string, execution: ApprovalExecution): Result<null>;
  close(): void;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL UNIQUE,
  session_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  callback_nonce TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'expired')),
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  decided_at_ms INTEGER,
  decided_by TEXT,
  message_id INTEGER,
  exec_status TEXT CHECK (exec_status IS NULL OR exec_status IN ('executing', 'executed', 'failed', 'unknown', 'not_executed')),
  exec_ref TEXT,
  exec_code TEXT
);
CREATE INDEX IF NOT EXISTS approvals_pending_due ON approvals (state, expires_at_ms);
CREATE TRIGGER IF NOT EXISTS approvals_state_is_final BEFORE UPDATE OF state ON approvals
  WHEN OLD.state <> 'pending'
  BEGIN SELECT RAISE(ABORT, 'approval state is final'); END;
CREATE TRIGGER IF NOT EXISTS approvals_no_delete BEFORE DELETE ON approvals
  BEGIN SELECT RAISE(ABORT, 'approvals are never deleted'); END;
`;

const id = z.string().regex(ID_RE);
const ms = z.int().nonnegative();
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

const createSchema = z.strictObject({
  approvalId: id,
  attemptId: id,
  sessionId: z.string().min(1).max(256),
  tool: z.string().regex(/^[A-Za-z0-9_.-]{1,128}$/),
  argsHash: hex64,
  ruleId: z.string().min(1).max(128),
  callbackNonce: z.string().regex(NONCE_RE),
  createdAtMs: ms,
  expiresAtMs: ms,
});

const rowSchema = z.object({
  approval_id: z.string(),
  attempt_id: z.string(),
  session_id: z.string(),
  tool: z.string(),
  args_hash: z.string(),
  rule_id: z.string(),
  callback_nonce: z.string(),
  state: z.enum(APPROVAL_STATES),
  created_at_ms: z.int(),
  expires_at_ms: z.int(),
  decided_at_ms: z.int().nullable(),
  decided_by: z.string().nullable(),
  message_id: z.int().nullable(),
  exec_status: z.enum(EXECUTION_STATUSES).nullable(),
  exec_ref: z.string().nullable(),
  exec_code: z.string().nullable(),
});

function toRow(raw: unknown): ApprovalRow | undefined {
  const p = rowSchema.safeParse(raw);
  if (!p.success) return undefined;
  const r = p.data;
  return {
    approvalId: r.approval_id,
    attemptId: r.attempt_id,
    sessionId: r.session_id,
    tool: r.tool,
    argsHash: r.args_hash,
    ruleId: r.rule_id,
    callbackNonce: r.callback_nonce,
    state: r.state,
    createdAtMs: r.created_at_ms,
    expiresAtMs: r.expires_at_ms,
    ...(r.decided_at_ms === null ? {} : { decidedAtMs: r.decided_at_ms }),
    ...(r.decided_by === null ? {} : { decidedBy: r.decided_by }),
    ...(r.message_id === null ? {} : { messageId: r.message_id }),
    ...(r.exec_status === null
      ? {}
      : {
          execution: {
            status: r.exec_status,
            ...(r.exec_ref === null ? {} : { upstreamRef: r.exec_ref }),
            ...(r.exec_code === null ? {} : { code: r.exec_code }),
          },
        }),
  };
}

function cause(e: unknown): string {
  return e instanceof Database.SqliteError ? e.code : e instanceof Error ? e.name : typeof e;
}

export interface OpenApprovalStoreOptions {
  /** File path (parent directory created) or `":memory:"`. */
  readonly path: string;
  readonly busyTimeoutMs?: number;
}

export function openApprovalStore(opts: OpenApprovalStoreOptions): Result<ApprovalStore> {
  let db: Database.Database;
  try {
    if (opts.path !== ":memory:") mkdirSync(dirname(opts.path), { recursive: true });
    db = new Database(opts.path);
    db.pragma(`busy_timeout = ${String(Math.max(0, Math.trunc(opts.busyTimeoutMs ?? 5000)))}`);
    if (opts.path !== ":memory:") db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.exec(SCHEMA_SQL);
  } catch (e: unknown) {
    return err("approval.store_open_failed", "could not open the approval store", {
      cause: cause(e),
    });
  }

  const SELECT = "SELECT * FROM approvals";
  const getStmt = db.prepare(`${SELECT} WHERE approval_id = ?`);
  const nonceStmt = db.prepare(`${SELECT} WHERE callback_nonce = ?`);
  const attemptStmt = db.prepare(`${SELECT} WHERE attempt_id = ?`);
  const insertStmt = db.prepare(
    `INSERT INTO approvals (approval_id, attempt_id, session_id, tool, args_hash, rule_id, callback_nonce, state,
       created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
  );
  const decideStmt = db.prepare(
    `UPDATE approvals SET state = ?, decided_at_ms = ?, decided_by = ?
       WHERE approval_id = ? AND state = 'pending' AND expires_at_ms > ?`,
  );
  const expireStmt = db.prepare(
    `UPDATE approvals SET state = 'expired', decided_at_ms = ?
       WHERE approval_id = ? AND state = 'pending' AND (expires_at_ms <= ? OR ? = 1)`,
  );
  const messageStmt = db.prepare(
    "UPDATE approvals SET message_id = ? WHERE approval_id = ? AND message_id IS NULL",
  );
  const execStmt = db.prepare(
    `UPDATE approvals SET exec_status = ?, exec_ref = ?, exec_code = ?
       WHERE approval_id = ? AND state = 'approved' AND (exec_status IS NULL OR exec_status = 'executing')`,
  );
  const dueStmt = db.prepare(
    `${SELECT} WHERE state = 'pending' AND expires_at_ms <= ? ORDER BY created_at_ms, approval_id LIMIT ?`,
  );
  const unfinishedStmt = db.prepare(
    `${SELECT} WHERE state = 'approved' AND (exec_status IS NULL OR exec_status = 'executing')
       ORDER BY created_at_ms, approval_id LIMIT ?`,
  );
  const pendingStmt = db.prepare(
    `${SELECT} WHERE state = 'pending' ORDER BY created_at_ms, approval_id LIMIT ?`,
  );

  const guard = <T>(what: string, fn: () => Result<T>): Result<T> => {
    if (!db.open) return err("approval.store_closed", "the approval store is closed");
    try {
      return fn();
    } catch (e: unknown) {
      return err("approval.store_failed", `approval store ${what} failed`, { cause: cause(e) });
    }
  };

  const read = (stmt: Database.Statement, key: string): Result<ApprovalRow | undefined> => {
    const raw: unknown = stmt.get(key);
    if (raw === undefined) return ok(undefined);
    const row = toRow(raw);
    return row === undefined
      ? err("approval.store_corrupt", "an approval row is unreadable")
      : ok(row);
  };

  const readMany = (rows: unknown[]): Result<ApprovalRow[]> => {
    const out: ApprovalRow[] = [];
    for (const raw of rows) {
      const row = toRow(raw);
      if (row === undefined) return err("approval.store_corrupt", "an approval row is unreadable");
      out.push(row);
    }
    return ok(out);
  };

  const validMs = (v: number): boolean => Number.isSafeInteger(v) && v >= 0;
  const validLimit = (v: number): boolean => Number.isSafeInteger(v) && v >= 1 && v <= 10_000;

  const transitioned = (approvalId: string, changes: number): Result<Transition> => {
    const row = read(getStmt, approvalId);
    if (!row.ok) return row;
    if (row.value === undefined) return err("approval.not_found", "no such approval");
    return ok({ won: changes === 1, row: row.value });
  };

  const store: ApprovalStore = {
    path: opts.path,
    create: (input) =>
      guard("create", () => {
        const p = createSchema.safeParse(input);
        if (!p.success || p.data.expiresAtMs <= p.data.createdAtMs) {
          return err("approval.invalid_input", "invalid approval");
        }
        const v = p.data;
        insertStmt.run(
          v.approvalId,
          v.attemptId,
          v.sessionId,
          v.tool,
          v.argsHash,
          v.ruleId,
          v.callbackNonce,
          v.createdAtMs,
          v.expiresAtMs,
        );
        const row = read(getStmt, v.approvalId);
        if (!row.ok) return row;
        return row.value === undefined
          ? err("approval.store_failed", "the approval was not written")
          : ok(row.value);
      }),
    get: (approvalId) =>
      guard("read", () =>
        id.safeParse(approvalId).success ? read(getStmt, approvalId) : ok(undefined),
      ),
    getByNonce: (nonce) =>
      guard("read", () => (NONCE_RE.test(nonce) ? read(nonceStmt, nonce) : ok(undefined))),
    getByAttempt: (attemptId) =>
      guard("read", () =>
        id.safeParse(attemptId).success ? read(attemptStmt, attemptId) : ok(undefined),
      ),
    setMessageId: (approvalId, messageId) =>
      guard("update", () => {
        if (!Number.isSafeInteger(messageId) || messageId < 1) {
          return err("approval.invalid_input", "invalid message id");
        }
        messageStmt.run(messageId, approvalId);
        return ok(null);
      }),
    decide: (approvalId, decision, decidedBy, nowMs) =>
      guard("decide", () => {
        if (
          (decision !== "approved" && decision !== "rejected") ||
          !DECIDED_BY_RE.test(decidedBy) ||
          !validMs(nowMs)
        ) {
          return err("approval.invalid_input", "invalid decision");
        }
        const info = decideStmt.run(decision, nowMs, decidedBy, approvalId, nowMs);
        return transitioned(approvalId, info.changes);
      }),
    expire: (approvalId, nowMs, force = false) =>
      guard("expire", () => {
        if (!validMs(nowMs)) return err("approval.invalid_input", "invalid time");
        const info = expireStmt.run(nowMs, approvalId, nowMs, force ? 1 : 0);
        return transitioned(approvalId, info.changes);
      }),
    listDue: (nowMs, limit = 100) =>
      guard("read", () => {
        if (!validMs(nowMs) || !validLimit(limit)) {
          return err("approval.invalid_input", "invalid query");
        }
        return readMany(dueStmt.all(nowMs, limit));
      }),
    listPending: (limit = 1000) =>
      guard("read", () => {
        if (!validLimit(limit)) return err("approval.invalid_input", "invalid query");
        return readMany(pendingStmt.all(limit));
      }),
    listUnfinished: (limit = 1000) =>
      guard("read", () => {
        if (!validLimit(limit)) return err("approval.invalid_input", "invalid query");
        return readMany(unfinishedStmt.all(limit));
      }),
    setExecution: (approvalId, execution) =>
      guard("update", () => {
        if (
          !EXECUTION_STATUSES.includes(execution.status) ||
          (execution.upstreamRef !== undefined && !ID_RE.test(execution.upstreamRef)) ||
          (execution.code !== undefined && !CODE_RE.test(execution.code))
        ) {
          return err("approval.invalid_input", "invalid execution status");
        }
        const info = execStmt.run(
          execution.status,
          execution.upstreamRef ?? null,
          execution.code ?? null,
          approvalId,
        );
        return info.changes === 1
          ? ok(null)
          : err("approval.not_approved", "only an approved action has an execution status");
      }),
    close: () => {
      if (db.open) db.close();
    },
  };
  return ok(store);
}
