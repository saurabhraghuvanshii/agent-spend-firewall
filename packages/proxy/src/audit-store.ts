/**
 * SQLite adapter for the hash-chained audit log (T005).
 *
 * - Embedded file via raw `better-sqlite3` (WAL, busy_timeout); no server, no ORM.
 * - Append-only: `BEFORE UPDATE` / `BEFORE DELETE` triggers abort. Outcomes are separate chained records.
 * - Every append runs in a `BEGIN IMMEDIATE` transaction that reads the head, builds the record with
 *   `@asf/core` `buildRecord`, and inserts it, so concurrent writers (other connections/processes) cannot fork the chain.
 * - Write methods never throw: every failure becomes `{ ok: false }` so the proxy can fail closed.
 * - Error messages never include argument values or the agent's reason.
 * - Record ids / attempt ids are restricted to `[A-Za-z0-9_.:-]{1,128}` (input, generator output and rows read
 *   back), so they are safe to print and cannot carry control characters or PII.
 * - Timestamps: a caller-supplied `ts` may not be earlier than the chain head nor more than
 *   `MAX_FUTURE_SKEW_MS` ahead of `clock()`. A clock-derived `ts` earlier than the head (e.g. an NTP step back)
 *   is clamped to the head's `ts` — never rejected, so a clock regression cannot stop money-path auditing.
 * - On open, the append-only triggers are compared to their expected SQL. A writable open with a missing-but-
 *   replaced, altered or extra trigger on `audit_log` fails (`audit.open_failed`); a read-only open reports it
 *   in `warnings` (the chain itself is still verified by hashes).
 */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { z } from "zod";
import {
  buildRecord,
  canonicalJson,
  err,
  IDEMPOTENCY_KEY_RE,
  ok,
  redact,
  redactText,
  verifyChain,
  AUDIT_APPROVAL_DECISIONS,
  AUDIT_VERIFICATION_METHODS,
  AUDIT_VERIFICATION_RESULTS,
  AUDIT_VERIFICATION_TRIGGERS,
  type AuditApprovalBody,
  type AuditApprovalDecision,
  type AuditAttemptBody,
  type AuditVerificationBody,
  type AuditVerificationMethod,
  type AuditVerificationResult,
  type AuditVerificationTrigger,
  type AuditBody,
  type AuditOutcomeBody,
  type AuditRecord,
  type FirewallErrorDetail,
  type Hasher,
  type InvalidAuditRow,
  type JsonValue,
  type Result,
  type VerifyResult,
} from "@asf/core";
import { redactionSafeUuid } from "./ids.js";
import { nodeHasher } from "./node-hasher.js";

export const AUDIT_DECISIONS = ["allow", "deny", "require_approval", "transform"] as const;
export const AUDIT_OUTCOMES = [
  "success",
  "upstream_error",
  "timeout",
  "denied",
  "not_forwarded",
] as const;

export interface RecordAttemptInput {
  sessionId: string;
  tool: string;
  /**
   * Tool arguments exactly as FORWARDED (post-transform; `reason` stripped). Redacted before hashing. History /
   * velocity read these (D-026).
   */
  args: unknown;
  /**
   * The agent's ORIGINAL args, only when a `transform` changed them. Redacted the same way as `args` and stored as
   * `originalArgsRedacted`. If they can't be canonicalised the whole attempt fails like invalid `args` would.
   */
  originalArgs?: unknown;
  reason: string;
  decision: AuditDecisionInput;
  matchedRules: readonly string[];
  /**
   * Opaque approver id: `telegram:<numeric user id>` or `dashboard:<slug>`. Never an email address or
   * phone number — the audit log is append-only, so PII written here can never be erased.
   */
  approver?: string;
  /**
   * Idempotency key of the forwarded args (T009, `idempotency.ts`): exactly 64 lowercase hex chars
   * (`IDEMPOTENCY_KEY_RE`), else `audit.invalid_input`. Stored verbatim and hashed; omitted when absent. Not stored
   * on an `audit.invalid_args` trail row (its args were not recorded).
   */
  idempotencyKey?: string;
  /**
   * T010: id of the earlier attempt this one retries. Checked in the write transaction: the original must exist, be
   * an attempt of the same tool, have a LATEST verification `not_happened`, not be a retry itself and not have been
   * retried already ⇒ else `audit.invalid_retry_of` (nothing written). Hashed only when present.
   */
  retryOf?: string;
  /** Defaults to `idGen()`. Must match `recordIdSchema` (T010: the pipeline pre-generates it for the notes marker). */
  id?: string;
  /** ISO-8601; defaults to `clock().toISOString()`. */
  ts?: string;
}

/** T010: a verification of an attempt whose outcome left it unclear whether upstream applied it. */
export interface RecordVerificationInput {
  attemptId: string;
  trigger: AuditVerificationTrigger;
  result: AuditVerificationResult;
  method: AuditVerificationMethod;
  /** True iff a human must settle it (always true for `unknown` written by the pipeline). */
  needsHuman: boolean;
  upstreamRef?: string;
  errorCode?: string;
  /** Required iff `trigger === "human"` (`approverSchema`); forbidden otherwise. */
  resolver?: string;
  id?: string;
  ts?: string;
}

/**
 * T011: the decision on a `require_approval` attempt. Checked in the write transaction: the attempt exists, has
 * decision `require_approval`, is not a retry, has no outcome and no approval yet ⇒ else `audit.invalid_approval`.
 */
export interface RecordApprovalInput {
  attemptId: string;
  approvalId: string;
  decision: AuditApprovalDecision;
  /** Required for `approved` / `rejected` (`approverSchema`), forbidden for `expired`. */
  approver?: string;
  id?: string;
  ts?: string;
}

export interface RecordOutcomeInput {
  attemptId: string;
  outcome: AuditOutcomeInput;
  errorCode?: string;
  /** Integer milliseconds, >= 0. */
  latencyMs: number;
  upstreamRef?: string;
  id?: string;
  ts?: string;
}

export type AuditDecisionInput = (typeof AUDIT_DECISIONS)[number];
export type AuditAttemptRecord = Extract<AuditRecord, { kind: "attempt" }>;
export type AuditOutcomeRecord = Extract<AuditRecord, { kind: "outcome" }>;
export type AuditVerificationRecord = Extract<AuditRecord, { kind: "verification" }>;
export type AuditApprovalRecord = Extract<AuditRecord, { kind: "approval" }>;

/**
 * An attempt joined with its outcome record, if one has been written, its LATEST verification (T010), if any, and
 * its approval decision (T011), if any.
 */
export interface AuditActivity {
  readonly attempt: AuditAttemptRecord;
  readonly outcome?: AuditOutcomeRecord;
  readonly verification?: AuditVerificationRecord;
  readonly approval?: AuditApprovalRecord;
}

/** Default cap on rows `readActivitySince` scans before failing closed. */
export const DEFAULT_MAX_ACTIVITY_ROWS = 10_000;
/** Default cap on rows the full scans (`readUnsettled`, `listNeedsHuman`) read before failing closed. */
export const DEFAULT_MAX_SCAN_ROWS = 100_000;
export type AuditOutcomeInput = (typeof AUDIT_OUTCOMES)[number];

export interface AuditStore {
  readonly path: string;
  readonly readonly: boolean;
  /** Non-fatal integrity warnings found at open (read-only stores only, e.g. altered triggers). */
  readonly warnings: readonly string[];
  /** Append an attempt record. Call *before* forwarding a money action. */
  recordAttempt(input: RecordAttemptInput): Result<AuditRecord>;
  /**
   * Append the outcome of an existing attempt. At most one outcome per attempt. T011: a `require_approval` attempt
   * (or a retry of one) may only get a sent outcome (`success` / `upstream_error` / `timeout`) after an `approved`
   * record; after `rejected` / `expired` only `not_forwarded` ⇒ else `audit.inconsistent_outcome`.
   */
  recordOutcome(input: RecordOutcomeInput): Result<AuditRecord>;
  /** T011: append the approval decision of a `require_approval` attempt (see `RecordApprovalInput`). */
  recordApproval(input: RecordApprovalInput): Result<AuditRecord>;
  /**
   * T011: one attempt joined with its outcome, latest verification and approval (indexed lookups), `undefined` if no
   * attempt has that id. Any unreadable / inconsistent row ⇒ `err`.
   */
  readAttempt(attemptId: string): Result<AuditActivity | undefined>;
  /** All rows ordered by seq; unparseable / inconsistent rows become `{ invalid: true, seq }`. */
  readAll(): Result<Array<AuditRecord | InvalidAuditRow>>;
  /**
   * Activity in the window `[sinceMs, ∞)` for history / velocity checks (T007): every attempt whose own `ts`, or
   * whose outcome's `ts`, is at or after `sinceMs`, each paired with its outcome (if any), ordered by attempt seq.
   *
   * Scans newest → oldest and stops at the first row older than `sinceMs` (record `ts` is non-decreasing by seq:
   * appends reject backdated caller timestamps and clamp clock regressions). Timestamps are compared as parsed
   * epoch ms, never as strings. Reads in one transaction (consistent snapshot).
   *
   * Fails closed (`err`): unreadable / non-canonical row or unparseable `ts` in the scanned range, an outcome whose
   * attempt is missing or not earlier in the chain, a duplicate id / outcome, more than `maxActivityRows` rows in
   * range, a non-finite `sinceMs`, or any read failure. Hashes are NOT re-verified here (use `verify()`).
   */
  readActivitySince(sinceMs: number): Result<AuditActivity[]>;
  /**
   * T010: append a verification record. Checked in the write transaction: the attempt exists, is not a `deny`, has an
   * outcome, and its latest verification (if any) is `unknown` (`happened` / `not_happened` are final) ⇒ else
   * `audit.invalid_verification` (nothing written).
   */
  recordVerification(input: RecordVerificationInput): Result<AuditRecord>;
  /**
   * T010: every UNSETTLED money action in the whole log (scans ALL rows, oldest first, at most `maxScanRows` ⇒ else
   * `err` `audit.scan_too_large`; any unreadable row ⇒ `err`), ordered by attempt seq:
   * - `open`: no outcome and possibly sent (orphaned by a crash): decision allow / transform, a `require_approval`
   *   attempt with an `approved` record, or a retry of one;
   * - `staleApprovals` (T011): `require_approval` attempts (not retries) with no outcome and no `approved` record —
   *   still pending (no record) or decided `rejected` / `expired` without the terminal outcome;
   * - `unsettled`: decision allow / transform / require_approval, outcome `timeout` / `upstream_error`, and no
   *   verification or a latest verification `unknown`.
   */
  readUnsettled(): Result<{
    open: AuditActivity[];
    unsettled: AuditActivity[];
    staleApprovals: AuditActivity[];
  }>;
  /** T010: actions whose latest verification is `unknown` (flagged for a human), full scan like `readUnsettled`. */
  listNeedsHuman(): Result<AuditActivity[]>;
  /** `verifyChain` over `readAll()`. `err` only if the DB cannot be read. */
  verify(): Result<VerifyResult>;
  /** Idempotent. */
  close(): void;
}

export interface OpenAuditStoreOptions {
  /** File path (parent directory is created for writable stores) or `":memory:"`. */
  path: string;
  hasher?: Hasher;
  clock?: () => Date;
  idGen?: () => string;
  /** Open read-only; the file must already exist and contain the audit table. */
  readonly?: boolean;
  /** SQLite busy timeout in ms (default 5000). */
  busyTimeoutMs?: number;
  /** Max rows `readActivitySince` may scan (default `DEFAULT_MAX_ACTIVITY_ROWS`); more ⇒ `err`. */
  maxActivityRows?: number;
  /** Max rows `readUnsettled` / `listNeedsHuman` may scan (default `DEFAULT_MAX_SCAN_ROWS`); more ⇒ `err`. */
  maxScanRows?: number;
}

/** Expected trigger SQL exactly as SQLite stores it in `sqlite_master.sql` (no IF NOT EXISTS, no `;`). */
const EXPECTED_TRIGGERS: ReadonlyMap<string, string> = new Map([
  [
    "audit_log_no_update",
    "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log\n" +
      "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END",
  ],
  [
    "audit_log_no_delete",
    "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log\n" +
      "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END",
  ],
]);

const ifNotExists = (sql: string): string =>
  sql.replace(/^CREATE TRIGGER /, "CREATE TRIGGER IF NOT EXISTS ") + ";";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  body_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL UNIQUE,
  hash TEXT NOT NULL UNIQUE
);
${[...EXPECTED_TRIGGERS.values()].map(ifNotExists).join("\n")}
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_one_outcome_per_attempt
  ON audit_log (json_extract(body_json, '$.attemptId')) WHERE kind = 'outcome';
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_one_approval_per_attempt
  ON audit_log (json_extract(body_json, '$.attemptId')) WHERE kind = 'approval';
`;

// ---------- input validation (boundary) ----------

const nonEmpty = z.string().min(1);
const isoTs = z.iso.datetime({ offset: true });

/** Caller-supplied `ts` may be at most this far ahead of the store clock. */
export const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

/** Record id / attempt id: printable ASCII token (UUIDs, `att-1`, `rfnd_x:1`). Stored and printed verbatim. */
export const recordIdSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/);

/**
 * Opaque approver id from a whitelisted channel: `telegram:<numeric user id, 1-20 digits>` or
 * `dashboard:<[a-z0-9_-]{1,32}>`. Must never be an email address or phone number (no PII in the
 * append-only log). Stored verbatim (never redacted).
 */
export const approverSchema = z
  .string()
  .regex(/^(?:telegram:[0-9]{1,20}|dashboard:[a-z0-9_-]{1,32})$/);
/** Upstream resource id, e.g. `rfnd_ABC123xyz` or a UUID. Stored verbatim. */
export const upstreamRefSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/);
/** Idempotency key: 64 lowercase hex chars (core `IDEMPOTENCY_KEY_RE`). */
export const idempotencyKeySchema = z.string().regex(IDEMPOTENCY_KEY_RE);
/** Lowercase machine code, e.g. `upstream.timeout`, `bad_request_error`. Stored verbatim. */
export const errorCodeSchema = z.string().regex(/^[a-z0-9_.:-]{1,64}$/);

const attemptInputSchema = z.object({
  sessionId: nonEmpty,
  tool: nonEmpty,
  args: z.unknown(),
  originalArgs: z.unknown().optional(),
  reason: z.string(),
  decision: z.enum(AUDIT_DECISIONS),
  matchedRules: z.array(z.string()),
  approver: approverSchema.optional(),
  idempotencyKey: idempotencyKeySchema.optional(),
  retryOf: recordIdSchema.optional(),
  id: recordIdSchema.optional(),
  ts: isoTs.optional(),
});

const verificationInputSchema = z
  .object({
    attemptId: recordIdSchema,
    trigger: z.enum(AUDIT_VERIFICATION_TRIGGERS),
    result: z.enum(AUDIT_VERIFICATION_RESULTS),
    method: z.enum(AUDIT_VERIFICATION_METHODS),
    needsHuman: z.boolean(),
    upstreamRef: z
      .string()
      .regex(/^[A-Za-z0-9_.:-]{1,128}$/)
      .optional(),
    errorCode: z
      .string()
      .regex(/^[a-z0-9_.:-]{1,64}$/)
      .optional(),
    resolver: approverSchema.optional(),
    id: recordIdSchema.optional(),
    ts: isoTs.optional(),
  })
  .refine((v) => (v.trigger === "human") === (v.resolver !== undefined), {
    message: "resolver is required iff trigger is human",
    path: ["resolver"],
  });

const approvalInputSchema = z
  .object({
    attemptId: recordIdSchema,
    approvalId: recordIdSchema,
    decision: z.enum(AUDIT_APPROVAL_DECISIONS),
    approver: approverSchema.optional(),
    id: recordIdSchema.optional(),
    ts: isoTs.optional(),
  })
  .refine((v) => (v.decision === "expired") === (v.approver === undefined), {
    message: "approver is required unless the approval expired",
    path: ["approver"],
  });

const outcomeInputSchema = z.object({
  attemptId: recordIdSchema,
  outcome: z.enum(AUDIT_OUTCOMES),
  errorCode: errorCodeSchema.optional(),
  latencyMs: z.int().nonnegative(),
  upstreamRef: upstreamRefSchema.optional(),
  id: recordIdSchema.optional(),
  ts: isoTs.optional(),
});

/** Outcomes allowed after a `deny` attempt: the action was never forwarded. */
const DENY_OUTCOMES: ReadonlySet<AuditOutcomeInput> = new Set(["denied", "not_forwarded"]);

// ---------- stored row validation ----------

/** Structural JSON check without copying (so `__proto__` keys etc. survive exactly as stored). */
function isJsonValue(v: unknown, depth = 0): v is JsonValue {
  if (depth > 256) return false;
  if (v === null || typeof v === "string" || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isSafeInteger(v) && !Object.is(v, -0);
  if (typeof v !== "object") return false;
  if (Array.isArray(v)) return v.every((x) => isJsonValue(x, depth + 1));
  const proto: unknown = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) return false;
  return Object.values(v).every((x) => isJsonValue(x, depth + 1));
}

const jsonValueSchema = z.custom<JsonValue>((v) => isJsonValue(v));
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

// strictObject: an extra key smuggled into body_json must not be silently dropped (it would be unhashed).
const storedAttemptSchema = z.strictObject({
  kind: z.literal("attempt"),
  id: recordIdSchema,
  ts: z.string(),
  sessionId: z.string(),
  tool: z.string(),
  argsRedacted: jsonValueSchema,
  originalArgsRedacted: jsonValueSchema.optional(),
  reason: z.string(),
  decision: z.enum(AUDIT_DECISIONS),
  matchedRules: z.array(z.string()),
  approver: z.string().optional(),
  // Legacy rows have no key; a present key must be well-formed (core verify reports it otherwise).
  idempotencyKey: idempotencyKeySchema.optional(),
  retryOf: recordIdSchema.optional(),
});

const storedOutcomeSchema = z.strictObject({
  kind: z.literal("outcome"),
  id: recordIdSchema,
  attemptId: recordIdSchema,
  ts: z.string(),
  outcome: z.enum(AUDIT_OUTCOMES),
  errorCode: z.string().optional(),
  latencyMs: z.int().nonnegative(),
  upstreamRef: z.string().optional(),
});

const storedVerificationSchema = z.strictObject({
  kind: z.literal("verification"),
  id: recordIdSchema,
  attemptId: recordIdSchema,
  ts: z.string(),
  trigger: z.enum(AUDIT_VERIFICATION_TRIGGERS),
  result: z.enum(AUDIT_VERIFICATION_RESULTS),
  method: z.enum(AUDIT_VERIFICATION_METHODS),
  needsHuman: z.boolean(),
  upstreamRef: z.string().optional(),
  errorCode: z.string().optional(),
  resolver: z.string().optional(),
});

const storedApprovalSchema = z.strictObject({
  kind: z.literal("approval"),
  id: recordIdSchema,
  attemptId: recordIdSchema,
  ts: z.string(),
  approvalId: z.string(),
  decision: z.enum(AUDIT_APPROVAL_DECISIONS),
  approver: z.string().optional(),
});

const storedBodySchema = z.discriminatedUnion("kind", [
  storedAttemptSchema,
  storedOutcomeSchema,
  storedVerificationSchema,
  storedApprovalSchema,
]);

const rowSchema = z.object({
  seq: z.int().positive(),
  id: z.string(),
  kind: z.string(),
  body_json: z.string(),
  prev_hash: hex64,
  hash: hex64,
});

type StoredBody = z.infer<typeof storedBodySchema>;

/** Rebuild a core body, omitting absent optionals (exactOptionalPropertyTypes). */
function toCoreBody(b: StoredBody): AuditBody {
  if (b.kind === "attempt") {
    const body: AuditAttemptBody = {
      kind: "attempt",
      id: b.id,
      ts: b.ts,
      sessionId: b.sessionId,
      tool: b.tool,
      argsRedacted: b.argsRedacted,
      reason: b.reason,
      decision: b.decision,
      matchedRules: b.matchedRules,
    };
    if (b.originalArgsRedacted !== undefined) body.originalArgsRedacted = b.originalArgsRedacted;
    if (b.approver !== undefined) body.approver = b.approver;
    if (b.idempotencyKey !== undefined) body.idempotencyKey = b.idempotencyKey;
    if (b.retryOf !== undefined) body.retryOf = b.retryOf;
    return body;
  }
  if (b.kind === "verification") {
    const v: AuditVerificationBody = {
      kind: "verification",
      id: b.id,
      attemptId: b.attemptId,
      ts: b.ts,
      trigger: b.trigger,
      result: b.result,
      method: b.method,
      needsHuman: b.needsHuman,
    };
    if (b.upstreamRef !== undefined) v.upstreamRef = b.upstreamRef;
    if (b.errorCode !== undefined) v.errorCode = b.errorCode;
    if (b.resolver !== undefined) v.resolver = b.resolver;
    return v;
  }
  if (b.kind === "approval") {
    const a: AuditApprovalBody = {
      kind: "approval",
      id: b.id,
      attemptId: b.attemptId,
      ts: b.ts,
      approvalId: b.approvalId,
      decision: b.decision,
    };
    if (b.approver !== undefined) a.approver = b.approver;
    return a;
  }
  const body: AuditOutcomeBody = {
    kind: "outcome",
    id: b.id,
    attemptId: b.attemptId,
    ts: b.ts,
    outcome: b.outcome,
    latencyMs: b.latencyMs,
  };
  if (b.errorCode !== undefined) body.errorCode = b.errorCode;
  if (b.upstreamRef !== undefined) body.upstreamRef = b.upstreamRef;
  return body;
}

function parseRow(raw: unknown, fallbackSeq: number): AuditRecord | InvalidAuditRow {
  const row = rowSchema.safeParse(raw);
  if (!row.success) {
    const seq =
      typeof raw === "object" && raw !== null && "seq" in raw && typeof raw.seq === "number"
        ? raw.seq
        : fallbackSeq;
    return { invalid: true, seq };
  }
  const { seq, id, kind, body_json, prev_hash, hash } = row.data;
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(body_json);
  } catch {
    // Unparseable body is reported as an invalid row (a verify break), not swallowed.
    return { invalid: true, seq };
  }
  const body = storedBodySchema.safeParse(parsedJson);
  if (!body.success) return { invalid: true, seq };
  if (body.data.id !== id || body.data.kind !== kind) return { invalid: true, seq };
  // The stored bytes must be exactly the canonical encoding. Otherwise duplicate keys (SQLite's
  // json_extract sees the first, JSON.parse the last) or whitespace edits could pass the hash check.
  const canon = canonicalJson(parsedJson);
  if (!canon.ok || canon.value !== body_json) return { invalid: true, seq };
  return { ...toCoreBody(body.data), seq, prevHash: prev_hash, hash };
}

// ---------- helpers ----------

function describeError(e: unknown): Record<string, FirewallErrorDetail> {
  if (e instanceof Database.SqliteError) return { sqliteCode: e.code, cause: e.message };
  if (e instanceof Error) return { cause: `${e.name}: ${e.message}` };
  return { cause: "non-error thrown" };
}

function zodIssuePaths(e: z.ZodError): string {
  // Paths only — never the offending values.
  return e.issues.map((i) => `${i.path.join(".") || "$"}: ${i.code}`).join("; ");
}

interface HeadRow {
  seq: number;
  hash: string;
  body_json: string;
}

const headRowSchema = z.object({
  seq: z.int().positive(),
  hash: z.string(),
  body_json: z.string(),
});
const tsOnlySchema = z.object({ ts: isoTs });
const attemptToolSchema = z.object({
  tool: z.string(),
  decision: z.enum(AUDIT_DECISIONS),
  retryOf: recordIdSchema.optional(),
});
const verificationResultSchema = z.object({ result: z.enum(AUDIT_VERIFICATION_RESULTS) });
const approvalDecisionSchema = z.object({ decision: z.enum(AUDIT_APPROVAL_DECISIONS) });

/** Outcomes meaning the action was (or may have been) sent upstream. */
const SENT_OUTCOMES: ReadonlySet<AuditOutcomeInput> = new Set([
  "success",
  "upstream_error",
  "timeout",
]);
const bodyJsonRowSchema = z.object({ body_json: z.string() });
const tableInfoRowSchema = z.object({ name: z.string() });
const triggerRowSchema = z.object({ name: z.string(), sql: z.string().nullable() });

const normaliseSql = (sql: string): string => sql.replace(/\s+/g, " ").trim();

const REQUIRED_COLUMNS: readonly string[] = ["seq", "id", "kind", "body_json", "prev_hash", "hash"];

/** Parse a JSON string through a zod schema; `null` if unparseable or not matching. */
function parseJsonAs<T>(schema: z.ZodType<T>, text: string): T | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    // Callers treat `null` as "row unreadable" and fail closed.
    return null;
  }
  const r = schema.safeParse(v);
  return r.success ? r.data : null;
}

interface AppendRequest {
  body: AuditBody;
  /**
   * `ts` came from the caller: reject if earlier than the head record. Otherwise it came from the store
   * clock and is clamped up to the head's `ts` on a clock regression.
   */
  callerTs: boolean;
}

interface ResolvedTs {
  ts: string;
  callerTs: boolean;
}

// ---------- store ----------

function joinActivity(
  attempt: AuditAttemptRecord,
  outcome: AuditOutcomeRecord | undefined,
  verification: AuditVerificationRecord | undefined,
  approval?: AuditApprovalRecord,
): AuditActivity {
  return {
    attempt,
    ...(outcome === undefined ? {} : { outcome }),
    ...(verification === undefined ? {} : { verification }),
    ...(approval === undefined ? {} : { approval }),
  };
}

export function openAuditStore(opts: OpenAuditStoreOptions): Result<AuditStore> {
  const hasher = opts.hasher ?? nodeHasher;
  const clock = opts.clock ?? (() => new Date());
  const idGen = opts.idGen ?? (() => redactionSafeUuid());
  const isReadonly = opts.readonly ?? false;
  const busyTimeoutMs = opts.busyTimeoutMs ?? 5000;
  const maxActivityRows = opts.maxActivityRows ?? DEFAULT_MAX_ACTIVITY_ROWS;
  if (!Number.isSafeInteger(maxActivityRows) || maxActivityRows < 1) {
    return err("audit.open_failed", "maxActivityRows must be a positive integer");
  }
  const maxScanRows = opts.maxScanRows ?? DEFAULT_MAX_SCAN_ROWS;
  if (!Number.isSafeInteger(maxScanRows) || maxScanRows < 1) {
    return err("audit.open_failed", "maxScanRows must be a positive integer");
  }

  let db: Database.Database;
  try {
    if (!isReadonly && opts.path !== ":memory:") mkdirSync(dirname(opts.path), { recursive: true });
    db = new Database(opts.path, { readonly: isReadonly, fileMustExist: isReadonly });
  } catch (e: unknown) {
    return err("audit.open_failed", "could not open audit database", describeError(e));
  }

  /** Column names of `audit_log` (empty if the table does not exist). */
  function auditColumns(): Set<string> {
    const rows: unknown[] = db.prepare("PRAGMA table_info(audit_log)").all();
    const names = new Set<string>();
    for (const r of rows) {
      const parsed = tableInfoRowSchema.safeParse(r);
      if (parsed.success) names.add(parsed.data.name);
    }
    return names;
  }

  function missingColumns(cols: Set<string>): string[] {
    return REQUIRED_COLUMNS.filter((c) => !cols.has(c));
  }

  /** Problems with the triggers on `audit_log` (missing, altered, or unexpected extra triggers). */
  function triggerProblems(): string[] {
    const rows: unknown[] = db
      .prepare(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'",
      )
      .all();
    const found = new Map<string, string | null>();
    const problems: string[] = [];
    for (const r of rows) {
      const parsed = triggerRowSchema.safeParse(r);
      if (!parsed.success) {
        problems.push("unreadable trigger row");
        continue;
      }
      found.set(parsed.data.name, parsed.data.sql);
    }
    for (const [name, expected] of EXPECTED_TRIGGERS) {
      const actual = found.get(name);
      if (actual === undefined) problems.push(`trigger ${name} is missing`);
      else if (actual === null || normaliseSql(actual) !== normaliseSql(expected)) {
        problems.push(`trigger ${name} does not match the expected definition`);
      }
    }
    for (const name of found.keys()) {
      if (!EXPECTED_TRIGGERS.has(name)) problems.push(`unexpected trigger ${name} on audit_log`);
    }
    return problems;
  }

  let headStmt: Database.Statement;
  let allStmt: Database.Statement;
  let insertStmt: Database.Statement | null;
  let attemptBodyStmt: Database.Statement;
  let outcomeExistsStmt: Database.Statement;
  let recentStmt: Database.Statement;
  let attemptRowStmt: Database.Statement;
  let outcomeRowStmt: Database.Statement;
  let latestVerificationStmt: Database.Statement;
  let retriedStmt: Database.Statement;
  let approvalStmt: Database.Statement;
  let approvalRowStmt: Database.Statement;
  let latestVerificationRowStmt: Database.Statement;
  let ascStmt: Database.Statement;
  let warnings: string[] = [];
  try {
    db.pragma(`busy_timeout = ${String(Math.max(0, Math.trunc(busyTimeoutMs)))}`);
    const before = auditColumns();
    if (isReadonly && before.size === 0) {
      db.close();
      return err("audit.open_failed", "database has no audit_log table");
    }
    // Refuse a pre-existing table with the wrong shape before touching the file.
    if (before.size > 0 && missingColumns(before).length > 0) {
      db.close();
      return err("audit.open_failed", "audit_log table has an unexpected schema", {
        missingColumns: missingColumns(before).join(","),
      });
    }
    if (!isReadonly) {
      db.pragma("journal_mode = WAL");
      // Audit durability over throughput: fsync on every commit.
      db.pragma("synchronous = FULL");
      db.exec(SCHEMA_SQL);
      const after = missingColumns(auditColumns());
      if (after.length > 0) {
        db.close();
        return err("audit.open_failed", "audit_log table has an unexpected schema", {
          missingColumns: after.join(","),
        });
      }
      const problems = triggerProblems();
      if (problems.length > 0) {
        db.close();
        return err("audit.open_failed", "audit_log append-only triggers are not as expected", {
          triggers: problems.join("; "),
        });
      }
    } else {
      warnings = triggerProblems();
    }

    headStmt = db.prepare("SELECT seq, hash, body_json FROM audit_log ORDER BY seq DESC LIMIT 1");
    allStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log ORDER BY seq ASC",
    );
    insertStmt = isReadonly
      ? null
      : db.prepare(
          "INSERT INTO audit_log (seq, id, kind, body_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
        );
    attemptBodyStmt = db.prepare(
      "SELECT body_json FROM audit_log WHERE id = ? AND kind = 'attempt'",
    );
    outcomeExistsStmt = db.prepare(
      "SELECT 1 AS present FROM audit_log WHERE kind = 'outcome' AND json_extract(body_json, '$.attemptId') = ?",
    );
    recentStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log ORDER BY seq DESC",
    );
    attemptRowStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log WHERE id = ?",
    );
    outcomeRowStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log WHERE kind = 'outcome' AND json_extract(body_json, '$.attemptId') = ?",
    );
    latestVerificationStmt = db.prepare(
      "SELECT body_json FROM audit_log WHERE kind = 'verification' AND json_extract(body_json, '$.attemptId') = ? ORDER BY seq DESC LIMIT 1",
    );
    retriedStmt = db.prepare(
      "SELECT 1 AS present FROM audit_log WHERE kind = 'attempt' AND json_extract(body_json, '$.retryOf') = ? LIMIT 1",
    );
    approvalStmt = db.prepare(
      "SELECT body_json FROM audit_log WHERE kind = 'approval' AND json_extract(body_json, '$.attemptId') = ?",
    );
    approvalRowStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log WHERE kind = 'approval' AND json_extract(body_json, '$.attemptId') = ?",
    );
    latestVerificationRowStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log WHERE kind = 'verification' AND json_extract(body_json, '$.attemptId') = ? ORDER BY seq DESC LIMIT 1",
    );
    ascStmt = db.prepare(
      "SELECT seq, id, kind, body_json, prev_hash, hash FROM audit_log ORDER BY seq ASC",
    );
  } catch (e: unknown) {
    if (db.open) db.close();
    return err("audit.open_failed", "could not initialise audit database", describeError(e));
  }

  function readHead(): Result<HeadRow | null> {
    const raw: unknown = headStmt.get();
    if (raw === undefined) return ok(null);
    const parsed = headRowSchema.safeParse(raw);
    if (!parsed.success) return err("audit.write_failed", "chain head row is malformed");
    return ok(parsed.data);
  }

  /** Latest verification result of `attemptId` (inside a transaction), `undefined` if none, `null` if unreadable. */
  function latestVerificationOf(attemptId: string): AuditVerificationResult | undefined | null {
    const raw: unknown = latestVerificationStmt.get(attemptId);
    if (raw === undefined) return undefined;
    const row = bodyJsonRowSchema.safeParse(raw);
    if (!row.success) return null;
    return parseJsonAs(verificationResultSchema, row.data.body_json)?.result ?? null;
  }

  /** The referenced attempt's tool / decision / retryOf (inside a transaction); `undefined` if absent / unreadable. */
  function attemptInfo(attemptId: string): z.infer<typeof attemptToolSchema> | undefined {
    const raw: unknown = attemptBodyStmt.get(attemptId);
    if (raw === undefined) return undefined;
    const row = bodyJsonRowSchema.safeParse(raw);
    if (!row.success) return undefined;
    return parseJsonAs(attemptToolSchema, row.data.body_json) ?? undefined;
  }

  /** Approval decision of `attemptId` (inside a transaction): `undefined` if none, `null` if unreadable. */
  function approvalDecisionOf(attemptId: string): AuditApprovalDecision | undefined | null {
    const raw: unknown = approvalStmt.get(attemptId);
    if (raw === undefined) return undefined;
    const row = bodyJsonRowSchema.safeParse(raw);
    if (!row.success) return null;
    return parseJsonAs(approvalDecisionSchema, row.data.body_json)?.decision ?? null;
  }

  /** T011 checks for approval records (mirror core `verifyChain`). */
  function checkApprovalRecord(body: AuditBody): Result<null> {
    if (body.kind !== "approval") return ok(null);
    const bad = (why: string): Result<null> =>
      err("audit.invalid_approval", `approval is not allowed: ${why}`);
    const attempt = attemptInfo(body.attemptId);
    if (attempt === undefined) return bad("the attempt does not exist");
    if (attempt.decision !== "require_approval") return bad("the attempt did not require approval");
    if (attempt.retryOf !== undefined) return bad("the attempt is a retry");
    if (outcomeExistsStmt.get(body.attemptId) !== undefined)
      return bad("the attempt has an outcome");
    if (approvalStmt.get(body.attemptId) !== undefined)
      return bad("the attempt is already decided");
    return ok(null);
  }

  /**
   * T011 outcome rule for `require_approval` attempts (inside a transaction): sent outcomes need an `approved` record
   * (a retry: on its original); after `rejected` / `expired` only `not_forwarded`.
   */
  function checkApprovalOutcome(
    attempt: { decision: AuditDecisionInput; retryOf?: string | undefined },
    attemptId: string,
    outcome: AuditOutcomeInput,
  ): Result<null> {
    if (attempt.decision !== "require_approval") return ok(null);
    const decision = approvalDecisionOf(attempt.retryOf ?? attemptId);
    if (decision === null) return err("audit.write_failed", "the approval record is unreadable");
    if (SENT_OUTCOMES.has(outcome) && decision !== "approved") {
      return err(
        "audit.inconsistent_outcome",
        "a require_approval attempt can only be sent after it was approved",
        { decision: attempt.decision, outcome },
      );
    }
    if ((decision === "rejected" || decision === "expired") && outcome !== "not_forwarded") {
      return err(
        "audit.inconsistent_outcome",
        "a rejected or expired approval can only have a not_forwarded outcome",
        { decision: attempt.decision, outcome },
      );
    }
    return ok(null);
  }

  /** T010 checks for an attempt's `retryOf` and for verification records (mirror core `verifyChain`). */
  function checkT010(body: AuditBody): Result<null> {
    if (body.kind === "attempt" && body.retryOf !== undefined) {
      const bad = (why: string): Result<null> =>
        err("audit.invalid_retry_of", `retryOf is not allowed: ${why}`);
      const original = attemptInfo(body.retryOf);
      if (original === undefined) return bad("the original attempt does not exist");
      if (original.tool !== body.tool) return bad("the original attempt is for another tool");
      if (original.retryOf !== undefined) return bad("a retry cannot be retried");
      if (latestVerificationOf(body.retryOf) !== "not_happened") {
        return bad("the original attempt is not verified as not executed");
      }
      if (retriedStmt.get(body.retryOf) !== undefined)
        return bad("the original was already retried");
    }
    if (body.kind === "verification") {
      const bad = (why: string): Result<null> =>
        err("audit.invalid_verification", `verification is not allowed: ${why}`);
      const attempt = attemptInfo(body.attemptId);
      if (attempt === undefined) return bad("the attempt does not exist");
      if (attempt.decision === "deny") return bad("the attempt was denied");
      if (outcomeExistsStmt.get(body.attemptId) === undefined)
        return bad("the attempt has no outcome");
      const prior = latestVerificationOf(body.attemptId);
      if (prior === null) return bad("an earlier verification is unreadable");
      if (prior !== undefined && prior !== "unknown") return bad("the attempt is already settled");
    }
    return ok(null);
  }

  /** Runs inside BEGIN IMMEDIATE. Returning `err` before the insert leaves the DB unchanged. */
  function appendInTx(req: AppendRequest): Result<AuditRecord> {
    const { body } = req;
    const t010 = checkT010(body);
    if (!t010.ok) return t010;
    const t011 = checkApprovalRecord(body);
    if (!t011.ok) return t011;
    if (body.kind === "outcome") {
      const attemptRow: unknown = attemptBodyStmt.get(body.attemptId);
      if (attemptRow === undefined) {
        return err("audit.unknown_attempt", "outcome references no existing attempt");
      }
      if (outcomeExistsStmt.get(body.attemptId) !== undefined) {
        return err("audit.duplicate_outcome", "an outcome is already recorded for this attempt");
      }
      const rowParsed = bodyJsonRowSchema.safeParse(attemptRow);
      const attempt = rowParsed.success
        ? parseJsonAs(attemptToolSchema, rowParsed.data.body_json)
        : null;
      if (attempt === null) return err("audit.write_failed", "referenced attempt is unreadable");
      // A denied action was never forwarded; any other outcome would be a lie in the log.
      if (attempt.decision === "deny" && !DENY_OUTCOMES.has(body.outcome)) {
        return err(
          "audit.inconsistent_outcome",
          "a denied attempt can only have a denied or not_forwarded outcome",
          { decision: attempt.decision, outcome: body.outcome },
        );
      }
      // `require_approval` executes only after an `approved` record (T011).
      const approvalCheck = checkApprovalOutcome(attempt, body.attemptId, body.outcome);
      if (!approvalCheck.ok) return approvalCheck;
    }
    const head = readHead();
    if (!head.ok) return head;
    if (head.value !== null) {
      const headTs = parseJsonAs(tsOnlySchema, head.value.body_json);
      if (headTs === null) return err("audit.write_failed", "chain head timestamp is unreadable");
      if (Date.parse(body.ts) < Date.parse(headTs.ts)) {
        if (req.callerTs) {
          return err("audit.invalid_input", "ts is earlier than the latest audit record", {
            issues: "ts: backdated",
          });
        }
        // Store clock went backwards (e.g. NTP step): keep ts monotonic rather than refusing to audit.
        body.ts = headTs.ts;
      }
    }
    const canon = canonicalJson(body);
    if (!canon.ok) {
      return err("audit.write_failed", "audit body is not canonical JSON", {
        reason: canon.error.code,
      });
    }
    const prev = head.value === null ? null : { seq: head.value.seq, hash: head.value.hash };
    const rec = buildRecord(hasher, prev, body);
    if (!rec.ok) {
      return err("audit.write_failed", "could not build chained record", {
        reason: rec.error.code,
      });
    }
    if (insertStmt === null) return err("audit.write_failed", "audit store is read-only");
    const info = insertStmt.run(
      rec.value.seq,
      body.id,
      body.kind,
      canon.value,
      rec.value.prevHash,
      rec.value.hash,
    );
    if (info.changes !== 1) {
      // e.g. a foreign trigger silently ignoring the insert: never report an unwritten record as written.
      throw new Error("audit insert did not write exactly one row");
    }
    return ok(rec.value);
  }

  const appendTx = db.transaction(appendInTx);

  /** Parsed record by row, or a fail-closed error message. */
  function lookupRecord(
    stmt: Database.Statement,
    key: string,
  ): AuditRecord | "missing" | "unreadable" {
    const raw: unknown = stmt.get(key);
    if (raw === undefined) return "missing";
    const rec = parseRow(raw, 0);
    if ("invalid" in rec || !Number.isFinite(Date.parse(rec.ts))) return "unreadable";
    return rec;
  }

  /** Runs inside a (deferred) read transaction. See `AuditStore.readActivitySince`. */
  function readActivityInTx(sinceMs: number): Result<AuditActivity[]> {
    const attempts = new Map<string, AuditAttemptRecord>();
    const outcomes = new Map<string, AuditOutcomeRecord>();
    /** Latest (first seen newest-first) verification per attempt. */
    const verifications = new Map<string, AuditVerificationRecord>();
    const approvals = new Map<string, AuditApprovalRecord>();
    const invalid = (message: string, seq: number): Result<AuditActivity[]> =>
      err("audit.activity_invalid", message, { seq });
    let scanned = 0;
    // Iterate (not .all()) so only the window is read; collect, then look up older attempts after the cursor closes.
    for (const raw of recentStmt.iterate() as Iterable<unknown>) {
      scanned++;
      if (scanned > maxActivityRows) {
        return err("audit.activity_too_large", "too many audit records in the activity window", {
          maxRows: maxActivityRows,
        });
      }
      const rec = parseRow(raw, 0);
      if ("invalid" in rec)
        return invalid("audit record in the activity window is unreadable", rec.seq);
      const ms = Date.parse(rec.ts);
      if (!Number.isFinite(ms))
        return invalid("audit record has an unparseable timestamp", rec.seq);
      if (ms < sinceMs) break;
      if (rec.kind === "attempt") {
        if (attempts.has(rec.id)) return invalid("duplicate attempt id in audit log", rec.seq);
        attempts.set(rec.id, rec);
      } else if (rec.kind === "outcome") {
        if (outcomes.has(rec.attemptId)) return invalid("duplicate outcome in audit log", rec.seq);
        outcomes.set(rec.attemptId, rec);
      } else if (rec.kind === "approval") {
        if (approvals.has(rec.attemptId))
          return invalid("duplicate approval in audit log", rec.seq);
        approvals.set(rec.attemptId, rec);
      } else if (!verifications.has(rec.attemptId)) {
        verifications.set(rec.attemptId, rec);
      }
    }
    const all = new Map(attempts);
    // Outcomes / verifications / approvals in the window for attempts older than the cutoff: indexed lookups.
    for (const [attemptId, later] of [...outcomes, ...verifications, ...approvals]) {
      let attempt = all.get(attemptId);
      if (attempt === undefined) {
        const rec = lookupRecord(attemptRowStmt, attemptId);
        if (rec === "missing") return invalid("record references a missing attempt", later.seq);
        if (rec === "unreadable") return invalid("attempt for a record is unreadable", later.seq);
        if (rec.kind !== "attempt")
          return invalid("record references a non-attempt record", later.seq);
        attempt = rec;
        all.set(attemptId, rec);
      }
      if (attempt.seq >= later.seq) return invalid("record precedes its attempt", later.seq);
    }
    for (const [attemptId, v] of verifications) {
      if (outcomes.has(attemptId)) continue;
      const rec = lookupRecord(outcomeRowStmt, attemptId);
      if (rec === "missing") return invalid("verification of an attempt without outcome", v.seq);
      if (rec === "unreadable" || rec.kind !== "outcome") {
        return invalid("outcome for a verification is unreadable", v.seq);
      }
      if (rec.seq >= v.seq) return invalid("verification precedes its outcome", v.seq);
      outcomes.set(attemptId, rec);
    }
    // Approvals written before the cutoff of attempts in the window (indexed lookup, one per attempt).
    for (const attempt of all.values()) {
      if (attempt.decision !== "require_approval" || approvals.has(attempt.id)) continue;
      const rec = lookupRecord(approvalRowStmt, attempt.id);
      if (rec === "missing") continue;
      if (rec === "unreadable" || rec.kind !== "approval") {
        return invalid("approval of an attempt is unreadable", attempt.seq);
      }
      if (rec.seq <= attempt.seq) return invalid("approval precedes its attempt", rec.seq);
      approvals.set(attempt.id, rec);
    }
    const result: AuditActivity[] = [];
    for (const attempt of [...all.values()].sort((a, b) => a.seq - b.seq)) {
      result.push(
        joinActivity(
          attempt,
          outcomes.get(attempt.id),
          verifications.get(attempt.id),
          approvals.get(attempt.id),
        ),
      );
    }
    return ok(result);
  }

  /** Runs inside a read transaction: a full scan (oldest first), bounded by `maxScanRows`. */
  function scanAllInTx(): Result<AuditActivity[]> {
    const attempts = new Map<string, AuditAttemptRecord>();
    const outcomes = new Map<string, AuditOutcomeRecord>();
    const verifications = new Map<string, AuditVerificationRecord>();
    const approvals = new Map<string, AuditApprovalRecord>();
    let scanned = 0;
    for (const raw of ascStmt.iterate() as Iterable<unknown>) {
      scanned++;
      if (scanned > maxScanRows) {
        return err("audit.scan_too_large", "too many audit records to scan", {
          maxRows: maxScanRows,
        });
      }
      const rec = parseRow(raw, 0);
      if ("invalid" in rec) {
        return err("audit.activity_invalid", "audit record is unreadable", { seq: rec.seq });
      }
      if (rec.kind === "attempt") {
        if (attempts.has(rec.id)) {
          return err("audit.activity_invalid", "duplicate attempt id", { seq: rec.seq });
        }
        attempts.set(rec.id, rec);
        continue;
      }
      if (!attempts.has(rec.attemptId)) {
        return err("audit.activity_invalid", "record references a missing attempt", {
          seq: rec.seq,
        });
      }
      if (rec.kind === "outcome") {
        if (outcomes.has(rec.attemptId)) {
          return err("audit.activity_invalid", "duplicate outcome", { seq: rec.seq });
        }
        outcomes.set(rec.attemptId, rec);
      } else if (rec.kind === "approval") {
        if (approvals.has(rec.attemptId)) {
          return err("audit.activity_invalid", "duplicate approval", { seq: rec.seq });
        }
        approvals.set(rec.attemptId, rec);
      } else {
        verifications.set(rec.attemptId, rec); // ascending ⇒ the last one wins (latest)
      }
    }
    return ok(
      [...attempts.values()].map((a) =>
        joinActivity(a, outcomes.get(a.id), verifications.get(a.id), approvals.get(a.id)),
      ),
    );
  }

  const scanAllTx = db.transaction(scanAllInTx);

  function scanAll(): Result<AuditActivity[]> {
    if (!db.open) return err("audit.read_failed", "audit store is closed");
    try {
      return scanAllTx();
    } catch (e: unknown) {
      return err("audit.read_failed", "could not scan the audit log", describeError(e));
    }
  }

  const readActivityTx = db.transaction(readActivityInTx);

  /** Runs inside a read transaction. See `AuditStore.readAttempt`. */
  function readAttemptInTx(attemptId: string): Result<AuditActivity | undefined> {
    const bad = (message: string): Result<AuditActivity | undefined> =>
      err("audit.activity_invalid", message);
    const attempt = lookupRecord(attemptRowStmt, attemptId);
    if (attempt === "missing") return ok(undefined);
    if (attempt === "unreadable") return bad("attempt record is unreadable");
    if (attempt.kind !== "attempt") return ok(undefined);
    const later = <K extends AuditRecord["kind"]>(
      stmt: Database.Statement,
      kind: K,
    ): Extract<AuditRecord, { kind: K }> | undefined | "bad" => {
      const rec = lookupRecord(stmt, attemptId);
      if (rec === "missing") return undefined;
      if (rec === "unreadable" || rec.kind !== kind || rec.seq <= attempt.seq) return "bad";
      return rec as Extract<AuditRecord, { kind: K }>;
    };
    const outcome = later(outcomeRowStmt, "outcome");
    const verification = later(latestVerificationRowStmt, "verification");
    const approval = later(approvalRowStmt, "approval");
    if (outcome === "bad" || verification === "bad" || approval === "bad") {
      return bad("a record of the attempt is unreadable or out of order");
    }
    return ok(joinActivity(attempt, outcome, verification, approval));
  }

  const readAttemptTx = db.transaction(readAttemptInTx);

  /** Guard + catch-all for write paths: never throws, fails closed. */
  function guardedWrite(fn: () => Result<AuditRecord>): Result<AuditRecord> {
    if (isReadonly) return err("audit.write_failed", "audit store is read-only");
    if (!db.open) return err("audit.write_failed", "audit store is closed");
    try {
      return fn();
    } catch (e: unknown) {
      return err("audit.write_failed", "audit append failed", describeError(e));
    }
  }

  /** Id from caller or injected generator, validated. */
  function resolveId(callerId: string | undefined): Result<string> {
    if (callerId !== undefined) return ok(callerId);
    const id = recordIdSchema.safeParse(idGen());
    if (!id.success) return err("audit.write_failed", "id generator returned an invalid id");
    return ok(id.data);
  }

  /**
   * Ts from caller (format already validated; must not be more than MAX_FUTURE_SKEW_MS ahead of the clock)
   * or from the injected clock, validated.
   */
  function resolveTs(callerTs: string | undefined): Result<ResolvedTs> {
    const d: unknown = clock();
    if (!(d instanceof Date) || Number.isNaN(d.getTime())) {
      return err("audit.write_failed", "clock returned an invalid date");
    }
    if (callerTs !== undefined) {
      if (Date.parse(callerTs) > d.getTime() + MAX_FUTURE_SKEW_MS) {
        return err("audit.invalid_input", "ts is too far in the future", {
          issues: "ts: future_dated",
        });
      }
      return ok({ ts: callerTs, callerTs: true });
    }
    const ts = isoTs.safeParse(d.toISOString());
    if (!ts.success) return err("audit.write_failed", "clock returned an invalid timestamp");
    return ok({ ts: ts.data, callerTs: false });
  }

  /** Validate args as audit JSON and return a detached redacted copy, or the core error. */
  function redactArgs(args: unknown): Result<JsonValue> {
    const argsCanon = canonicalJson(args);
    if (!argsCanon.ok) return argsCanon;
    const argsJson: unknown = JSON.parse(argsCanon.value);
    if (!isJsonValue(argsJson)) return err("audit.args_not_json", "tool args are not JSON");
    return ok(redact(argsJson));
  }

  const store: AuditStore = {
    path: opts.path,
    readonly: isReadonly,
    warnings,

    recordAttempt(input: RecordAttemptInput): Result<AuditRecord> {
      return guardedWrite(() => {
        const parsed = attemptInputSchema.safeParse(input);
        if (!parsed.success) {
          return err("audit.invalid_input", "invalid attempt input", {
            issues: zodIssuePaths(parsed.error),
          });
        }
        const p = parsed.data;
        const id = resolveId(p.id);
        if (!id.ok) return id;
        const ts = resolveTs(p.ts);
        if (!ts.ok) return ts;

        // `originalArgs` (transform only) is validated together with `args`: if either can't be audited, the
        // attempt becomes an invalid-args deny trail and no original args are stored.
        const original = p.originalArgs === undefined ? undefined : redactArgs(p.originalArgs);
        const args = original === undefined || original.ok ? redactArgs(p.args) : original;
        const body: AuditAttemptBody = {
          kind: "attempt",
          id: id.value,
          ts: ts.value.ts,
          sessionId: p.sessionId,
          tool: p.tool,
          argsRedacted: null,
          reason: redactText(p.reason),
          decision: p.decision,
          matchedRules: [...p.matchedRules],
        };
        if (p.approver !== undefined) body.approver = p.approver;
        if (p.retryOf !== undefined) body.retryOf = p.retryOf;

        if (args.ok) {
          body.argsRedacted = args.value;
          if (original?.ok === true) body.originalArgsRedacted = original.value;
          if (p.idempotencyKey !== undefined) body.idempotencyKey = p.idempotencyKey;
          return appendTx.immediate({ body, callerTs: ts.value.callerTs });
        }

        // Invalid args (e.g. float amount): still leave a trail, as a deny, then report the error.
        delete body.retryOf;
        const rawPath = args.error.details?.["path"];
        const path = typeof rawPath === "string" ? redactText(rawPath) : null;
        body.argsRedacted = { _invalid: args.error.code, _path: path };
        body.decision = "deny";
        body.matchedRules = ["audit.invalid_args"];
        const written = appendTx.immediate({ body, callerTs: ts.value.callerTs });
        if (!written.ok) {
          return err("audit.write_failed", "could not record invalid-args attempt", {
            cause: written.error.code,
            reason: args.error.code,
          });
        }
        return err("audit.invalid_args", "tool args are not valid audit JSON", {
          reason: args.error.code,
          path,
          attemptId: written.value.id,
          recorded: true,
        });
      });
    },

    recordOutcome(input: RecordOutcomeInput): Result<AuditRecord> {
      return guardedWrite(() => {
        const parsed = outcomeInputSchema.safeParse(input);
        if (!parsed.success) {
          return err("audit.invalid_input", "invalid outcome input", {
            issues: zodIssuePaths(parsed.error),
          });
        }
        const p = parsed.data;
        const id = resolveId(p.id);
        if (!id.ok) return id;
        const ts = resolveTs(p.ts);
        if (!ts.ok) return ts;
        const body: AuditOutcomeBody = {
          kind: "outcome",
          id: id.value,
          attemptId: p.attemptId,
          ts: ts.value.ts,
          outcome: p.outcome,
          latencyMs: p.latencyMs,
        };
        if (p.errorCode !== undefined) body.errorCode = p.errorCode;
        if (p.upstreamRef !== undefined) body.upstreamRef = p.upstreamRef;
        return appendTx.immediate({ body, callerTs: ts.value.callerTs });
      });
    },

    recordVerification(input: RecordVerificationInput): Result<AuditRecord> {
      return guardedWrite(() => {
        const parsed = verificationInputSchema.safeParse(input);
        if (!parsed.success) {
          return err("audit.invalid_input", "invalid verification input", {
            issues: zodIssuePaths(parsed.error),
          });
        }
        const p = parsed.data;
        const id = resolveId(p.id);
        if (!id.ok) return id;
        const ts = resolveTs(p.ts);
        if (!ts.ok) return ts;
        const body: AuditVerificationBody = {
          kind: "verification",
          id: id.value,
          attemptId: p.attemptId,
          ts: ts.value.ts,
          trigger: p.trigger,
          result: p.result,
          method: p.method,
          needsHuman: p.needsHuman,
        };
        if (p.upstreamRef !== undefined) body.upstreamRef = p.upstreamRef;
        if (p.errorCode !== undefined) body.errorCode = p.errorCode;
        if (p.resolver !== undefined) body.resolver = p.resolver;
        return appendTx.immediate({ body, callerTs: ts.value.callerTs });
      });
    },

    recordApproval(input: RecordApprovalInput): Result<AuditRecord> {
      return guardedWrite(() => {
        const parsed = approvalInputSchema.safeParse(input);
        if (!parsed.success) {
          return err("audit.invalid_input", "invalid approval input", {
            issues: zodIssuePaths(parsed.error),
          });
        }
        const p = parsed.data;
        const id = resolveId(p.id);
        if (!id.ok) return id;
        const ts = resolveTs(p.ts);
        if (!ts.ok) return ts;
        const body: AuditApprovalBody = {
          kind: "approval",
          id: id.value,
          attemptId: p.attemptId,
          ts: ts.value.ts,
          approvalId: p.approvalId,
          decision: p.decision,
        };
        if (p.approver !== undefined) body.approver = p.approver;
        return appendTx.immediate({ body, callerTs: ts.value.callerTs });
      });
    },

    readAttempt(attemptId: string): Result<AuditActivity | undefined> {
      if (!recordIdSchema.safeParse(attemptId).success) {
        return err("audit.invalid_input", "invalid attempt id");
      }
      if (!db.open) return err("audit.read_failed", "audit store is closed");
      try {
        return readAttemptTx(attemptId);
      } catch (e: unknown) {
        return err("audit.read_failed", "could not read the attempt", describeError(e));
      }
    },

    readUnsettled(): Result<{
      open: AuditActivity[];
      unsettled: AuditActivity[];
      staleApprovals: AuditActivity[];
    }> {
      const all = scanAll();
      if (!all.ok) return all;
      const open: AuditActivity[] = [];
      const unsettled: AuditActivity[] = [];
      const staleApprovals: AuditActivity[] = [];
      for (const a of all.value) {
        const d = a.attempt.decision;
        if (a.outcome === undefined) {
          if (d === "allow" || d === "transform") open.push(a);
          else if (d === "require_approval") {
            // An approved action (or its retry) may have been sent before a crash; anything else never was.
            if (a.attempt.retryOf !== undefined || a.approval?.decision === "approved")
              open.push(a);
            else staleApprovals.push(a);
          }
          continue;
        }
        if (d === "deny") continue;
        if (a.outcome.outcome !== "timeout" && a.outcome.outcome !== "upstream_error") continue;
        if (a.verification === undefined || a.verification.result === "unknown") unsettled.push(a);
      }
      return ok({ open, unsettled, staleApprovals });
    },

    listNeedsHuman(): Result<AuditActivity[]> {
      const all = scanAll();
      if (!all.ok) return all;
      return ok(all.value.filter((a) => a.verification?.result === "unknown"));
    },

    readAll(): Result<Array<AuditRecord | InvalidAuditRow>> {
      if (!db.open) return err("audit.read_failed", "audit store is closed");
      try {
        const rows: unknown[] = allStmt.all();
        return ok(rows.map((r, i) => parseRow(r, i + 1)));
      } catch (e: unknown) {
        return err("audit.read_failed", "could not read audit log", describeError(e));
      }
    },

    readActivitySince(sinceMs: number): Result<AuditActivity[]> {
      if (typeof sinceMs !== "number" || !Number.isFinite(sinceMs)) {
        return err("audit.invalid_input", "sinceMs must be a finite number");
      }
      if (!db.open) return err("audit.read_failed", "audit store is closed");
      try {
        return readActivityTx(sinceMs);
      } catch (e: unknown) {
        return err("audit.read_failed", "could not read audit activity", describeError(e));
      }
    },

    verify(): Result<VerifyResult> {
      const rows = store.readAll();
      if (!rows.ok) return rows;
      try {
        return ok(verifyChain(hasher, rows.value));
      } catch (e: unknown) {
        return err("audit.read_failed", "chain verification failed", describeError(e));
      }
    },

    close(): void {
      if (db.open) db.close();
    },
  };

  return ok(store);
}
