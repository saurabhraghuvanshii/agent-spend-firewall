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
  type AuditAttemptBody,
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
  /** Defaults to `idGen()`. Must match `recordIdSchema`. */
  id?: string;
  /** ISO-8601; defaults to `clock().toISOString()`. */
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

/** An attempt joined with its outcome record, if one has been written. */
export interface AuditActivity {
  readonly attempt: AuditAttemptRecord;
  readonly outcome?: AuditOutcomeRecord;
}

/** Default cap on rows `readActivitySince` scans before failing closed. */
export const DEFAULT_MAX_ACTIVITY_ROWS = 10_000;
export type AuditOutcomeInput = (typeof AUDIT_OUTCOMES)[number];

export interface AuditStore {
  readonly path: string;
  readonly readonly: boolean;
  /** Non-fatal integrity warnings found at open (read-only stores only, e.g. altered triggers). */
  readonly warnings: readonly string[];
  /** Append an attempt record. Call *before* forwarding a money action. */
  recordAttempt(input: RecordAttemptInput): Result<AuditRecord>;
  /** Append the outcome of an existing attempt. At most one outcome per attempt. */
  recordOutcome(input: RecordOutcomeInput): Result<AuditRecord>;
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
  id: recordIdSchema.optional(),
  ts: isoTs.optional(),
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

const storedBodySchema = z.discriminatedUnion("kind", [storedAttemptSchema, storedOutcomeSchema]);

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
    return body;
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
const decisionOnlySchema = z.object({ decision: z.enum(AUDIT_DECISIONS) });
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

  /** Runs inside BEGIN IMMEDIATE. Returning `err` before the insert leaves the DB unchanged. */
  function appendInTx(req: AppendRequest): Result<AuditRecord> {
    const { body } = req;
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
        ? parseJsonAs(decisionOnlySchema, rowParsed.data.body_json)
        : null;
      if (attempt === null) return err("audit.write_failed", "referenced attempt is unreadable");
      // A denied action was never forwarded; any other outcome would be a lie in the log.
      // `require_approval` executes later (after approval), so all outcomes are allowed.
      if (attempt.decision === "deny" && !DENY_OUTCOMES.has(body.outcome)) {
        return err(
          "audit.inconsistent_outcome",
          "a denied attempt can only have a denied or not_forwarded outcome",
          { decision: attempt.decision, outcome: body.outcome },
        );
      }
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

  /** Runs inside a (deferred) read transaction. See `AuditStore.readActivitySince`. */
  function readActivityInTx(sinceMs: number): Result<AuditActivity[]> {
    const attempts = new Map<string, AuditAttemptRecord>();
    const outcomes = new Map<string, AuditOutcomeRecord>();
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
      } else {
        if (outcomes.has(rec.attemptId)) return invalid("duplicate outcome in audit log", rec.seq);
        outcomes.set(rec.attemptId, rec);
      }
    }
    const all = new Map(attempts);
    for (const [attemptId, outcome] of outcomes) {
      let attempt = attempts.get(attemptId);
      if (attempt === undefined) {
        // Outcome in the window for an attempt older than the cutoff: indexed lookup by UNIQUE id.
        const raw: unknown = attemptRowStmt.get(attemptId);
        if (raw === undefined) return invalid("outcome references a missing attempt", outcome.seq);
        const rec = parseRow(raw, 0);
        if ("invalid" in rec) return invalid("attempt for an outcome is unreadable", rec.seq);
        if (rec.kind !== "attempt")
          return invalid("outcome references a non-attempt record", outcome.seq);
        if (!Number.isFinite(Date.parse(rec.ts))) {
          return invalid("audit record has an unparseable timestamp", rec.seq);
        }
        attempt = rec;
        all.set(attemptId, rec);
      }
      if (attempt.seq >= outcome.seq) return invalid("outcome precedes its attempt", outcome.seq);
    }
    const result: AuditActivity[] = [];
    for (const attempt of [...all.values()].sort((a, b) => a.seq - b.seq)) {
      const outcome = outcomes.get(attempt.id);
      result.push(outcome === undefined ? { attempt } : { attempt, outcome });
    }
    return ok(result);
  }

  const readActivityTx = db.transaction(readActivityInTx);

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

        if (args.ok) {
          body.argsRedacted = args.value;
          if (original?.ok === true) body.originalArgsRedacted = original.value;
          if (p.idempotencyKey !== undefined) body.idempotencyKey = p.idempotencyKey;
          return appendTx.immediate({ body, callerTs: ts.value.callerTs });
        }

        // Invalid args (e.g. float amount): still leave a trail, as a deny, then report the error.
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
