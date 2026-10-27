import { err, ok, type Result } from "../result.js";
import { canonicalJson } from "./canonical-json.js";
import {
  APPROVER_RE,
  AUDIT_VERIFICATION_METHODS,
  AUDIT_VERIFICATION_RESULTS,
  AUDIT_VERIFICATION_TRIGGERS,
  ERROR_CODE_RE,
  GENESIS_PREV_HASH,
  IDEMPOTENCY_KEY_RE,
  RECORD_ID_RE,
  UPSTREAM_REF_RE,
  type AuditVerificationResult,
  type AuditBody,
  type AuditRecord,
  type Hasher,
  type InvalidAuditRow,
  type VerifyBreakReason,
  type VerifyResult,
} from "./types.js";

const HEX64_RE = /^[0-9a-f]{64}$/;

/** Strip chain fields so only the body is hashed (plus `seq`). */
function bodyOf(record: AuditRecord): AuditBody {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { seq, prevHash, hash, ...body } = record;
  return body;
}

/**
 * `idempotencyKey` shape check (T009). Absent/undefined is fine (dropped by `canonicalJson`, so legacy rows hash
 * unchanged). On an attempt it must be 64 lowercase hex chars; an outcome must never carry one.
 * Reads the field at runtime because rows come from storage and may not match the static type.
 */
function checkIdempotencyKey(body: AuditBody): Result<true> {
  const key: unknown = (body as { idempotencyKey?: unknown }).idempotencyKey;
  if (key === undefined) return ok(true);
  const kind: string = body.kind;
  if (kind !== "attempt") {
    return err("audit.invalid_idempotency_key", "only attempt records may carry idempotencyKey");
  }
  if (typeof key !== "string" || !IDEMPOTENCY_KEY_RE.test(key)) {
    return err(
      "audit.invalid_idempotency_key",
      "idempotencyKey must be exactly 64 lowercase hex chars",
    );
  }
  return ok(true);
}

/**
 * `retryOf` shape check (T010). Absent/undefined is fine (legacy rows hash unchanged). On an attempt it must match
 * `RECORD_ID_RE`; any other record kind must not carry it.
 */
function checkRetryOf(body: AuditBody): Result<true> {
  const v: unknown = (body as { retryOf?: unknown }).retryOf;
  if (v === undefined) return ok(true);
  const kind: string = body.kind;
  if (kind !== "attempt") {
    return err("audit.invalid_retry_of", "only attempt records may carry retryOf");
  }
  if (typeof v !== "string" || !RECORD_ID_RE.test(v)) {
    return err("audit.invalid_retry_of", "retryOf must be a record id");
  }
  return ok(true);
}

const VERIFICATION_KEYS: ReadonlySet<string> = new Set([
  "kind",
  "id",
  "attemptId",
  "ts",
  "trigger",
  "result",
  "method",
  "needsHuman",
  "upstreamRef",
  "errorCode",
  "resolver",
]);

function optionalMatches(v: unknown, re: RegExp): boolean {
  return v === undefined || (typeof v === "string" && re.test(v));
}

/**
 * Strict shape check for `verification` records (T010). Reads every field as `unknown` because rows come from
 * storage. Other kinds pass through unchanged.
 */
function checkVerification(body: AuditBody): Result<true> {
  const kind: string = body.kind;
  if (kind !== "verification") return ok(true);
  const bad = (msg: string): Result<true> => err("audit.invalid_verification", msg);
  const b = body as unknown as Record<string, unknown>;
  for (const k of Object.keys(b)) {
    if (!VERIFICATION_KEYS.has(k) && b[k] !== undefined) return bad("unexpected field");
  }
  if (typeof b["id"] !== "string" || !RECORD_ID_RE.test(b["id"])) return bad("invalid id");
  if (typeof b["attemptId"] !== "string" || !RECORD_ID_RE.test(b["attemptId"])) {
    return bad("invalid attemptId");
  }
  if (typeof b["ts"] !== "string" || b["ts"] === "") return bad("invalid ts");
  if (!(AUDIT_VERIFICATION_TRIGGERS as readonly unknown[]).includes(b["trigger"])) {
    return bad("invalid trigger");
  }
  if (!(AUDIT_VERIFICATION_RESULTS as readonly unknown[]).includes(b["result"])) {
    return bad("invalid result");
  }
  if (!(AUDIT_VERIFICATION_METHODS as readonly unknown[]).includes(b["method"])) {
    return bad("invalid method");
  }
  if (typeof b["needsHuman"] !== "boolean") return bad("needsHuman must be a boolean");
  if (!optionalMatches(b["upstreamRef"], UPSTREAM_REF_RE)) return bad("invalid upstreamRef");
  if (!optionalMatches(b["errorCode"], ERROR_CODE_RE)) return bad("invalid errorCode");
  if (b["trigger"] === "human") {
    if (typeof b["resolver"] !== "string" || !APPROVER_RE.test(b["resolver"])) {
      return bad("a human verification requires a valid resolver");
    }
  } else if (b["resolver"] !== undefined) {
    return bad("resolver is only allowed when trigger is human");
  }
  return ok(true);
}

/**
 * `hash = sha256Hex(prevHash + canonicalJson({ ...body, seq }))`. Never throws.
 * Rejects (`audit.invalid_idempotency_key`) a malformed `idempotencyKey` or one on a non-attempt record,
 * (`audit.invalid_retry_of`) a malformed `retryOf` or one on a non-attempt record, and
 * (`audit.invalid_verification`) a malformed `verification` record (see `AuditVerificationBody`).
 */
export function computeHash(
  h: Hasher,
  prevHash: string,
  seq: number,
  body: AuditBody,
): Result<string> {
  const keyCheck = checkIdempotencyKey(body);
  if (!keyCheck.ok) return keyCheck;
  const retryCheck = checkRetryOf(body);
  if (!retryCheck.ok) return retryCheck;
  const verificationCheck = checkVerification(body);
  if (!verificationCheck.ok) return verificationCheck;
  const canon = canonicalJson({ ...body, seq });
  if (!canon.ok) return canon;
  let digest: string;
  try {
    digest = h.sha256Hex(prevHash + canon.value);
  } catch (e: unknown) {
    return err("audit.hasher_error", "hasher threw", {
      cause: e instanceof Error ? e.message : String(e),
    });
  }
  if (typeof digest !== "string" || !HEX64_RE.test(digest)) {
    return err("audit.hasher_error", "hasher returned a value that is not 64 lowercase hex chars");
  }
  return ok(digest);
}

/** Build the next record in the chain. `prev` is the current head (or null for an empty chain). */
export function buildRecord(
  h: Hasher,
  prev: { seq: number; hash: string } | null,
  body: AuditBody,
): Result<AuditRecord> {
  const seq = prev ? prev.seq + 1 : 1;
  const prevHash = prev?.hash ?? GENESIS_PREV_HASH;
  const hash = computeHash(h, prevHash, seq, body);
  if (!hash.ok) return hash;
  return ok({ ...body, seq, prevHash, hash: hash.value });
}

function isInvalid(r: AuditRecord | InvalidAuditRow): r is InvalidAuditRow {
  return "invalid" in r && r.invalid === true;
}

/**
 * Verify an ordered chain (seq ascending). Returns the first broken record, checking per record in order:
 * invalid row → seq gap → genesis → prev-hash link → recomputed hash → id not seen before (`duplicate_id`) →
 * outcome references an earlier attempt (`orphan_outcome`) → attempt has no earlier outcome (`duplicate_outcome`).
 * T010 verification records: must reference an earlier attempt (`orphan_verification`) that already has an outcome
 * (`verification_before_outcome`) and no earlier `happened` / `not_happened` verification
 * (`verification_after_settled`; only `unknown` may be followed by more verifications).
 * T010 retries: an attempt with `retryOf` must reference an earlier attempt of the same tool whose latest
 * verification so far is `not_happened`, that is not itself a retry, and that has not been retried already
 * (`bad_retry_of`).
 * The id/outcome/verification checks catch tampered rows that otherwise chain correctly.
 * Attempts with no outcome are reported in `danglingAttempts` (a warning, not a break).
 */
export function verifyChain(
  h: Hasher,
  records: Iterable<AuditRecord | InvalidAuditRow>,
): VerifyResult {
  let prevHash = GENESIS_PREV_HASH;
  let index = 0;
  const attempts = new Set<string>();
  const answered = new Set<string>();
  const seenIds = new Set<string>();
  const attemptOrder: string[] = [];
  const attemptTool = new Map<string, string>();
  const isRetry = new Set<string>();
  const retried = new Set<string>();
  const latestVerification = new Map<string, AuditVerificationResult>();

  const broken = (seq: number, id: string | null, reason: VerifyBreakReason): VerifyResult => ({
    ok: false,
    brokenAt: { index, seq, id, reason },
  });

  for (const r of records) {
    if (isInvalid(r)) return broken(r.seq, null, "invalid_row");
    // Rows come from storage; re-check the discriminant at runtime rather than trusting the type.
    const kind: string = r.kind;
    if (kind !== "attempt" && kind !== "outcome" && kind !== "verification") {
      return broken(r.seq, null, "invalid_row");
    }
    const id = typeof r.id === "string" ? r.id : null;
    if (r.seq !== index + 1) return broken(r.seq, id, "seq_gap");
    if (index === 0 && r.prevHash !== GENESIS_PREV_HASH)
      return broken(r.seq, id, "genesis_mismatch");
    if (r.prevHash !== prevHash) return broken(r.seq, id, "prev_hash_mismatch");

    const recomputed = computeHash(h, r.prevHash, r.seq, bodyOf(r));
    if (!recomputed.ok) {
      return broken(
        r.seq,
        id,
        recomputed.error.code === "audit.hasher_error" ? "hasher_error" : "invalid_row",
      );
    }
    if (recomputed.value !== r.hash) return broken(r.seq, id, "hash_mismatch");

    if (seenIds.has(r.id)) return broken(r.seq, id, "duplicate_id");
    seenIds.add(r.id);

    if (r.kind === "attempt") {
      if (r.retryOf !== undefined) {
        const original = r.retryOf;
        if (
          attemptTool.get(original) !== r.tool ||
          latestVerification.get(original) !== "not_happened" ||
          isRetry.has(original) ||
          retried.has(original)
        ) {
          return broken(r.seq, id, "bad_retry_of");
        }
        retried.add(original);
        isRetry.add(r.id);
      }
      attempts.add(r.id);
      attemptOrder.push(r.id);
      attemptTool.set(r.id, r.tool);
    } else if (r.kind === "verification") {
      if (!attempts.has(r.attemptId)) return broken(r.seq, id, "orphan_verification");
      if (!answered.has(r.attemptId)) return broken(r.seq, id, "verification_before_outcome");
      const prior = latestVerification.get(r.attemptId);
      if (prior !== undefined && prior !== "unknown") {
        return broken(r.seq, id, "verification_after_settled");
      }
      latestVerification.set(r.attemptId, r.result);
    } else {
      if (!attempts.has(r.attemptId)) return broken(r.seq, id, "orphan_outcome");
      if (answered.has(r.attemptId)) return broken(r.seq, id, "duplicate_outcome");
      answered.add(r.attemptId);
    }
    prevHash = r.hash;
    index++;
  }

  return {
    ok: true,
    count: index,
    headHash: prevHash,
    danglingAttempts: attemptOrder.filter((a) => !answered.has(a)),
  };
}
