import { err, ok, type Result } from "../result.js";
import { canonicalJson } from "./canonical-json.js";
import {
  GENESIS_PREV_HASH,
  IDEMPOTENCY_KEY_RE,
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
 * `hash = sha256Hex(prevHash + canonicalJson({ ...body, seq }))`. Never throws.
 * Rejects (`audit.invalid_idempotency_key`) a malformed `idempotencyKey` or one on an outcome record.
 */
export function computeHash(
  h: Hasher,
  prevHash: string,
  seq: number,
  body: AuditBody,
): Result<string> {
  const keyCheck = checkIdempotencyKey(body);
  if (!keyCheck.ok) return keyCheck;
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
 * The id/outcome checks catch tampered rows that otherwise chain correctly.
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

  const broken = (seq: number, id: string | null, reason: VerifyBreakReason): VerifyResult => ({
    ok: false,
    brokenAt: { index, seq, id, reason },
  });

  for (const r of records) {
    if (isInvalid(r)) return broken(r.seq, null, "invalid_row");
    // Rows come from storage; re-check the discriminant at runtime rather than trusting the type.
    const kind: string = r.kind;
    if (kind !== "attempt" && kind !== "outcome") return broken(r.seq, null, "invalid_row");
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
      attempts.add(r.id);
      attemptOrder.push(r.id);
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
