/**
 * Pure helpers for `HistoryPort` / `StatsPort` adapters (T007): which audit records count toward
 * limits, whether a recorded action matches a history query, and when it happened.
 * No I/O, no clock: `Date.parse` only parses strings.
 */
import { canonicalJson } from "../audit/canonical-json.js";
import { redact } from "../audit/redact.js";
import type {
  AuditDecision,
  AuditOutcome,
  AuditVerificationResult,
  JsonValue,
} from "../audit/types.js";
import { isPlainObject } from "./context.js";
import type { Args } from "./types.js";

/**
 * An audit attempt's decision joined with its outcome record, if one exists yet, and the `result` of its LATEST
 * verification record (T010, highest seq), if any.
 */
export type Countable = {
  decision: AuditDecision;
  outcome?: AuditOutcome;
  verification?: AuditVerificationResult;
};

/**
 * Settlement status of an audited action (D-023 as amended by T010):
 * - `executed`: outcome `success`, or latest verification `happened`. Ages out after the duplicate window.
 * - `may_have_executed`: outcome `timeout` / `upstream_error` and no verification yet. Ages out after the open
 *   lookback (24 h) until verified.
 * - `unknown`: latest verification `unknown` — may have executed and could not be settled. NEVER ages out
 *   (`blocksIndefinitely`), until a later `happened` / `not_happened` verification exists.
 * - `open`: no outcome yet (in flight, or awaiting / approved but not executed).
 * - `not_counted`: `deny`, outcome `denied` / `not_forwarded`, latest verification `not_happened`, or a decision /
 *   outcome outside the audit schema.
 */
export type ActivityStatus = "executed" | "may_have_executed" | "unknown" | "open" | "not_counted";

const COUNTED_DECISIONS: ReadonlySet<string> = new Set<AuditDecision>([
  "allow",
  "transform",
  "require_approval",
]);
const MAY_HAVE_EXECUTED_OUTCOMES: ReadonlySet<string> = new Set<AuditOutcome>([
  "timeout",
  "upstream_error",
]);

/**
 * Settlement status of an audited action; see `ActivityStatus`. Precedence, first match wins:
 * 1. decision not in {allow, transform, require_approval} ⇒ `not_counted` (nothing was ever sent).
 * 2. outcome `success` ⇒ `executed` (an upstream success is authoritative; a later verification cannot undo it).
 * 3. latest verification `happened` ⇒ `executed`; `not_happened` ⇒ `not_counted`; `unknown` ⇒ `unknown`.
 *    A verification value outside the audit schema ⇒ `unknown` (fail closed: keeps blocking).
 * 4. no verification: D-023 — no outcome ⇒ `open`; `timeout` / `upstream_error` ⇒ `may_have_executed`;
 *    anything else ⇒ `not_counted`.
 */
export function activityStatus(a: Countable): ActivityStatus {
  if (!COUNTED_DECISIONS.has(a.decision)) return "not_counted";
  if (a.outcome === "success") return "executed";
  if (a.verification !== undefined) {
    if (a.verification === "happened") return "executed";
    if (a.verification === "not_happened") return "not_counted";
    return "unknown";
  }
  if (a.outcome === undefined) return "open";
  return MAY_HAVE_EXECUTED_OUTCOMES.has(a.outcome) ? "may_have_executed" : "not_counted";
}

/**
 * Whether an audited action counts toward history / velocity / duplicate limits: `activityStatus(a)` is anything
 * but `not_counted`.
 *
 * Counted: actions that were executed (`success`, or verified `happened`), may have executed (`timeout`,
 * `upstream_error` not yet verified, or verified `unknown`), or are still pending (no outcome yet: in flight, or
 * awaiting / approved but not yet executed). Counting pending actions stops the same refund from being queued twice.
 *
 * Not counted: `deny` decisions, any action whose outcome is `denied` (e.g. approval rejected or expired) or
 * `not_forwarded` (never sent upstream), and any action whose latest verification is `not_happened`.
 *
 * Unknown decision / outcome values (not in the audit schema) are not counted.
 */
export function countsTowardLimits(a: Countable): boolean {
  return activityStatus(a) !== "not_counted";
}

/**
 * True iff the action is counted and must NOT age out of any window or lookback (latest verification `unknown`):
 * callers must count it regardless of its timestamp, however old.
 */
export function blocksIndefinitely(a: Countable): boolean {
  return activityStatus(a) === "unknown";
}

/**
 * Latest verification result per attempt id from verification records in any order (highest `seq` wins).
 * Pure helper for adapters building `Countable.verification`.
 */
export function latestVerifications(
  records: Iterable<{ attemptId: string; seq: number; result: AuditVerificationResult }>,
): Map<string, AuditVerificationResult> {
  const best = new Map<string, { seq: number; result: AuditVerificationResult }>();
  for (const r of records) {
    const cur = best.get(r.attemptId);
    if (cur === undefined || r.seq > cur.seq)
      best.set(r.attemptId, { seq: r.seq, result: r.result });
  }
  const out = new Map<string, AuditVerificationResult>();
  for (const [id, v] of best) out.set(id, v.result);
  return out;
}

/**
 * Whether a recorded action's redacted args match a `HistoryQuery.match`.
 *
 * Audit args are stored redacted (D-011), so `match` is redacted the same way and compared in
 * redacted form: for every key `k` of `match`, `argsRedacted` must be a plain object with an own
 * key `k` whose canonical JSON equals that of `redact(match)[k]`. Extra keys in `argsRedacted` are
 * ignored. An empty `match` matches every plain-object `argsRedacted`.
 *
 * Consequences (documented, deliberate):
 * - Over-match: values redacted to `[REDACTED]` (e.g. under `email`) compare equal even when
 *   the originals differ. For duplicate detection this errs towards deny (fail closed).
 * - A match key that `redact` renames (a key that itself contains PII) never matches.
 * - Any canonicalisation failure (floats, NaN, …) or a non-object `argsRedacted` ⇒ `false`.
 *
 * Never throws.
 */
export function argsMatch(argsRedacted: JsonValue, match: Args): boolean {
  try {
    if (!isPlainObject(argsRedacted) || !isPlainObject(match)) return false;
    if (!canonicalJson(match).ok) return false;
    const red = redact(match);
    if (!isPlainObject(red)) return false;
    for (const k of Object.keys(match)) {
      if (!Object.hasOwn(red, k) || !Object.hasOwn(argsRedacted, k)) return false;
      const want = canonicalJson(red[k]);
      const got = canonicalJson(argsRedacted[k]);
      if (!want.ok || !got.ok || want.value !== got.value) return false;
    }
    return true;
  } catch {
    // Defensive: redact/canonicalJson are not expected to throw; treat any throw as "no match".
    return false;
  }
}

/**
 * Activity time (epoch ms) of an action: the latest of the attempt timestamp, its outcome timestamp and its latest
 * verification timestamp (T010), where given. Returns `undefined` if any given timestamp is not a string or does
 * not parse; adapters should then treat the action as inside every window (fail closed).
 */
export function activityTs(
  attemptTs: string,
  outcomeTs?: string,
  verificationTs?: string,
): number | undefined {
  let latest = parseTs(attemptTs);
  if (latest === undefined) return undefined;
  for (const ts of [outcomeTs, verificationTs]) {
    if (ts === undefined) continue;
    const t = parseTs(ts);
    if (t === undefined) return undefined;
    latest = Math.max(latest, t);
  }
  return latest;
}

function parseTs(ts: unknown): number | undefined {
  if (typeof ts !== "string" || ts === "") return undefined;
  const ms = Date.parse(ts);
  return Number.isFinite(ms) ? ms : undefined;
}
