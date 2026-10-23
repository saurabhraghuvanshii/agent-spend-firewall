/**
 * Pure helpers for `HistoryPort` / `StatsPort` adapters (T007): which audit records count toward
 * limits, whether a recorded action matches a history query, and when it happened.
 * No I/O, no clock: `Date.parse` only parses strings.
 */
import { canonicalJson } from "../audit/canonical-json.js";
import { redact } from "../audit/redact.js";
import type { AuditDecision, AuditOutcome, JsonValue } from "../audit/types.js";
import { isPlainObject } from "./context.js";
import type { Args } from "./types.js";

/** An audit attempt's decision joined with its outcome record, if one exists yet. */
export type Countable = { decision: AuditDecision; outcome?: AuditOutcome };

const COUNTED_DECISIONS: ReadonlySet<string> = new Set<AuditDecision>([
  "allow",
  "transform",
  "require_approval",
]);
const COUNTED_OUTCOMES: ReadonlySet<string> = new Set<AuditOutcome>([
  "success",
  "timeout",
  "upstream_error",
]);

/**
 * Whether an audited action counts toward history / velocity limits.
 *
 * Counted: actions that were executed (`success`), may have executed (`timeout`,
 * `upstream_error` — the upstream may have applied them), or are still pending (no outcome yet:
 * in flight, or awaiting / approved but not yet executed). Counting pending actions stops the same
 * refund from being queued twice.
 *
 * Not counted: `deny` decisions, and any action whose outcome is `denied` (e.g. approval rejected
 * or expired) or `not_forwarded` (never sent upstream).
 *
 * Unknown decision / outcome values (not in the audit schema) are not counted.
 */
export function countsTowardLimits(a: Countable): boolean {
  if (!COUNTED_DECISIONS.has(a.decision)) return false;
  return a.outcome === undefined || COUNTED_OUTCOMES.has(a.outcome);
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
 * Activity time (epoch ms) of an action: the later of the attempt timestamp and its outcome
 * timestamp, if any. Returns `undefined` if any given timestamp is not a string or does not parse;
 * adapters should then treat the action as inside every window (fail closed).
 */
export function activityTs(attemptTs: string, outcomeTs?: string): number | undefined {
  const a = parseTs(attemptTs);
  if (a === undefined) return undefined;
  if (outcomeTs === undefined) return a;
  const o = parseTs(outcomeTs);
  return o === undefined ? undefined : Math.max(a, o);
}

function parseTs(ts: unknown): number | undefined {
  if (typeof ts !== "string" || ts === "") return undefined;
  const ms = Date.parse(ts);
  return Number.isFinite(ms) ? ms : undefined;
}
