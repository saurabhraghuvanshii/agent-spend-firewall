/**
 * Idempotency keys and duplicate detection for money tools (T009). A firewall invariant: it runs for EVERY money
 * tool, inside the pipeline's global lock, and a policy cannot disable it.
 *
 * KEY: `sha256Hex(canonicalJson({ v: 1, tool, key }))` where `key` is the call's key material:
 * - tools in `IDEMPOTENCY_FIELDS` (exact name): only those top-level fields (absent fields are simply absent, so
 *   the key stays deterministic). For `create_refund` that is `payment_id` + `amount`, so a retry that only changes
 *   `notes`, `receipt` or `speed` is the SAME logical action;
 * - any other money tool (incl. unknown ones): ALL forwarded top-level args EXCEPT the free-text fields in
 *   `IDEMPOTENCY_FREE_TEXT_FIELDS` (`notes`, `description`, `receipt`, `reference_id`; exact top-level names), so
 *   repeating `create_payment_link` / `initiate_payment` / … with only new metadata is still the SAME action.
 *   Any other extra key (incl. unknown ones and case variants such as `Notes`) still changes the key — closing that is
 *   T020 (schema allowlisting of money-tool args).
 * `reason` is never part of it (the pipeline strips it before this point).
 *
 * The key material is REDACTED with core `redact`, exactly as the audit store redacts `argsRedacted`, so the key can
 * be recomputed from a stored row (`argsRedacted` / `originalArgsRedacted`), including legacy rows written before
 * keys were stored. Equivalence (tested): live = `redact(json(select(args)))`, stored = `select(redact(json(args)))`
 * where `select` is the pick (pinned tools) or the free-text omission (other tools). They are equal because
 * `redact` treats every top-level key independently except that it RENAMES keys that themselves contain PII (to
 * `[REDACTED_KEY_<n>]`, numbered over the offending keys only) — and neither the picked names (`payment_id`,
 * `amount`) nor the omitted free-text names are ever renamed or produced by a rename. Nothing relies on `redact` being
 * idempotent. Redaction can merge distinct values (two different e-mails both become `[REDACTED]`): such collisions
 * only ever over-deny (fail closed, D-026).
 *
 * MATCHING (`findDuplicate`): a row is a duplicate of the call iff it is for the same exact tool, counts toward
 * limits (D-023: decision allow / transform / require_approval with outcome none / success / timeout /
 * upstream_error), is inside the time window (`t = max(attempt.ts, outcome.ts)`; executed (`success`):
 * `t ≥ now − windowMs`; open, or `timeout` / `upstream_error` (may have executed, unsettled until T010's
 * verify-before-retry): `t ≥ now − max(windowMs, openLookbackMs)`; an unparseable time is inside every window), is not excluded, and either its
 * stored `idempotencyKey` or the key recomputed from its `argsRedacted` / `originalArgsRedacted` is one of the
 * call's keys. A same-tool row whose key can't be recomputed is treated as a match (fail closed).
 */
import {
  activityTs,
  canonicalJson,
  countsTowardLimits,
  err,
  ok,
  redact,
  type JsonValue,
  type Result,
} from "@asf/core";
import type { AuditActivity } from "./audit-store.js";
import { nodeHasher } from "./node-hasher.js";

/**
 * Version tag hashed into every key. Not bumped when the free-text exclusion was added: matching never relies on a
 * stored key alone (keys are always recomputed from the stored args too), so a pre-change stored key can only
 * add matches, never hide one.
 */
export const IDEMPOTENCY_KEY_VERSION = 1;

/**
 * Top-level free-text fields (exact names) left out of the key of tools NOT in `IDEMPOTENCY_FIELDS`: changing only
 * these must not make a repeat look like a new action.
 */
export const IDEMPOTENCY_FREE_TEXT_FIELDS: readonly string[] = Object.freeze([
  "notes",
  "description",
  "receipt",
  "reference_id",
]);

/**
 * Key fields per tool (exact names, looked up with `Object.hasOwn`). Any money tool not listed here is keyed on all
 * of its forwarded args.
 */
export const IDEMPOTENCY_FIELDS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  create_refund: Object.freeze(["payment_id", "amount"]),
  capture_payment: Object.freeze(["payment_id", "amount"]),
  create_instant_settlement: Object.freeze(["amount"]),
});

/** Default duplicate window for CLOSED actions (10 min). */
export const DEFAULT_DUPLICATE_WINDOW_MS = 600_000;
export const MIN_DUPLICATE_WINDOW_MS = 60_000;
export const MAX_DUPLICATE_WINDOW_MS = 86_400_000;

export type DuplicateStatus = "executed" | "may_have_executed" | "pending_approval" | "in_flight";

/** Agent-facing message of a `firewall.duplicate` deny, per status (constant: the result filter checks it). */
export const DUPLICATE_MESSAGES: Readonly<Record<DuplicateStatus, string>> = Object.freeze({
  executed:
    "an identical money action was already executed recently (see duplicateOf); it was not repeated. The call was not sent",
  may_have_executed:
    "an identical money action was sent recently and may have executed (timeout or upstream error); check its status before trying again. The call was not sent",
  pending_approval:
    "an identical money action is already awaiting human approval; the call was not sent",
  in_flight: "an identical money action is in progress right now; the call was not sent",
});

export const DUPLICATE_STATUSES: readonly DuplicateStatus[] = Object.freeze([
  "executed",
  "may_have_executed",
  "pending_approval",
  "in_flight",
]);

export interface DuplicateHit {
  /** Audit attempt id of the earlier action. */
  readonly attemptId: string;
  readonly status: DuplicateStatus;
  /** Upstream resource id of an executed action (e.g. `rfnd_…`), when recorded. */
  readonly upstreamRef?: string;
}

export interface FindDuplicateOpts {
  /** Current time, epoch ms (non-negative safe integer). */
  readonly nowMs: number;
  /** Window for CLOSED actions, positive safe integer ms. */
  readonly windowMs: number;
  /** Max age of OPEN actions (no outcome yet), positive safe integer ms. */
  readonly openLookbackMs: number;
  /** Attempts never matched (e.g. the approved attempt being executed, T011). */
  readonly excludeAttemptIds?: ReadonlySet<string>;
}

function isPlainObject(v: unknown): v is Record<string, JsonValue> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function fieldsFor(tool: string): readonly string[] | undefined {
  return Object.hasOwn(IDEMPOTENCY_FIELDS, tool) ? IDEMPOTENCY_FIELDS[tool] : undefined;
}

function omitFreeText(args: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const entries: Array<[string, unknown]> = [];
  for (const k of Object.keys(args)) {
    if (!IDEMPOTENCY_FREE_TEXT_FIELDS.includes(k)) entries.push([k, args[k]]);
  }
  // Define semantics (fromEntries): a `__proto__` key stays an own data property.
  return Object.fromEntries(entries);
}

/** The key material of `args` for `tool` (pinned fields, or all args minus free text). */
function keyMaterial(
  tool: string,
  args: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const fields = fieldsFor(tool);
  return fields === undefined ? omitFreeText(args) : pick(args, fields);
}

function pick(
  args: Readonly<Record<string, unknown>>,
  fields: readonly string[],
): Record<string, unknown> {
  // Define semantics: a `__proto__` field name could never alter the prototype.
  const entries: Array<[string, unknown]> = [];
  for (const f of fields) if (Object.hasOwn(args, f)) entries.push([f, args[f]]);
  return Object.fromEntries(entries);
}

function hashMaterial(tool: string, material: JsonValue): Result<string> {
  const canon = canonicalJson({ v: IDEMPOTENCY_KEY_VERSION, tool, key: material });
  if (!canon.ok) return err("idempotency.invalid_args", "idempotency key material is not JSON");
  return ok(nodeHasher.sha256Hex(canon.value));
}

/**
 * Idempotency key of a money call from its LIVE (forwarded, `reason`-free) args. `err` (code
 * `idempotency.invalid_args`) if the args aren't a plain object or the key material isn't audit JSON (e.g. a float);
 * the caller denies. Never throws.
 */
export function idempotencyKey(tool: string, args: unknown): Result<string> {
  try {
    if (!isPlainObject(args)) {
      return err("idempotency.invalid_args", "money tool args must be a plain object");
    }
    const material = keyMaterial(tool, args);
    // Same steps as the audit store's `redactArgs`: canonical JSON → parse → redact.
    const canon = canonicalJson(material);
    if (!canon.ok) return err("idempotency.invalid_args", "idempotency key material is not JSON");
    const parsed = JSON.parse(canon.value) as JsonValue;
    return hashMaterial(tool, redact(parsed));
  } catch {
    // Defensive: canonicalJson / redact are not expected to throw. Fail closed.
    return err("idempotency.invalid_args", "idempotency key could not be computed");
  }
}

/**
 * Idempotency key recomputed from STORED (already redacted) args, e.g. `argsRedacted`. Equal to `idempotencyKey`
 * of the original live args (see module doc). `err` if the stored args aren't a plain object. Never throws.
 */
export function idempotencyKeyFromRedacted(tool: string, argsRedacted: unknown): Result<string> {
  try {
    if (!isPlainObject(argsRedacted)) {
      return err("idempotency.unrecomputable", "stored args are not an object");
    }
    const material = keyMaterial(tool, argsRedacted);
    // Round-trip so the material is a detached JSON value with own keys only.
    const canon = canonicalJson(material);
    if (!canon.ok) return err("idempotency.unrecomputable", "stored args are not JSON");
    return hashMaterial(tool, JSON.parse(canon.value) as JsonValue);
  } catch {
    // Defensive. The caller treats an unrecomputable same-tool row as a match.
    return err("idempotency.unrecomputable", "stored key could not be recomputed");
  }
}

function validMs(v: unknown, min: number): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= min;
}

function statusOf(a: AuditActivity): DuplicateStatus {
  if (a.outcome === undefined) {
    return a.attempt.decision === "require_approval" ? "pending_approval" : "in_flight";
  }
  return a.outcome.outcome === "success" ? "executed" : "may_have_executed";
}

/** Whether `a` matches one of `keys` (stored key, or recomputed from either stored args). Unrecomputable ⇒ true. */
function rowMatches(a: AuditActivity, tool: string, keys: ReadonlySet<string>): boolean {
  const stored = a.attempt.idempotencyKey;
  if (stored !== undefined && keys.has(stored)) return true;
  const forwarded = idempotencyKeyFromRedacted(tool, a.attempt.argsRedacted);
  if (!forwarded.ok || keys.has(forwarded.value)) return true;
  const original = a.attempt.originalArgsRedacted;
  if (original !== undefined) {
    const k = idempotencyKeyFromRedacted(tool, original);
    if (!k.ok || keys.has(k.value)) return true;
  }
  return false;
}

/**
 * The most recent earlier action of the same `tool` that duplicates a call with idempotency keys `keys` (see module
 * doc), or `undefined`. `err` (code `idempotency.invalid_config`) for an invalid clock / window / lookback or an
 * empty key set; the caller denies. `rows` must be every attempt active since `min(now − windowMs,
 * now − openLookbackMs)` (e.g. `AuditStore.readActivitySince`), in any order.
 */
export function findDuplicate(
  rows: readonly AuditActivity[],
  tool: string,
  keys: ReadonlySet<string>,
  opts: FindDuplicateOpts,
): Result<DuplicateHit | undefined> {
  if (!validMs(opts.nowMs, 0)) return err("idempotency.invalid_config", "invalid current time");
  if (!validMs(opts.windowMs, 1)) {
    return err("idempotency.invalid_config", "invalid duplicate window");
  }
  if (!validMs(opts.openLookbackMs, 1)) {
    return err("idempotency.invalid_config", "invalid open lookback");
  }
  if (keys.size === 0) return err("idempotency.invalid_config", "no idempotency key to match");
  const executedCutoff = opts.nowMs - opts.windowMs;
  // Open and may-have-executed rows: never a shorter lookback than executed ones.
  const unsettledCutoff = opts.nowMs - Math.max(opts.windowMs, opts.openLookbackMs);
  let best: AuditActivity | undefined;
  for (const a of rows) {
    if (a.attempt.tool !== tool) continue;
    const open = a.outcome === undefined;
    const countable = open
      ? { decision: a.attempt.decision }
      : { decision: a.attempt.decision, outcome: a.outcome.outcome };
    if (!countsTowardLimits(countable)) continue;
    if (opts.excludeAttemptIds?.has(a.attempt.id) === true) continue;
    const ts = activityTs(a.attempt.ts, a.outcome?.ts);
    // Unparseable time ⇒ inside every window (fail closed).
    const executed = !open && a.outcome.outcome === "success";
    if (ts !== undefined && ts < (executed ? executedCutoff : unsettledCutoff)) continue;
    if (!rowMatches(a, tool, keys)) continue;
    if (best === undefined || a.attempt.seq > best.attempt.seq) best = a;
  }
  if (best === undefined) return ok(undefined);
  const status = statusOf(best);
  const ref = best.outcome?.upstreamRef;
  return ok(
    status === "executed" && ref !== undefined
      ? { attemptId: best.attempt.id, status, upstreamRef: ref }
      : { attemptId: best.attempt.id, status },
  );
}
