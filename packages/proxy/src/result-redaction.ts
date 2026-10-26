/**
 * Agent-facing redaction of tool results (T008, from T002): card details, saved tokens and customer PII never reach
 * the agent in clear.
 *
 * Applied by the server's `resultFilter` to the result the AGENT sees, after the interceptor (audit / outcome stages
 * see the unfiltered result). The policy engine's own `fetch_payment` and the firewall's `fetch_order` lookups go
 * straight to upstream and are NOT filtered (they only read id / status / amounts / currency).
 *
 * DEFAULT: EVERY tool's result is redacted (reads and money tools alike: `capture_payment`, `create_payment_link`,
 * `fetch_all_payouts`, … all return customer / beneficiary data). Exempt only tools in `REDACTION_EXEMPT_TOOLS`,
 * which must be proven PII-free; it is deliberately EMPTY: even the settlement tools return UTRs / bank references
 * (`fetch_all_settlements`) or per-payment recon rows with customer email / contact / card metadata
 * (`fetch_settlement_recon_details`), and upstream may add fields at any time, so no tool's output is assumed safe.
 *
 * For a redacted result:
 * - each `text` content item that parses as JSON is run through core `redact` with `RESULT_EXTRA_KEYS` and
 *   re-serialised; any other text goes through `redactText`;
 * - `structuredContent` is redacted the same way;
 * - non-text content (images, resources, …) is replaced by a placeholder text item (can't be inspected ⇒ removed).
 * Firewall-generated `pending_approval` bodies and `firewall.duplicate` denies (T009) of the exact shape the pipeline
 * emits are passed through (they carry no upstream data beyond an allowlisted reference id, and the ids must stay
 * usable).
 *
 * Kept on purpose: Razorpay reference ids — ONLY the allowlisted keys in `REF_ID_KEY_PREFIXES` (`token_id`,
 * `card_id`, `customer_id`, `contact_id`, …) whose value is an opaque Razorpay id with the prefix expected for that key
 * (`REF_ID_VALUE`, e.g. `token_` for `token_id`). They are references the agent needs to act on, not PII. Core
 * `redact` has no allow option and its `token` substring rule removes `token_id`, so such values are RESTORED after
 * redaction (`restoreRefIds`) when they pass `isRestorableRefId` and `redactText` leaves them unchanged. Nothing
 * inside `notes` (merchant / customer free-form metadata) is ever restored, at any depth.
 * `card` / `token` objects themselves stay removed wholesale (core substring rules).
 */
import { REDACTED, redact, redactText, type JsonValue } from "@asf/core";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { DUPLICATE_MESSAGES, DUPLICATE_STATUSES, type DuplicateStatus } from "./idempotency.js";

/**
 * Tools whose results are returned unredacted. Must only contain tools proven to return no customer, payment
 * instrument or bank data. Empty on purpose (see module doc).
 */
export const REDACTION_EXEMPT_TOOLS: ReadonlySet<string> = new Set<string>();

/** Keys removed in addition to core's built-in denylist (many overlap; listed for clarity). */
export const RESULT_EXTRA_KEYS: readonly string[] = [
  "last4",
  "iin",
  "token",
  "token_iin",
  "vpa",
  "email",
  "contact",
  "name",
  "account_number",
  "bank_account",
];

export const NON_TEXT_PLACEHOLDER = "[non-text content removed by the firewall]";

/**
 * Reference-id keys that may be restored, each mapped to the Razorpay id prefix(es) its value must carry. Only
 * documented Razorpay id fields (`docs/razorpay-tools.json` + Razorpay / RazorpayX API entities). Any other `*_id`
 * key (`email_id`, `vpa_id`, `phone_id`, …) stays as core `redact` left it.
 */
export const REF_ID_KEY_PREFIXES: ReadonlyMap<string, readonly string[]> = new Map<
  string,
  readonly string[]
>([
  ["token_id", ["token"]],
  ["card_id", ["card"]],
  ["customer_id", ["cust"]],
  ["contact_id", ["cont"]],
  ["payment_id", ["pay"]],
  ["order_id", ["order"]],
  ["refund_id", ["rfnd"]],
  ["payment_link_id", ["plink"]],
  ["qr_code_id", ["qr"]],
  ["settlement_id", ["setl"]],
  ["payout_id", ["pout"]],
  ["fund_account_id", ["fa"]],
  ["account_id", ["acc"]],
  ["invoice_id", ["inv"]],
  ["plan_id", ["plan"]],
  ["subscription_id", ["sub"]],
]);

/** Opaque Razorpay id: known prefix, `_`, 6–40 base62 chars (e.g. `token_4lsdksD31GaZ09`, `cust_Ab12Cd`). */
export const REF_ID_VALUE =
  /^(token|card|cust|cont|pay|order|rfnd|plink|qr|setl|pout|fa|ba|acc|inv|plan|sub)_[A-Za-z0-9]{6,40}$/;

/** Free-form merchant / customer metadata: never restored into, at any depth. */
const NO_RESTORE_KEY = "notes";

/** True iff `value` may be put back under `key`: allowlisted key, matching prefix, and `redactText` finds nothing. */
export function isRestorableRefId(key: string, value: unknown): value is string {
  if (typeof value !== "string") return false;
  const prefixes = REF_ID_KEY_PREFIXES.get(key);
  if (prefixes === undefined) return false;
  const m = REF_ID_VALUE.exec(value);
  if (m === null) return false;
  const prefix = m[1];
  return prefix !== undefined && prefixes.includes(prefix) && redactText(value) === value;
}

/** Approval id from the approval port (`apr_` + UUID). */
const PENDING_APPROVAL_ID = /^apr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Firewall-generated attempt id: exactly what the audit store's default id generator (`redactionSafeUuid`, a
 * lowercase RFC 4122 v4 UUID that `redactText` leaves unchanged) produces. Narrower than `recordIdSchema` on purpose: a bare digit string (a phone or
 * account number) in an upstream body forged to the duplicate-deny shape must not pass through unredacted.
 */
const ATTEMPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * True iff `v` is a firewall id of the exact `format` that `redactText` leaves unchanged. The `redactText` check
 * stops a digit run (e.g. a 12-digit account number in the last UUID group) of a forged body from passing; the
 * firewall's own generators (`ids.ts`) never produce such ids.
 */
function isFirewallId(format: RegExp, v: unknown): v is string {
  return typeof v === "string" && format.test(v) && redactText(v) === v;
}

/** Message of the pipeline's `pending_approval` result (shared with `interceptor.ts`). */
export const PENDING_APPROVAL_MESSAGE = "awaiting human approval; NOT executed";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Put back reference ids that `redact` replaced. Walks `original` and `redacted` in parallel; only same-named keys
 * are considered (keys renamed by `redact` because they contain PII are left alone). Restores only values accepted
 * by `isRestorableRefId`; never descends into `notes` (any depth, any case). Mutates `redacted` (a fresh copy owned
 * by the caller).
 */
export function restoreRefIds(original: unknown, redacted: JsonValue): void {
  if (Array.isArray(original) && Array.isArray(redacted)) {
    const n = Math.min(original.length, redacted.length);
    for (let i = 0; i < n; i++) restoreRefIds(original[i], redacted[i] as JsonValue);
    return;
  }
  if (!isRecord(original) || !isRecord(redacted)) return;
  for (const key of Object.keys(original)) {
    if (!Object.hasOwn(redacted, key)) continue;
    if (key.toLowerCase() === NO_RESTORE_KEY) continue;
    const before = original[key];
    const after = redacted[key] as JsonValue;
    if (after === REDACTED && isRestorableRefId(key, before)) {
      redacted[key] = before;
    } else {
      restoreRefIds(before, after);
    }
  }
}

/** Core `redact` with `RESULT_EXTRA_KEYS`, then reference ids restored. */
export function redactResultJson(value: unknown): JsonValue {
  // Callers pass JSON.parse output / MCP structuredContent: JSON by construction (non-integers tolerated by `redact`).
  const out = redact(value as JsonValue, { extraKeys: RESULT_EXTRA_KEYS });
  restoreRefIds(value, out);
  return out;
}

/** True iff `body` is exactly the pipeline's `pending_approval` result body. */
function isPendingApprovalBody(body: unknown): boolean {
  if (!isRecord(body)) return false;
  const keys = Object.keys(body).sort();
  return (
    keys.length === 3 &&
    keys[0] === "approvalId" &&
    keys[1] === "decision" &&
    keys[2] === "message" &&
    body["decision"] === "pending_approval" &&
    typeof body["approvalId"] === "string" &&
    isFirewallId(PENDING_APPROVAL_ID, body["approvalId"]) &&
    body["message"] === PENDING_APPROVAL_MESSAGE
  );
}

/** An upstream reference id safe to show the agent verbatim: Razorpay id shape and nothing `redactText` would hit. */
export function isSafeUpstreamRef(value: unknown): value is string {
  return typeof value === "string" && REF_ID_VALUE.test(value) && redactText(value) === value;
}

function isDuplicateStatus(v: unknown): v is DuplicateStatus {
  return typeof v === "string" && (DUPLICATE_STATUSES as readonly string[]).includes(v);
}

/** True iff `body` is exactly the pipeline's `firewall.duplicate` deny body. */
function isDuplicateDenyBody(body: unknown): boolean {
  if (!isRecord(body)) return false;
  const keys = Object.keys(body).sort();
  if (
    keys.length !== 4 ||
    keys[0] !== "decision" ||
    keys[1] !== "duplicateOf" ||
    keys[2] !== "message" ||
    keys[3] !== "ruleId" ||
    body["decision"] !== "deny" ||
    body["ruleId"] !== "firewall.duplicate"
  ) {
    return false;
  }
  const dup = body["duplicateOf"];
  if (!isRecord(dup)) return false;
  const status = dup["status"];
  if (!isDuplicateStatus(status) || body["message"] !== DUPLICATE_MESSAGES[status]) return false;
  const attemptId = dup["attemptId"];
  if (!isFirewallId(ATTEMPT_ID, attemptId)) return false;
  for (const k of Object.keys(dup)) {
    if (k !== "attemptId" && k !== "status" && k !== "upstreamRef") return false;
  }
  return !Object.hasOwn(dup, "upstreamRef") || isSafeUpstreamRef(dup["upstreamRef"]);
}

function redactJsonText(text: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Not JSON (plain message): scrub patterns in the free text instead.
    return redactText(text);
  }
  if (isPendingApprovalBody(parsed) || isDuplicateDenyBody(parsed)) return text;
  return JSON.stringify(redactResultJson(parsed));
}

type ContentItem = CallToolResult["content"][number];

function redactItem(item: ContentItem): ContentItem {
  if (item.type === "text") return { ...item, text: redactJsonText(item.text) };
  return { type: "text", text: NON_TEXT_PLACEHOLDER };
}

/** See module doc. Pure; never mutates `result`. Exempt tools ⇒ the same object. */
export function redactSensitiveResult(tool: string, result: CallToolResult): CallToolResult {
  if (REDACTION_EXEMPT_TOOLS.has(tool)) return result;
  const out: CallToolResult = { ...result, content: result.content.map(redactItem) };
  if (result.structuredContent !== undefined) {
    const red = redactResultJson(result.structuredContent);
    if (isRecord(red)) {
      out.structuredContent = red;
    } else {
      delete out.structuredContent;
    }
  }
  return out;
}
