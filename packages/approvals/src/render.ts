/**
 * Telegram (HTML parse mode) rendering of approval requests and resolutions (T011).
 *
 * Display rules (D-030, T008 review):
 * - Only REDACTED args are ever shown (`argsRedacted` = core `redact(finalArgs)`); never raw `finalArgs`.
 * - EVERY dynamic string — the agent's reason, every arg key and string value (notes, description, customer_name,
 *   the payment id, …), the tool name, rule ids and the policy message — goes through core `formatUntrustedReason`
 *   (quoted, control / bidi / invisible chars escaped, length-capped) and THEN `escapeHtml`. Only fixed labels are
 *   markup. The reason is shown under the `UNTRUSTED_REASON_LABEL` label.
 * - Amounts are integer paise rendered as ₹ with integer arithmetic only (no floats); a non-integer amount is shown as
 *   "invalid" (the firewall never forwards one anyway).
 */
import {
  formatUntrustedReason,
  UNTRUSTED_REASON_LABEL,
  type FormattedUntrusted,
  type JsonValue,
} from "@asf/core";
import type { ApprovalExecution, ApprovalState } from "./store.js";

/** Telegram's message limit is 4096 characters; stay well below it (entities expand on our side only). */
export const MAX_MESSAGE_CHARS = 3500;
/** Max lines of the redacted-args listing. */
export const MAX_ARG_LINES = 40;
const MAX_VALUE_CHARS = 200;
const MAX_KEY_CHARS = 80;
const MAX_DEPTH = 6;

export interface ApprovalNotice {
  readonly approvalId: string;
  readonly tool: string;
  /** `redact(finalArgs)`: the ONLY form of the args an approver may see. */
  readonly argsRedacted: JsonValue;
  /** `formatUntrustedReason(redactText(reason))` (already PII-scrubbed and escaped, NOT HTML-escaped). */
  readonly reason: FormattedUntrusted;
  readonly ruleId: string;
  /** Policy-authored message (trusted, still escaped). */
  readonly policyMessage: string;
  readonly expiresAtMs: number;
}

/** Escape for Telegram HTML parse mode. */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Any dynamic string: untrusted formatting (quoted, escaped, capped) + HTML escaping. */
export function show(s: string, maxChars: number = MAX_VALUE_CHARS): string {
  return escapeHtml(formatUntrustedReason(s, maxChars).text);
}

/** Integer paise ⇒ `₹1,23,456.78` (Indian digit grouping); anything else ⇒ `undefined`. */
export function formatPaise(amountPaise: unknown): string | undefined {
  if (typeof amountPaise !== "number" || !Number.isSafeInteger(amountPaise) || amountPaise < 0) {
    return undefined;
  }
  const rupees = String(Math.trunc(amountPaise / 100));
  const paise = String(amountPaise % 100).padStart(2, "0");
  let grouped = rupees;
  if (rupees.length > 3) {
    const head = rupees.slice(0, -3);
    const tail = rupees.slice(-3);
    grouped = `${head.replace(/\B(?=(\d{2})+(?!\d))/g, ",")},${tail}`;
  }
  return `₹${grouped}.${paise}`;
}

/** Flatten redacted args to `path = value` lines (strings formatted as untrusted; HTML-escaped). */
export function argLines(value: JsonValue, maxLines: number = MAX_ARG_LINES): string[] {
  const out: string[] = [];
  let truncated = false;
  const walk = (v: JsonValue, path: string, depth: number): void => {
    if (out.length >= maxLines) {
      truncated = true;
      return;
    }
    const label = path === "" ? "(args)" : path;
    const key = show(label, MAX_KEY_CHARS);
    if (v === null || typeof v === "boolean" || typeof v === "number") {
      out.push(
        `${key} = ${typeof v === "number" && !Number.isSafeInteger(v) ? "invalid" : String(v)}`,
      );
      return;
    }
    if (typeof v === "string") {
      out.push(`${key} = ${show(v)}`);
      return;
    }
    if (depth >= MAX_DEPTH) {
      out.push(`${key} = (nested too deep)`);
      return;
    }
    const entries: Array<[string, JsonValue]> = Array.isArray(v)
      ? v.map((x, i) => [String(i), x])
      : Object.entries(v);
    if (entries.length === 0) {
      out.push(`${key} = ${Array.isArray(v) ? "[]" : "{}"}`);
      return;
    }
    for (const [k, x] of entries) walk(x, path === "" ? k : `${path}.${k}`, depth + 1);
  };
  walk(value, "", 0);
  if (truncated) out.push("… (more arguments not shown)");
  return out;
}

function topLevel(args: JsonValue, key: string): JsonValue | undefined {
  if (typeof args !== "object" || args === null || Array.isArray(args)) return undefined;
  return Object.hasOwn(args, key) ? args[key] : undefined;
}

function isoOf(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "unknown" : d.toISOString();
}

/** The approval request message (Telegram HTML). */
export function renderApprovalMessage(n: ApprovalNotice): string {
  const amount = topLevel(n.argsRedacted, "amount");
  const payment = topLevel(n.argsRedacted, "payment_id");
  const head = [
    `<b>Approval required</b>: ${show(n.tool, 64)}`,
    amount === undefined
      ? "<b>Amount:</b> (none)"
      : `<b>Amount:</b> ${escapeHtml(formatPaise(amount) ?? "invalid")}${
          typeof amount === "number" && Number.isSafeInteger(amount)
            ? ` (${String(amount)} paise)`
            : ""
        }`,
    `<b>Payment:</b> ${typeof payment === "string" ? show(payment, 64) : "(none)"}`,
    `<b>Rule:</b> ${show(n.ruleId, 128)}: ${show(n.policyMessage, 300)}`,
    `<b>${escapeHtml(UNTRUSTED_REASON_LABEL)}:</b>`,
    `<i>${escapeHtml(n.reason.text)}</i>`,
    "<b>Arguments (redacted):</b>",
  ];
  const tail = [
    `<b>Expires:</b> ${escapeHtml(isoOf(n.expiresAtMs))}`,
    `<b>Approval:</b> ${show(n.approvalId, 64)}`,
  ];
  const fixed = head.join("\n").length + tail.join("\n").length + "<pre></pre>\n\n".length;
  const lines: string[] = [];
  let used = 0;
  for (const l of argLines(n.argsRedacted)) {
    if (fixed + used + l.length + 1 > MAX_MESSAGE_CHARS) {
      lines.push("… (more arguments not shown)");
      break;
    }
    lines.push(l);
    used += l.length + 1;
  }
  return [...head, `<pre>${lines.join("\n")}</pre>`, ...tail].join("\n");
}

export interface ResolutionView {
  readonly approvalId: string;
  readonly state: ApprovalState;
  readonly decidedBy?: string;
  readonly decidedAtMs?: number;
  readonly execution?: ApprovalExecution;
}

/** Replacement text once an approval is decided / expired (buttons removed). */
export function renderResolution(v: ResolutionView): string {
  const who = v.decidedBy === undefined ? "" : ` by ${show(v.decidedBy, 64)}`;
  const when = v.decidedAtMs === undefined ? "" : ` at ${escapeHtml(isoOf(v.decidedAtMs))}`;
  const state =
    v.state === "approved"
      ? "APPROVED"
      : v.state === "rejected"
        ? "REJECTED"
        : v.state === "expired"
          ? "EXPIRED (treated as rejected)"
          : "PENDING";
  const lines = [`<b>Approval ${show(v.approvalId, 64)}</b>: ${state}${who}${when}`];
  if (v.execution !== undefined) {
    const ref =
      v.execution.upstreamRef === undefined ? "" : ` ${show(v.execution.upstreamRef, 64)}`;
    const code = v.execution.code === undefined ? "" : ` (${show(v.execution.code, 64)})`;
    lines.push(`<b>Execution:</b> ${escapeHtml(v.execution.status)}${ref}${code}`);
  }
  return lines.join("\n");
}
