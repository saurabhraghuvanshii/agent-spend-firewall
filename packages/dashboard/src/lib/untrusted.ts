/**
 * Display helpers for agent-supplied text (T008 review, D-036). Everything the agent controls (reason, notes,
 * description, customer_name, any arg key or value) goes through core `formatUntrustedReason` before it is shown: one
 * line, quoted, invisible / bidi / control characters as visible `\u{…}` escapes, truncated. React then renders it as a
 * text node (no `dangerouslySetInnerHTML`, no markdown, no auto-linking), so HTML / script strings stay inert.
 */
import { formatUntrustedReason } from "@asf/core";
import type { JsonValue, UntrustedTextView } from "../api/schemas";

export { UNTRUSTED_REASON_LABEL } from "@asf/core";

/** Same classes core escapes; anything matching here was NOT produced by the formatter. */
const UNSAFE_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}\p{Cs}ᅟᅠㅤﾠ⠀]/u;
const PLAIN_ID_RE = /^[\x21-\x7E]{1,256}$/;
const MAX_PREFORMATTED_CHARS = 4000;
export const ARG_VALUE_MAX_CHARS = 200;

/** Every `"` inside is backslash-escaped and no trailing lone `\` escapes the closing quote (formatter output). */
function innerQuotesEscaped(inner: string): boolean {
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === "\\") {
      if (i === inner.length - 1) return false;
      i += 1;
    } else if (c === '"') return false;
  }
  return true;
}

/** Agent text from the API's `{ untrusted, text }` (already formatted server-side): re-checked, re-formatted if odd. */
export function displayReason(reason: UntrustedTextView | undefined): string {
  if (reason === undefined) return '""';
  const t = reason.text;
  const looksFormatted =
    t.length >= 2 &&
    t.length <= MAX_PREFORMATTED_CHARS &&
    t.startsWith('"') &&
    t.endsWith('"') &&
    !UNSAFE_RE.test(t) &&
    innerQuotesEscaped(t.slice(1, -1));
  return looksFormatted ? t : formatUntrustedReason(t).text;
}

/** A raw agent-supplied string. */
export function displayUntrusted(raw: string, maxChars = ARG_VALUE_MAX_CHARS): string {
  return formatUntrustedReason(raw, maxChars).text;
}

/** Identifiers (tool, session, rule ids): shown as-is when plain printable ASCII, else formatted like agent text. */
export function displayId(raw: string): string {
  return PLAIN_ID_RE.test(raw) ? raw : formatUntrustedReason(raw, 128).text;
}

export interface ArgLine {
  readonly path: string;
  readonly value: string;
}

const MAX_ARG_LINES = 60;
const MAX_ARG_DEPTH = 5;

/** Flatten redacted args into `path = value` lines; keys and string values are agent text, formatted. */
export function flattenArgs(value: JsonValue): ArgLine[] {
  const out: ArgLine[] = [];
  const key = (k: string): string =>
    /^[A-Za-z0-9_-]{1,64}$/.test(k) ? k : displayUntrusted(k, 64);
  const walk = (v: JsonValue, path: string, depth: number): void => {
    if (out.length >= MAX_ARG_LINES) return;
    if (v === null || typeof v !== "object") {
      out.push({
        path: path === "" ? "(value)" : path,
        value: typeof v === "string" ? displayUntrusted(v) : String(v),
      });
      return;
    }
    if (depth >= MAX_ARG_DEPTH) {
      out.push({ path, value: "…" });
      return;
    }
    const entries: Array<[string, JsonValue]> = Array.isArray(v)
      ? v.map((x, i): [string, JsonValue] => [`[${String(i)}]`, x])
      : Object.entries(v).map(([k, x]): [string, JsonValue] => [key(k), x]);
    if (entries.length === 0) {
      out.push({ path: path === "" ? "(value)" : path, value: Array.isArray(v) ? "[]" : "{}" });
      return;
    }
    for (const [k, x] of entries) {
      const p = k.startsWith("[") ? `${path}${k}` : path === "" ? k : `${path}.${k}`;
      walk(x, p, depth + 1);
    }
  };
  walk(value, "", 0);
  if (out.length >= MAX_ARG_LINES) out.push({ path: "…", value: "(truncated)" });
  return out;
}
