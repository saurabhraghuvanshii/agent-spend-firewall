/** Label that must accompany an agent-supplied reason wherever a human sees it. */
export const UNTRUSTED_REASON_LABEL = "Agent-supplied reason (untrusted)" as const;

export const UNTRUSTED_REASON_DEFAULT_MAX_CHARS = 500;

export interface FormattedUntrusted {
  label: typeof UNTRUSTED_REASON_LABEL;
  /** Quoted, escaped, single-line text. NOT escaped for any markup language. */
  text: string;
}

/**
 * Code points rendered as `\u{XXXX}` escapes:
 * - `\p{Cc}` control (C0, DEL, C1) — `\n` and `\t` are handled separately as visible `\n` / `\t`
 * - `\p{Cf}` format (ZWSP, ZWJ, ZWNJ, LRM/RLM, ALM, bidi embeddings/overrides/isolates, BOM, tag chars, …)
 * - `\p{Zl}` / `\p{Zp}` line / paragraph separators (U+2028, U+2029)
 * - `\p{Co}` private use, `\p{Cn}` unassigned, `\p{Cs}` lone surrogates
 * - blank "filler" letters that render as empty space: U+115F, U+1160, U+3164, U+FFA0, U+2800
 */
const ESCAPE_RE = /^[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}\p{Cs}ᅟᅠㅤﾠ⠀]$/u;

function escapeCodePoint(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  return `\\u{${cp.toString(16).toUpperCase().padStart(4, "0")}}`;
}

function renderChar(ch: string): string {
  switch (ch) {
    case "\n":
      return "\\n";
    case "\t":
      return "\\t";
    case "\\":
      return "\\\\";
    case '"':
      return '\\"';
    default:
      return ESCAPE_RE.test(ch) ? escapeCodePoint(ch) : ch;
  }
}

/**
 * Render an agent-supplied reason so a human can see exactly what the agent wrote, without invisible
 * or direction-changing characters being able to disguise it.
 *
 * - Truncates to `maxChars` Unicode code points (of the input), appending `…` when cut.
 * - Escapes `\n` → `\n`, `\t` → `\t`, `\` → `\\`, `"` → `\"`; every other control, format, bidi, line/paragraph
 *   separator, private-use, unassigned, lone-surrogate or blank-filler code point becomes `\u{XXXX}`.
 *   Ordinary text in any script (Hindi, emoji, …) is preserved as-is.
 * - Wraps the result in straight double quotes. The output is a single line.
 * - Non-string input (runtime guard) yields `""`. An invalid `maxChars` falls back to the default.
 *
 * This does NOT escape HTML, Markdown or any other markup: consumers (Telegram in T011, the dashboard in T014)
 * MUST additionally escape `text` (and render `label`) for their own medium.
 */
export function formatUntrustedReason(
  s: string,
  maxChars: number = UNTRUSTED_REASON_DEFAULT_MAX_CHARS,
): FormattedUntrusted {
  const limit =
    Number.isSafeInteger(maxChars) && maxChars >= 0 ? maxChars : UNTRUSTED_REASON_DEFAULT_MAX_CHARS;
  if (typeof s !== "string") return { label: UNTRUSTED_REASON_LABEL, text: '""' };

  let out = "";
  let count = 0;
  let truncated = false;
  for (const ch of s) {
    if (count >= limit) {
      truncated = true;
      break;
    }
    out += renderChar(ch);
    count++;
  }
  return { label: UNTRUSTED_REASON_LABEL, text: `"${out}${truncated ? "…" : ""}"` };
}
