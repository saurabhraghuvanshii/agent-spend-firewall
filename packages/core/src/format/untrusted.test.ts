import { describe, expect, it } from "vitest";
import {
  UNTRUSTED_REASON_DEFAULT_MAX_CHARS,
  UNTRUSTED_REASON_LABEL,
  formatUntrustedReason,
} from "./untrusted.js";

const text = (s: string, max?: number): string => formatUntrustedReason(s, max).text;

describe("formatUntrustedReason", () => {
  it("always returns the constant label", () => {
    expect(UNTRUSTED_REASON_LABEL).toBe("Agent-supplied reason (untrusted)");
    expect(formatUntrustedReason("x").label).toBe(UNTRUSTED_REASON_LABEL);
    expect(formatUntrustedReason("").label).toBe(UNTRUSTED_REASON_LABEL);
  });

  it("wraps plain text in straight double quotes", () => {
    expect(text("duplicate charge on pay_1")).toBe('"duplicate charge on pay_1"');
    expect(text("")).toBe('""');
  });

  it("escapes inner double quotes and backslashes", () => {
    expect(text('say "approve"')).toBe('"say \\"approve\\""');
    expect(text("a\\u{202E}b")).toBe('"a\\\\u{202E}b"');
  });

  it("escapes the bidi override U+202E and other bidi controls", () => {
    expect(text("refund ‮evil")).toBe('"refund \\u{202E}evil"');
    expect(text("⁦x⁩‎‏؜")).toBe('"\\u{2066}x\\u{2069}\\u{200E}\\u{200F}\\u{061C}"');
  });

  it("escapes zero-width characters (ZWSP, ZWJ, ZWNJ, BOM)", () => {
    expect(text("a​b‍c‌d﻿")).toBe('"a\\u{200B}b\\u{200D}c\\u{200C}d\\u{FEFF}"');
  });

  it("escapes line and paragraph separators", () => {
    expect(text("a b c")).toBe('"a\\u{2028}b\\u{2029}c"');
  });

  it("renders \\n and \\t visibly and escapes other C0/C1/DEL controls", () => {
    expect(text("a\nb\tc")).toBe('"a\\nb\\tc"');
    expect(text("a\rb\u0000c\u001Bd\u007Fe\u0085f\u009Bg")).toBe(
      '"a\\u{000D}b\\u{0000}c\\u{001B}d\\u{007F}e\\u{0085}f\\u{009B}g"',
    );
    expect(text("x\ny")).not.toContain("\n");
  });

  it("escapes private-use, unassigned, tag characters and lone surrogates", () => {
    expect(text("")).toBe('"\\u{E000}"');
    expect(text("\u{F0000}")).toBe('"\\u{F0000}"');
    expect(text("\u{E0041}")).toBe('"\\u{E0041}"'); // TAG LATIN CAPITAL A (Cf)
    expect(text("\u{10FFFE}")).toBe('"\\u{10FFFE}"'); // noncharacter (Cn)
    expect(text("a\uD800b")).toBe('"a\\u{D800}b"');
  });

  it("escapes blank filler characters", () => {
    expect(text("ᅟᅠㅤﾠ⠀")).toBe('"\\u{115F}\\u{1160}\\u{3164}\\u{FFA0}\\u{2800}"');
  });

  it("preserves Hindi, emoji and other ordinary scripts", () => {
    const s = "ग्राहक को दो बार चार्ज किया गया 😀 €5 日本";
    expect(text(s)).toBe(`"${s}"`);
  });

  it("truncates to maxChars code points with an ellipsis", () => {
    expect(text("abcdef", 3)).toBe('"abc…"');
    expect(text("abc", 3)).toBe('"abc"');
    expect(text("😀😀😀😀", 2)).toBe('"😀😀…"');
    expect(text("abc", 0)).toBe('"…"');
  });

  it("defaults to 500 code points", () => {
    expect(UNTRUSTED_REASON_DEFAULT_MAX_CHARS).toBe(500);
    expect(text("a".repeat(500))).toBe(`"${"a".repeat(500)}"`);
    expect(text("a".repeat(501))).toBe(`"${"a".repeat(500)}…"`);
  });

  it("falls back to the default for an invalid maxChars", () => {
    for (const bad of [Number.NaN, -1, 2.5, Number.POSITIVE_INFINITY]) {
      expect(text("a".repeat(501), bad)).toBe(`"${"a".repeat(500)}…"`);
    }
  });

  it("truncation never leaves a dangling half-escape", () => {
    expect(text("ab‮cd", 3)).toBe('"ab\\u{202E}…"');
  });

  it("returns a safe empty string for non-string input", () => {
    for (const bad of [undefined, null, 42, { toString: () => "‮" }, ["x"]]) {
      expect(formatUntrustedReason(bad as unknown as string)).toEqual({
        label: UNTRUSTED_REASON_LABEL,
        text: '""',
      });
    }
  });

  it("does not HTML-escape (caller's responsibility)", () => {
    expect(text("<b>&</b>")).toBe('"<b>&</b>"');
  });
});
