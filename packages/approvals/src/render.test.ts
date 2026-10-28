import { formatUntrustedReason, redact, redactText, UNTRUSTED_REASON_LABEL } from "@asf/core";
import { describe, expect, it } from "vitest";
import {
  argLines,
  escapeHtml,
  formatPaise,
  MAX_MESSAGE_CHARS,
  renderApprovalMessage,
  renderResolution,
  type ApprovalNotice,
} from "./render.js";

const RLO = String.fromCodePoint(0x202e);

function notice(over: Partial<ApprovalNotice> = {}): ApprovalNotice {
  return {
    approvalId: "apr_11111111-1111-4111-8111-111111111111",
    tool: "create_refund",
    argsRedacted: redact({ payment_id: "pay_ABC123", amount: 300_000 }),
    reason: formatUntrustedReason(redactText("customer was double charged")),
    ruleId: "refund.approval",
    policyMessage: "Refunds over ₹2,000 need a human",
    expiresAtMs: Date.parse("2026-10-23T10:30:00.000Z"),
    ...over,
  };
}

describe("formatPaise", () => {
  it("renders integer paise as ₹ with Indian grouping", () => {
    expect(formatPaise(0)).toBe("₹0.00");
    expect(formatPaise(5)).toBe("₹0.05");
    expect(formatPaise(300_000)).toBe("₹3,000.00");
    expect(formatPaise(12_345_678)).toBe("₹1,23,456.78");
    expect(formatPaise(10_000_000_000)).toBe("₹10,00,00,000.00");
  });
  it("refuses non-integer, negative and non-number amounts", () => {
    for (const bad of [1.5, -1, "300", Number.NaN, Number.MAX_SAFE_INTEGER + 2, null]) {
      expect(formatPaise(bad)).toBeUndefined();
    }
  });
});

describe("renderApprovalMessage", () => {
  it("shows tool, ₹ amount, payment id, labelled untrusted reason, rule and expiry", () => {
    const html = renderApprovalMessage(notice());
    expect(html).toContain("create_refund");
    expect(html).toContain("₹3,000.00 (300000 paise)");
    expect(html).toContain("&quot;pay_ABC123&quot;");
    expect(html).toContain(`<b>${UNTRUSTED_REASON_LABEL}:</b>`);
    expect(html).toContain("&quot;customer was double charged&quot;");
    expect(html).toContain("refund.approval");
    expect(html).toContain("2026-10-23T10:30:00.000Z");
  });

  it("escapes HTML and invisible / bidi characters in every agent-controlled string", () => {
    const evil = `<a href="x">click</a> & ${RLO}gnp.exe`;
    const html = renderApprovalMessage(
      notice({
        reason: formatUntrustedReason(evil),
        argsRedacted: redact({
          payment_id: `pay_X</code><b>`,
          amount: 300_000,
          notes: { [`<i>k${RLO}</i>`]: evil },
          description: evil,
          customer_name: `Bob${RLO}`,
        }),
      }),
    );
    // The only tags are the fixed labels.
    const tags = html.match(/<\/?[a-z]+[^>]*>/g) ?? [];
    expect(new Set(tags)).toEqual(new Set(["<b>", "</b>", "<i>", "</i>", "<pre>", "</pre>"]));
    expect(html).not.toContain(RLO);
    expect(html).toContain("\\u{202E}");
    expect(html).toContain("&lt;a href=");
    expect(html).toContain("&amp;");
  });

  it("only ever shows redacted args (PII from the caller's redact is never rendered)", () => {
    const html = renderApprovalMessage(
      notice({
        argsRedacted: redact({
          payment_id: "pay_1",
          amount: 100,
          customer_email: "bob@example.com",
          notes: { memo: "call 9876543210" },
        }),
      }),
    );
    expect(html).not.toContain("bob@example.com");
    expect(html).not.toContain("9876543210");
    expect(html).toContain("[REDACTED]");
  });

  it("shows an invalid or missing amount without inventing one", () => {
    expect(renderApprovalMessage(notice({ argsRedacted: { amount: "300" } }))).toContain(
      "<b>Amount:</b> invalid",
    );
    expect(renderApprovalMessage(notice({ argsRedacted: {} }))).toContain("<b>Amount:</b> (none)");
  });

  it("stays below Telegram's message limit with huge args", () => {
    const notes: Record<string, string> = {};
    for (let i = 0; i < 100; i++) notes[`k${String(i)}`] = "x".repeat(500);
    const html = renderApprovalMessage(notice({ argsRedacted: { amount: 1, notes } }));
    expect(html.length).toBeLessThanOrEqual(MAX_MESSAGE_CHARS + 100);
    expect(html).toContain("more arguments not shown");
  });
});

describe("argLines / escapeHtml / renderResolution", () => {
  it("flattens nested args and caps depth and lines", () => {
    expect(argLines({ a: 1, b: { c: "x" }, d: [], e: null })).toEqual([
      "&quot;a&quot; = 1",
      "&quot;b.c&quot; = &quot;x&quot;",
      "&quot;d&quot; = []",
      "&quot;e&quot; = null",
    ]);
    const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
    expect(argLines(deep).join("\n")).toContain("nested too deep");
    expect(argLines({ a: 1, b: 2, c: 3 }, 2).at(-1)).toContain("more arguments");
  });

  it("escapes the four HTML-significant characters", () => {
    expect(escapeHtml(`<&>"`)).toBe("&lt;&amp;&gt;&quot;");
  });

  it("renders decisions, expiry and execution", () => {
    const base = { approvalId: "apr_1" };
    expect(
      renderResolution({
        ...base,
        state: "approved",
        decidedBy: "telegram:42",
        decidedAtMs: 0,
        execution: { status: "executed", upstreamRef: "rfnd_1" },
      }),
    ).toContain("APPROVED by &quot;telegram:42&quot; at 1970-01-01T00:00:00.000Z");
    expect(renderResolution({ ...base, state: "expired" })).toContain(
      "EXPIRED (treated as rejected)",
    );
    expect(renderResolution({ ...base, state: "rejected", decidedBy: "telegram:1" })).toContain(
      "REJECTED",
    );
  });
});
