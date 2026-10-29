import { describe, expect, it } from "vitest";
import { cap, createTranscript } from "./transcript.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };

describe("createTranscript", () => {
  it("prints tool calls and REDACTED results (card / email / VPA / keys), mapped to the tool name", () => {
    const t = createTranscript(KEYS);
    const call = t.lines({
      type: "assistant",
      message: {
        content: [
          { type: "text", text: "Looking up the payment." },
          {
            type: "tool_use",
            id: "tu1",
            name: "mcp__razorpay__fetch_payment",
            input: { payment_id: "pay_A" },
          },
        ],
      },
    });
    expect(call).toEqual([
      "  agent: Looking up the payment.",
      '  → mcp__razorpay__fetch_payment {"payment_id":"pay_A"}',
    ]);
    const res = t.lines({
      type: "user",
      message: {
        content: [
          {
            type: "tool_result",
            tool_use_id: "tu1",
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  id: "pay_A",
                  email: "alice@example.com",
                  contact: "+919999999999",
                  vpa: "alice@okhdfc",
                  card: { last4: "1111", number: "4111111111111111" },
                  description: `key ${KEYS.keySecret}`,
                }),
              },
            ],
          },
        ],
      },
    });
    const line = res.join("\n");
    expect(line).toMatch(/← mcp__razorpay__fetch_payment:/);
    for (const s of [
      "alice@example.com",
      "+919999999999",
      "alice@okhdfc",
      "4111111111111111",
      KEYS.keySecret,
    ]) {
      expect(line).not.toContain(s);
    }
    expect(line).toContain("pay_A");
  });

  it("marks errors, escapes control characters, prints the result line; ignores unknown shapes", () => {
    const t = createTranscript(KEYS);
    expect(
      t.lines({
        type: "user",
        message: {
          content: [
            { type: "tool_result", tool_use_id: "zz", is_error: true, content: "bad\u001b[31m" },
          ],
        },
      })[0],
    ).toMatch(/^ {2}← unknown \[isError\]: bad\\u001b\[31m$/);
    expect(t.lines({ type: "result", subtype: "success", num_turns: 3 })).toEqual([
      "  [done: success, 3 turns]",
    ]);
    expect(t.lines({ type: "weird" })).toEqual([]);
    expect(t.lines(null)).toEqual([]);
  });

  it("caps long text", () => {
    expect(cap("x".repeat(700)).length).toBeLessThan(700);
  });
});
