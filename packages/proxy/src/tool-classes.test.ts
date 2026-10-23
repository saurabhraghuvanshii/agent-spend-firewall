import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TOOL_CLASSES, classifyTool, isMoneyTool } from "./tool-classes.js";
import { toolsFileSchema } from "./tool-discovery.js";

const TOOLS_JSON = fileURLToPath(new URL("../../../docs/razorpay-tools.json", import.meta.url));

function discoveredNames(): string[] {
  const file = toolsFileSchema.parse(JSON.parse(readFileSync(TOOLS_JSON, "utf8")));
  return file.tools.map((t) => t.name);
}

describe("classifyTool", () => {
  it("unknown tool names are money (fail closed)", () => {
    expect(classifyTool("create_payout")).toBe("money");
    expect(classifyTool("some_new_tool")).toBe("money");
    expect(classifyTool("")).toBe("money");
    expect(isMoneyTool("totally_unknown")).toBe(true);
  });

  it("prototype property names are money", () => {
    for (const n of [
      "constructor",
      "__proto__",
      "toString",
      "hasOwnProperty",
      "valueOf",
      "prototype",
    ]) {
      expect(classifyTool(n)).toBe("money");
    }
  });

  it("case and whitespace variants of read tools are money", () => {
    for (const n of [
      "FETCH_PAYMENT",
      "Fetch_payment",
      " fetch_payment",
      "fetch_payment ",
      "fetch_payment\n",
      "fetch-payment",
    ]) {
      expect(classifyTool(n)).toBe("money");
    }
    expect(classifyTool("fetch_payment")).toBe("read");
  });

  it("refunds, payment links, order/payment creation and updates are money", () => {
    for (const n of [
      "create_refund",
      "update_refund",
      "create_payment_link",
      "payment_link_upi_create",
      "update_payment_link",
      "payment_link_notify",
      "create_order",
      "update_order",
      "capture_payment",
      "initiate_payment",
      "update_payment",
      "create_instant_settlement",
      "create_qr_code",
      "close_qr_code",
      "submit_otp",
      "resend_otp",
    ]) {
      expect(classifyTool(n)).toBe("money");
    }
  });

  it("fetch_tokens is money (creates a customer as a side effect)", () => {
    expect(classifyTool("fetch_tokens")).toBe("money");
  });

  it("the map is frozen", () => {
    expect(Object.isFrozen(TOOL_CLASSES)).toBe(true);
    expect(() => {
      (TOOL_CLASSES as Record<string, string>)["create_refund"] = "read";
    }).toThrow(TypeError);
    expect(classifyTool("create_refund")).toBe("money");
  });

  it("non-string input is money", () => {
    expect(classifyTool(undefined as unknown as string)).toBe("money");
    expect(classifyTool(42 as unknown as string)).toBe("money");
  });
});

describe("coverage against docs/razorpay-tools.json", () => {
  const names = discoveredNames();

  it("every discovered tool is explicitly classified", () => {
    const missing = names.filter((n) => !Object.hasOwn(TOOL_CLASSES, n));
    expect(missing).toEqual([]);
  });

  it("no stale entries: every classified tool was discovered", () => {
    const stale = Object.keys(TOOL_CLASSES).filter((n) => !names.includes(n));
    expect(stale).toEqual([]);
  });

  it("names with money verbs/nouns (outside fetch_) are money", () => {
    const moneyish =
      /(^|_)(refund|payout|transfer|create|update|cancel|capture|close|reverse|initiate|submit|resend|notify|revoke|settle)/;
    for (const n of [...names, ...Object.keys(TOOL_CLASSES)]) {
      if (moneyish.test(n) && !n.startsWith("fetch_")) expect(classifyTool(n), n).toBe("money");
      if (
        /(^|_)(create|update|cancel|capture|close|reverse|initiate|submit|resend|notify|revoke)(_|$)/.test(
          n,
        )
      ) {
        expect(classifyTool(n), n).toBe("money");
      }
    }
  });

  it("only fetch_* tools are ever read", () => {
    for (const [n, c] of Object.entries(TOOL_CLASSES)) {
      if (c === "read") expect(n.startsWith("fetch_"), n).toBe(true);
    }
  });
});
