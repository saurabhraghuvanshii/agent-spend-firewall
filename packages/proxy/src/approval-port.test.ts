import { canonicalJson, UNTRUSTED_REASON_LABEL, type Args } from "@asf/core";
import { describe, expect, it } from "vitest";
import {
  approvalArgsHash,
  argsForDisplay,
  createInMemoryApprovalStub,
  STUB_MAX_REQUESTS,
  reasonForDisplay,
  type PendingApprovalRequest,
} from "./approval-port.js";
import { nodeHasher } from "./node-hasher.js";

const ARGS: Args = { payment_id: "pay_1", amount: 300_000 };

function req(over: Partial<PendingApprovalRequest> = {}): PendingApprovalRequest {
  return {
    attemptId: "att-1",
    tool: "create_refund",
    finalArgs: ARGS,
    finalArgsRedacted: argsForDisplay(ARGS),
    argsHash: "0".repeat(64),
    untrustedReason: "a reason",
    reasonForDisplay: reasonForDisplay("a reason"),
    sessionId: "s",
    ruleId: "refund.approval",
    message: "needs approval",
    via: "telegram",
    timeoutMin: 30,
    matchedRules: ["refund.approval"],
    ...over,
  };
}

describe("approvalArgsHash", () => {
  it("is sha256 of canonicalJson({tool, args}) and independent of key order", () => {
    const h = approvalArgsHash("create_refund", ARGS);
    const canon = canonicalJson({ tool: "create_refund", args: ARGS });
    expect(canon.ok).toBe(true);
    if (!canon.ok || !h.ok) return;
    expect(h.value).toBe(nodeHasher.sha256Hex(canon.value));
    expect(approvalArgsHash("create_refund", { amount: 300_000, payment_id: "pay_1" })).toEqual(h);
    expect(approvalArgsHash("create_refund", { ...ARGS, amount: 300_001 })).not.toEqual(h);
    expect(approvalArgsHash("update_refund", ARGS)).not.toEqual(h);
  });

  it("errs on args that can't be canonicalised", () => {
    const r = approvalArgsHash("create_refund", { amount: 1.5 });
    expect(!r.ok && r.error.code).toBe("approval.unhashable_args");
  });
});

describe("reasonForDisplay", () => {
  it("labels, escapes and PII-scrubs the agent's reason", () => {
    const f = reasonForDisplay(`refund bob@example.com ${String.fromCodePoint(0x202e)}evil\nnext`);
    expect(f.label).toBe(UNTRUSTED_REASON_LABEL);
    expect(f.text).not.toContain("bob@example.com");
    expect(f.text).toContain("\\u{202E}");
    expect(f.text).toContain("\\n");
  });
});

describe("createInMemoryApprovalStub", () => {
  it("records requests and returns unique apr_<uuid> ids", async () => {
    const stub = createInMemoryApprovalStub();
    const a = await stub.create(req());
    const b = await stub.create(req({ attemptId: "att-2" }));
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.value.approvalId).toMatch(/^apr_[0-9a-f-]{36}$/);
    expect(a.value.approvalId).not.toBe(b.value.approvalId);
    expect(stub.requests.map((r) => r.attemptId)).toEqual(["att-1", "att-2"]);
  });
});

describe("argsForDisplay", () => {
  it("redacts PII but keeps ids and amounts", () => {
    expect(
      argsForDisplay({
        payment_id: "pay_1",
        amount: 300_000,
        customer_email: "bob@example.com",
        notes: { contact: "9876543210", memo: "call 9876543210" },
      }),
    ).toEqual({
      payment_id: "pay_1",
      amount: 300_000,
      customer_email: "[REDACTED]",
      notes: { contact: "[REDACTED]", memo: "call [REDACTED]" },
    });
  });
});

describe("createInMemoryApprovalStub cap", () => {
  it(`keeps only the last ${String(STUB_MAX_REQUESTS)} requests`, async () => {
    const stub = createInMemoryApprovalStub();
    for (let i = 0; i < STUB_MAX_REQUESTS + 5; i++) {
      await stub.create(req({ attemptId: `att-${String(i)}` }));
    }
    expect(stub.requests).toHaveLength(STUB_MAX_REQUESTS);
    expect(stub.requests[0]?.attemptId).toBe("att-5");
    expect(stub.requests.at(-1)?.attemptId).toBe(`att-${String(STUB_MAX_REQUESTS + 4)}`);
  });
});
