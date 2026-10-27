import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { DUPLICATE_MESSAGES } from "./idempotency.js";
import {
  duplicateDenyResult,
  pendingApprovalResult,
  unknownOutcomeResult,
  verifiedSuccessResult,
} from "./interceptor.js";
import {
  isRestorableRefId,
  isUnknownOutcomeBody,
  isVerifiedSuccessBody,
  UNKNOWN_OUTCOME_MESSAGE,
  VERIFIED_AFTER_TIMEOUT_MESSAGE,
  VERIFIED_AFTER_TIMEOUT_PENDING_MESSAGE,
  NON_TEXT_PLACEHOLDER,
  redactResultJson,
  redactSensitiveResult,
  REDACTION_EXEMPT_TOOLS,
  restoreRefIds,
} from "./result-redaction.js";

const text = (t: string): CallToolResult => ({ content: [{ type: "text", text: t }] });
const json = (v: unknown): CallToolResult => text(JSON.stringify(v));
const bodyOf = (r: CallToolResult): unknown => {
  const first = r.content[0];
  return first?.type === "text" ? JSON.parse(first.text) : undefined;
};

const CARD = {
  id: "card_ABC123",
  entity: "card",
  name: "Gaurav Kumar",
  last4: "1111",
  iin: "411111",
  network: "Visa",
  type: "credit",
  issuer: "HDFC",
};

const PAYMENT = {
  id: "pay_ABC123",
  amount: 50_000,
  currency: "INR",
  status: "captured",
  method: "card",
  card_id: "card_ABC123",
  customer_id: "cust_ABC123",
  email: "gaurav@example.com",
  contact: "+919876543210",
  vpa: "gaurav@okhdfc",
  token_id: "token_ABC123",
  card: CARD,
  bank_account: { account_number: "123456789012", ifsc: "HDFC0000001", name: "G K" },
  notes: { note: "call 9876543210" },
};

describe("redactSensitiveResult", () => {
  it("redacts every tool by default: the exempt list is empty", () => {
    expect([...REDACTION_EXEMPT_TOOLS]).toEqual([]);
  });

  it("fetch_payment_card_details: card PII removed, ids and non-sensitive fields kept", () => {
    const out = bodyOf(redactSensitiveResult("fetch_payment_card_details", json(CARD)));
    expect(out).toEqual({
      ...CARD,
      name: "[REDACTED]",
      last4: "[REDACTED]",
      iin: "[REDACTED]",
    });
  });

  it("fetch_payment: PII / card / bank removed; amounts, status, currency and *_id refs kept", () => {
    const r = redactSensitiveResult("fetch_payment", json(PAYMENT));
    const out = bodyOf(r) as Record<string, unknown>;
    expect(out).toMatchObject({
      id: "pay_ABC123",
      amount: 50_000,
      currency: "INR",
      status: "captured",
      card_id: "card_ABC123",
      customer_id: "cust_ABC123",
      token_id: "token_ABC123",
      email: "[REDACTED]",
      contact: "[REDACTED]",
      vpa: "[REDACTED]",
      card: "[REDACTED]",
      bank_account: "[REDACTED]",
      notes: { note: "call [REDACTED]" },
    });
    const s = JSON.stringify(r);
    for (const secret of ["gaurav@", "9876543210", "1111", "411111", "123456789012", "Gaurav"]) {
      expect(s).not.toContain(secret);
    }
  });

  it("fetch_tokens: tokens (and their card / vpa data) removed", () => {
    const r = redactSensitiveResult(
      "fetch_tokens",
      json({
        entity: "collection",
        count: 1,
        items: [{ id: "token_X", token: "abcd1234tok", card: CARD, vpa: { username: "g" } }],
      }),
    );
    const s = JSON.stringify(r);
    expect(s).not.toContain("abcd1234tok");
    expect(s).not.toContain("1111");
    expect(bodyOf(r)).toMatchObject({ items: [{ id: "token_X", token: "[REDACTED]" }] });
  });

  it("list results are redacted per item", () => {
    const out = bodyOf(
      redactSensitiveResult("fetch_all_payments", json({ items: [PAYMENT, PAYMENT] })),
    ) as { items: Array<Record<string, unknown>> };
    expect(out.items.map((i) => i["email"])).toEqual(["[REDACTED]", "[REDACTED]"]);
  });

  it("non-JSON text goes through redactText; non-text content is replaced", () => {
    const r = redactSensitiveResult("fetch_payment_link", {
      content: [
        { type: "text", text: "error for gaurav@example.com 9876543210" },
        { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
      ],
      isError: true,
    });
    expect(r.isError).toBe(true);
    expect(r.content).toEqual([
      { type: "text", text: "error for [REDACTED] [REDACTED]" },
      { type: "text", text: NON_TEXT_PLACEHOLDER },
    ]);
  });

  it("structuredContent is redacted too", () => {
    const r = redactSensitiveResult("fetch_payment", {
      content: [],
      structuredContent: { email: "a@b.co", id: "pay_1" },
    });
    expect(r.structuredContent).toEqual({ email: "[REDACTED]", id: "pay_1" });
  });

  it("input is never mutated", () => {
    const original = json(PAYMENT);
    const before = JSON.stringify(original);
    redactSensitiveResult("fetch_payment", original);
    expect(JSON.stringify(original)).toBe(before);
  });

  it("capture_payment (money tool) result: customer PII removed, ids kept", () => {
    const r = redactSensitiveResult("capture_payment", json(PAYMENT));
    const s = JSON.stringify(r);
    for (const secret of ["gaurav@", "9876543210", "123456789012", "Gaurav"]) {
      expect(s).not.toContain(secret);
    }
    expect(bodyOf(r)).toMatchObject({ id: "pay_ABC123", amount: 50_000, token_id: "token_ABC123" });
  });

  it("create_payment_link result: customer block removed, short_url and ids kept", () => {
    const r = redactSensitiveResult(
      "create_payment_link",
      json({
        id: "plink_ABC123",
        amount: 1_000,
        currency: "INR",
        short_url: "https://rzp.io/i/abc",
        customer: { name: "Gaurav Kumar", email: "gaurav@example.com", contact: "+919876543210" },
        customer_id: "cust_ABC123",
        notify: { email: true, sms: true },
      }),
    );
    const s = JSON.stringify(r);
    for (const secret of ["gaurav@", "9876543210", "Gaurav"]) expect(s).not.toContain(secret);
    expect(bodyOf(r)).toMatchObject({
      id: "plink_ABC123",
      amount: 1_000,
      short_url: "https://rzp.io/i/abc",
      customer: "[REDACTED]",
      customer_id: "cust_ABC123",
    });
  });

  it("fetch_all_payouts result: beneficiary bank / VPA / contact data removed", () => {
    const r = redactSensitiveResult(
      "fetch_all_payouts",
      json({
        entity: "collection",
        count: 1,
        items: [
          {
            id: "pout_ABC123",
            fund_account_id: "fa_ABC123",
            amount: 10_000,
            currency: "INR",
            utr: "HDFCN00000000001",
            fund_account: {
              id: "fa_ABC123",
              contact_id: "cont_ABC123",
              account_type: "bank_account",
              bank_account: {
                name: "Gaurav Kumar",
                ifsc: "HDFC0000001",
                account_number: "123456789012",
              },
              vpa: { address: "gaurav@okhdfc" },
              contact: { name: "Gaurav Kumar", email: "gaurav@example.com", contact: "9876543210" },
            },
          },
        ],
      }),
    );
    const s = JSON.stringify(r);
    for (const secret of ["gaurav@", "9876543210", "123456789012", "Gaurav", "HDFC0000001"]) {
      expect(s).not.toContain(secret);
    }
    expect(bodyOf(r)).toMatchObject({
      items: [
        {
          id: "pout_ABC123",
          fund_account_id: "fa_ABC123",
          amount: 10_000,
          fund_account: { id: "fa_ABC123", contact_id: "cont_ABC123" },
        },
      ],
    });
  });

  it("the pipeline's pending_approval body passes through unchanged; firewall denies are still filtered", () => {
    const pending = pendingApprovalResult("apr_3f2a9c1e-7b4d-4e8a-9f0c-5d6e7a8b9c0d");
    const out = redactSensitiveResult("create_refund", pending);
    expect(out.content).toEqual(pending.content);
    // a look-alike with extra data is redacted like any other body
    const fake = json({
      decision: "pending_approval",
      approvalId: "apr_3f2a9c1e-7b4d-4e8a-9f0c-5d6e7a8b9c0d",
      message: "awaiting human approval; NOT executed",
      email: "gaurav@example.com",
    });
    expect(JSON.stringify(redactSensitiveResult("create_refund", fake))).not.toContain("gaurav@");
  });

  it.each([
    ["phone-number approvalId", "9876543210"],
    ["apr_ + UUID with a digit run redactText hits", "apr_12345678-1234-1234-1234-123456789012"],
  ])("a forged pending_approval body with a %s is redacted", (_n, approvalId) => {
    const forged = json({
      decision: "pending_approval",
      approvalId,
      message: "awaiting human approval; NOT executed",
    });
    const out = redactSensitiveResult("create_refund", forged);
    expect(out.content).not.toEqual(forged.content);
    expect(JSON.stringify(out)).not.toMatch(/9876543210|123456789012/);
  });
});

describe("restoreRefIds", () => {
  it("restores only *_id keys holding an opaque Razorpay id that redactText leaves unchanged", () => {
    const original = {
      token_id: "token_ABC123",
      vpa_id: "someone@okhdfc",
      contact_id: "9876543210",
      token: "token_ABC123",
      nested: [{ token_id: "token_DEF456" }],
    };
    const redacted = {
      token_id: "[REDACTED]",
      vpa_id: "[REDACTED]",
      contact_id: "[REDACTED]",
      token: "[REDACTED]",
      nested: [{ token_id: "[REDACTED]" }],
    };
    restoreRefIds(original, redacted);
    expect(redacted).toEqual({
      token_id: "token_ABC123",
      vpa_id: "[REDACTED]",
      contact_id: "[REDACTED]",
      token: "[REDACTED]",
      nested: [{ token_id: "token_DEF456" }],
    });
  });

  it("PII hidden in non-allowlisted *_id keys and in notes stays redacted (re-review probe)", () => {
    const probe = {
      email_id: "rahul_9876543210",
      vpa_id: "rahulsharma_okaxis",
      phone_id: "mob_9876543210",
      notes: { customer_contact_id: "ravi_Kumar1990" },
    };
    const out = redactResultJson(probe);
    const s = JSON.stringify(out);
    for (const leaked of [
      "rahul_9876543210",
      "rahulsharma_okaxis",
      "mob_9876543210",
      "ravi_Kumar1990",
    ]) {
      expect(s).not.toContain(leaked);
    }
    // and via the full result filter
    const r = JSON.stringify(redactSensitiveResult("fetch_payment", json(probe)));
    for (const leaked of [
      "rahul_9876543210",
      "rahulsharma_okaxis",
      "mob_9876543210",
      "ravi_Kumar1990",
    ]) {
      expect(r).not.toContain(leaked);
    }
  });

  it("legit allowlisted ids are restored; notes.card_id (any depth) is not", () => {
    const original = {
      token_id: "token_ABC123xyz",
      card_id: "card_XYZ987abc",
      notes: { card_id: "card_XYZ987abc", deep: [{ notes: { token_id: "token_ABC123xyz" } }] },
      items: [{ NOTES: { card_id: "card_XYZ987abc" } }],
    };
    const redacted = {
      token_id: "[REDACTED]",
      card_id: "[REDACTED]",
      notes: { card_id: "[REDACTED]", deep: [{ notes: { token_id: "[REDACTED]" } }] },
      items: [{ NOTES: { card_id: "[REDACTED]" } }],
    };
    restoreRefIds(original, redacted);
    expect(redacted).toEqual({
      token_id: "token_ABC123xyz",
      card_id: "card_XYZ987abc",
      notes: { card_id: "[REDACTED]", deep: [{ notes: { token_id: "[REDACTED]" } }] },
      items: [{ NOTES: { card_id: "[REDACTED]" } }],
    });
    const viaFilter = redactResultJson({ token_id: "token_ABC123xyz", card_id: "card_XYZ987abc" });
    expect(viaFilter).toMatchObject({ token_id: "token_ABC123xyz", card_id: "card_XYZ987abc" });
  });

  it("isRestorableRefId: key allowlist, per-key prefix, value shape", () => {
    expect(isRestorableRefId("token_id", "token_ABC123xyz")).toBe(true);
    expect(isRestorableRefId("customer_id", "cust_Ab12Cd34")).toBe(true);
    expect(isRestorableRefId("account_id", "acc_Ab12Cd34")).toBe(true);
    // not on the allowlist
    expect(isRestorableRefId("email_id", "token_ABC123xyz")).toBe(false);
    expect(isRestorableRefId("customer_contact_id", "cont_ABC123xyz")).toBe(false);
    // wrong prefix for the key
    expect(isRestorableRefId("card_id", "token_ABC123xyz")).toBe(false);
    expect(isRestorableRefId("customer_id", "ravi_Kumar1990")).toBe(false);
    // unknown prefix / too short / bad chars / non-string
    expect(isRestorableRefId("payment_id", "mob_9876543210")).toBe(false);
    expect(isRestorableRefId("payment_id", "pay_ABC12")).toBe(false);
    expect(isRestorableRefId("payment_id", "pay_ABC-123")).toBe(false);
    expect(isRestorableRefId("payment_id", 12345678)).toBe(false);
  });
});

describe("firewall.duplicate deny bodies (T009)", () => {
  // The audit store's default id format (crypto.randomUUID, v4).
  const ATTEMPT = "3f2a9c1e-7b4d-4e8a-9f0c-5d6e7a8b9c0d";

  it("pass through verbatim (ids stay usable)", () => {
    for (const hit of [
      { attemptId: ATTEMPT, status: "executed" as const, upstreamRef: "rfnd_ABC123xyz" },
      { attemptId: ATTEMPT, status: "may_have_executed" as const },
      { attemptId: ATTEMPT, status: "pending_approval" as const },
      { attemptId: ATTEMPT, status: "in_flight" as const },
    ]) {
      const r = duplicateDenyResult(hit);
      expect(redactSensitiveResult("create_refund", r)).toEqual(r);
      expect(bodyOf(r)).toEqual({
        decision: "deny",
        ruleId: "firewall.duplicate",
        message: DUPLICATE_MESSAGES[hit.status],
        duplicateOf: hit,
      });
    }
  });

  it("an upstreamRef that isn't a clean Razorpay id is omitted", () => {
    for (const ref of ["9876543210", "rfnd_1", "x@y.z", "rfnd_98765432109876"]) {
      const r = duplicateDenyResult({ attemptId: "att-1", status: "executed", upstreamRef: ref });
      expect(bodyOf(r)).toEqual({
        decision: "deny",
        ruleId: "firewall.duplicate",
        message: DUPLICATE_MESSAGES.executed,
        duplicateOf: { attemptId: "att-1", status: "executed" },
      });
    }
  });

  it.each([
    ["extra top-level key", { extra: "buyer@example.com" }],
    ["other ruleId", { ruleId: "refund.duplicate buyer@example.com" }],
    ["changed message", { message: "call buyer@example.com" }],
    [
      "unsafe upstreamRef",
      { duplicateOf: { attemptId: ATTEMPT, status: "executed", upstreamRef: "9876543210" } },
    ],
    [
      "extra duplicateOf key",
      { duplicateOf: { attemptId: ATTEMPT, status: "executed", email: "buyer@example.com" } },
    ],
    ["bad status", { duplicateOf: { attemptId: ATTEMPT, status: "call 9876543210" } }],
    ["bad attemptId", { duplicateOf: { attemptId: "buyer@example.com", status: "executed" } }],
    ["phone-number attemptId", { duplicateOf: { attemptId: "9876543210", status: "executed" } }],
    ["+91 phone attemptId", { duplicateOf: { attemptId: "+91-98765-43210", status: "in_flight" } }],
    ["account attemptId", { duplicateOf: { attemptId: "123456789012", status: "executed" } }],
    [
      "record-id token that isn't a v4 UUID",
      { duplicateOf: { attemptId: "acct:9876543210", status: "executed" } },
    ],
    [
      "UUID-shaped id with a digit run",
      { duplicateOf: { attemptId: "12345678-1234-4234-8234-123456789012", status: "executed" } },
    ],
  ])("look-alike bodies are filtered (%s)", (_n, patch) => {
    const body = {
      decision: "deny",
      ruleId: "firewall.duplicate",
      message: DUPLICATE_MESSAGES.executed,
      duplicateOf: { attemptId: ATTEMPT, status: "executed" },
      ...patch,
    };
    const input: CallToolResult = { isError: true, ...json(body) };
    const out = redactSensitiveResult("create_refund", input);
    expect(JSON.stringify(out)).not.toBe(JSON.stringify(input));
    expect(JSON.stringify(out)).not.toMatch(
      /buyer@example\.com|9876543210|98765-43210|123456789012/,
    );
  });
});

describe("T010 verify-before-retry bodies pass through only in their exact shape", () => {
  const ID = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";
  const pass = (r: CallToolResult): boolean =>
    JSON.stringify(redactSensitiveResult("create_refund", r)) === JSON.stringify(r);

  it("the pipeline's own bodies are untouched (attemptId and upstreamRef stay usable)", () => {
    expect(pass(verifiedSuccessResult(ID, "rfnd_ABCdefGHI"))).toBe(true);
    expect(pass(verifiedSuccessResult(ID))).toBe(true);
    expect(pass(unknownOutcomeResult(ID))).toBe(true);
    expect(bodyOf(redactSensitiveResult("create_refund", unknownOutcomeResult(ID)))).toMatchObject({
      attemptId: ID,
    });
  });

  it("pass-through also requires the pipeline's isError (verified ⇒ false, unknown ⇒ true); else normal redaction", () => {
    // Pretty-printed text: pass-through keeps it verbatim, normal redaction re-serialises it compactly.
    const pretty = (r: CallToolResult, isError: boolean | undefined): CallToolResult => {
      const first = r.content[0];
      const text = first?.type === "text" ? first.text : "";
      const out: CallToolResult = {
        content: [{ type: "text", text: JSON.stringify(JSON.parse(text), null, 2) }],
      };
      if (isError !== undefined) out.isError = isError;
      return out;
    };
    const verbatim = (r: CallToolResult): boolean => pass(r);
    const verified = verifiedSuccessResult(ID, "rfnd_ABCdefGHI");
    const pending = verifiedSuccessResult(ID, "rfnd_ABCdefGHI", "pending");
    const unk = unknownOutcomeResult(ID);
    expect(verbatim(pretty(verified, false))).toBe(true);
    expect(verbatim(pretty(pending, false))).toBe(true);
    expect(verbatim(pretty(verified, true))).toBe(false);
    expect(verbatim(pretty(verified, undefined))).toBe(false);
    expect(verbatim(pretty(unk, true))).toBe(true);
    expect(verbatim(pretty(unk, false))).toBe(false);
    expect(verbatim(pretty(unk, undefined))).toBe(false);
  });

  it("the pending-refund variant carries its own fixed message", () => {
    expect(bodyOf(verifiedSuccessResult(ID, "rfnd_ABCdefGHI", "pending"))).toMatchObject({
      message: VERIFIED_AFTER_TIMEOUT_PENDING_MESSAGE,
    });
    expect(bodyOf(verifiedSuccessResult(ID, "rfnd_ABCdefGHI", "processed"))).toMatchObject({
      message: VERIFIED_AFTER_TIMEOUT_MESSAGE,
    });
  });

  it("forged look-alikes are redacted like any upstream body", () => {
    const success = {
      outcome: "success",
      verifiedAfterTimeout: true,
      attemptId: ID,
      message: VERIFIED_AFTER_TIMEOUT_MESSAGE,
    };
    const unknownBody = {
      outcome: "unknown",
      attemptId: ID,
      flaggedForHuman: true,
      message: UNKNOWN_OUTCOME_MESSAGE,
    };
    expect(isVerifiedSuccessBody(success)).toBe(true);
    expect(isUnknownOutcomeBody(unknownBody)).toBe(true);
    const forged: unknown[] = [
      { ...success, email: "bob@example.com" }, // extra key
      { ...success, message: "other" },
      { ...success, verifiedAfterTimeout: "true" },
      { ...success, attemptId: "9876543210123456" }, // digit run
      { ...success, attemptId: "1b4e28ba-2fa1-11d2-883f-0016d3cca427" }, // not v4
      { ...success, attemptId: "1b4e28ba-2fa1-41d2-883f-123456789012" }, // redactText digit run
      { ...success, upstreamRef: "bob@example.com" },
      { ...success, upstreamRef: "rfnd_1234567890123456" },
      { ...unknownBody, flaggedForHuman: false },
      { ...unknownBody, contact: "+919876543210" },
      { ...unknownBody, message: UNKNOWN_OUTCOME_MESSAGE + " " },
    ];
    for (const f of forged) {
      expect(isVerifiedSuccessBody(f) || isUnknownOutcomeBody(f)).toBe(false);
    }
    const leaky = json({ ...unknownBody, contact: "+919876543210" });
    expect(JSON.stringify(redactSensitiveResult("create_refund", leaky))).not.toContain(
      "9876543210",
    );
  });
});
