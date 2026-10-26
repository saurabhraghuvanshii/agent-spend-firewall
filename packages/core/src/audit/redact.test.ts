import { describe, expect, it } from "vitest";
import { REDACTED, redact, redactText } from "./redact.js";
import type { JsonValue } from "./types.js";

describe("redact", () => {
  it("redacts denylisted keys at any depth, including whole objects", () => {
    const input: JsonValue = {
      payment_id: "pay_ABC123",
      amount: 50000,
      notes: { customer: { email: "a@b.com", contact: "+919876543210" } },
      items: [{ vpa: "user@okaxis" }, { card: { number: "4111111111111111", cvv: "123" } }],
      card: { last4: "1111", network: "Visa" },
    };
    expect(redact(input)).toEqual({
      payment_id: "pay_ABC123",
      amount: 50000,
      notes: { customer: REDACTED },
      items: [{ vpa: REDACTED }, { card: REDACTED }],
      card: REDACTED,
    });
  });

  it.each([
    "Card_Number",
    "CARDNUMBER",
    "card-number",
    "key-secret",
    "Key_Secret",
    "API_KEY",
    "Authorization",
    "account_number",
    "bank_account",
    "IFSC",
    "expiry",
    "expiry_month",
    "expiry_year",
    "Expiry-Year",
    "password",
    "token",
    "secret",
    "Phone",
    "CVV",
  ])("redacts key variant %s", (key) => {
    expect(redact({ [key]: "x", keep: "y" })).toEqual({ [key]: REDACTED, keep: "y" });
  });

  it("redacts card objects whole (no separate card.number rule needed) and leaves bare `number` keys", () => {
    expect(redact({ number: 42, meta: { number: 7 } })).toEqual({
      number: 42,
      meta: { number: 7 },
    });
    expect(redact({ Card: { Number: "4111" } })).toEqual({ Card: REDACTED });
    expect(redact({ card: [{ number: "4111" }] })).toEqual({ card: REDACTED });
    expect(redact({ payment_card: { number: "4111" } })).toEqual({ payment_card: REDACTED });
  });

  it("supports extraKeys with normalisation", () => {
    expect(
      redact({ customer_name: "Asha", tool: "refund" }, { extraKeys: ["Customer-Name"] }),
    ).toEqual({
      customer_name: REDACTED,
      tool: "refund",
    });
  });

  it("scrubs sensitive patterns inside non-denylisted string values", () => {
    const out = redact({
      description: "refund to user@okicici please",
      memo: "card 4111 1111 1111 1111 declined",
      note: "key rzp_test_AbC123xyz leaked",
      live: "rzp_live_Zz9",
      remark: "call 9876543210",
    });
    expect(out).toEqual({
      description: `refund to ${REDACTED} please`,
      memo: `card ${REDACTED} declined`,
      note: `key ${REDACTED} leaked`,
      live: REDACTED,
      remark: `call ${REDACTED}`,
    });
  });

  it("keeps ids, amounts and non-sensitive values", () => {
    const input: JsonValue = {
      id: "rfnd_1",
      payment_id: "pay_29QQoUBi66xm2f",
      order_id: "order_EKwxwAgItmmXdp",
      amount: 150000,
      speed: "normal",
      flags: [true, false, null],
    };
    expect(redact(input)).toEqual(input);
  });

  it("does not mutate its input and is deterministic", () => {
    const input: JsonValue = { email: "a@b.com", nested: { token: "t", list: ["x@y.z"] } };
    const snapshot = JSON.stringify(input);
    const a = redact(input);
    const b = redact(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(a).toEqual(b);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(a).not.toBe(input);
  });

  it("does not let a __proto__ key alter the output prototype", () => {
    const input = JSON.parse('{"__proto__":{"polluted":"yes"}}') as JsonValue;
    const out = redact(input) as Record<string, JsonValue>;
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(true);
  });
});

describe("redact — security review findings (T005)", () => {
  it.each([
    "client_secret",
    "access_token",
    "refresh-token",
    "razorpay_signature",
    "x-razorpay-signature",
    "customer_email",
    "customer.phone",
    "mobile",
    "mobile_no",
    "contact_number",
    "upi_vpa",
    "upi_id",
    "card_cvv",
    "card_expiry_month",
    "beneficiary_ifsc",
    "account_no",
    "account_number",
    "bank_account_no",
    "aadhaar",
    "billing_address",
    "passwd",
    "db_password",
    "cc",
    "CC",
    "pan",
    "PAN",
    "name",
    "Name",
    "customer_name",
    "full_name",
    "ac_no",
  ])("redacts key %s whole", (key) => {
    expect(redact({ [key]: "x", keep: "y" })).toEqual({ [key]: REDACTED, keep: "y" });
  });

  it("redacts the verified leaks from the review", () => {
    expect(
      redact({
        mobile: 9876543210,
        cc: 4111111111111111,
        client_secret: "abc",
        access_token: "abc",
        razorpay_signature: "abc",
        account_no: "12345678901",
        name: "Ravi Kumar",
      }),
    ).toEqual({
      mobile: REDACTED,
      cc: REDACTED,
      client_secret: REDACTED,
      access_token: REDACTED,
      razorpay_signature: REDACTED,
      account_no: REDACTED,
      name: REDACTED,
    });
  });

  it("does not substring-match short terms onto innocent keys", () => {
    const input: JsonValue = {
      company: "Acme",
      company_name: "Acme",
      account_id: "acc_29QQoUBi66xm2f",
      fund_account_id: "fa_29QQoUBi66xm2f",
      contact_id: "cont_29QQoUBi66xm2f",
      card_id: "card_29QQoUBi66xm2f",
      group_id: "g1",
      success: true,
      span: 3,
      keyboard: "qwerty",
      pancake: "yes",
    };
    expect(redact(input)).toEqual(input);
  });

  it("keeps amount, ids, currency and notes keys; notes strings are still scrubbed", () => {
    const input: JsonValue = {
      id: "rfnd_29QQoUBi66xm2f",
      amount: 2500000,
      amount_refunded: 6000000000,
      payment_id: "pay_29QQoUBi66xm2f",
      order_id: "order_EKwxwAgItmmXdp",
      refund_id: "rfnd_EKwxwAgItmmXdp",
      currency: "INR",
      created_at: 1700000000,
      count: 10,
      customer_id: "cust_29QQoUBi66xm2f",
      notes: { ticket: "T-1234", comment: "mail a@b.com" },
    };
    expect(redact(input)).toEqual({
      ...input,
      notes: { ticket: "T-1234", comment: `mail ${REDACTED}` },
    });
  });

  it.each([
    [4111111111111111, true],
    [123456789012, true],
    [9876543210, true],
    [919876543210, true],
    [-9876543210, true],
    [6000000000, true],
    [2500000, false],
    [150000, false],
    [5000000000, false],
    [1700000000, false],
    [12345678901, false],
    [1.5, false],
  ])("integer %d under a neutral key is redacted: %s", (n, redacted) => {
    expect(redact({ value: n })).toEqual({ value: redacted ? REDACTED : n });
    expect(redact([n])).toEqual([redacted ? REDACTED : n]);
  });

  it("exempts phone-looking integers only under exact amount keys", () => {
    expect(redact({ amount: 9876543210, fee: 9876543210, tax: 123456789012 })).toEqual({
      amount: 9876543210,
      fee: 9876543210,
      tax: 123456789012,
    });
  });

  it("renames object keys that contain PII, deterministically and independent of insertion order", () => {
    const a = redact({ "x@y.com": 1, "9876543210": { note: "hi" }, plain: 2 });
    const b = redact({ plain: 2, "9876543210": { note: "hi" }, "x@y.com": 1 });
    // sorted offending keys: "9876543210" < "x@y.com"
    expect(a).toEqual({ "[REDACTED_KEY_0]": { note: "hi" }, "[REDACTED_KEY_1]": 1, plain: 2 });
    expect(b).toEqual(a);
    expect(JSON.stringify(a)).not.toMatch(/x@y|98765/);
  });

  it("renames card-number and rzp-key object keys, at any depth", () => {
    const out = redact({ nested: { "4111 1111 1111 1111": "v", rzp_test_AbC123: "k" } });
    expect(out).toEqual({ nested: { "[REDACTED_KEY_0]": "v", "[REDACTED_KEY_1]": "k" } });
  });

  it("does not collide with an existing key named like a placeholder", () => {
    const out = redact({ "[REDACTED_KEY_0]": "orig", "a@b.co": "v" });
    expect(out).toEqual({ "[REDACTED_KEY_0]": "orig", "[REDACTED_KEY_1]": "v" });
  });

  it("walks (does not deny) the value of a renamed PII key", () => {
    expect(redact({ "a@b.co": { email: "c@d.co", ok: 1 } })).toEqual({
      "[REDACTED_KEY_0]": { email: REDACTED, ok: 1 },
    });
  });
});

describe("redactText", () => {
  it("scrubs VPA, email, phone, card and API keys from a reason", () => {
    const reason =
      "Customer jane.doe@example.com (UPI jane@oksbi, +91 98765 43210) was double charged on card 4111-1111-1111-1111; " +
      "used rzp_live_ABCdef123 to check";
    const out = redactText(reason);
    expect(out).not.toMatch(/example\.com|oksbi|98765|4111|rzp_/);
    expect(out).toContain("double charged");
  });

  it("redacts 12-19 digit runs but not short numbers", () => {
    expect(redactText("acct 123456789012")).toBe(`acct ${REDACTED}`);
    expect(redactText("pan 4111111111111111111")).toBe(`pan ${REDACTED}`);
    expect(redactText("refund 50000 paise for order 12345")).toBe(
      "refund 50000 paise for order 12345",
    );
  });

  it("scrubs long digit runs even when glued to a word (fail-safe over-redaction)", () => {
    expect(redactText("card4111111111111111")).toBe(`card${REDACTED}`);
  });

  it("leaves text without sensitive data unchanged", () => {
    expect(redactText("duplicate charge on pay_29QQoUBi66xm2f")).toBe(
      "duplicate charge on pay_29QQoUBi66xm2f",
    );
  });

  it.each([
    ["the key secret is AbCdEf0123456789XyZ9876q", "the key secret is [REDACTED]"],
    ["secret: AbCdEf0123456789XyZ9876q please rotate", "secret: [REDACTED] please rotate"],
    ["KEY=AbCdEf0123456789XyZ9876q", "KEY=[REDACTED]"],
    ["token AbCdEf0123456789XyZ9876q", "token [REDACTED]"],
    ["Password was hunter2hunter2hunter2xx", "Password was [REDACTED]"],
    ["signature: 9f2c7a8b1d4e6f0a3b5c7d9e1f2a4b6c", "signature: [REDACTED]"],
    ["key_secret AbCdEf0123456789XyZ9876q", "key_secret [REDACTED]"],
  ])("redacts a long base62 run after a secret-ish word: %s", (input, expected) => {
    expect(redactText(input)).toBe(expected);
  });

  it.each([
    "Customer says the key issue is a duplicate charge on pay_29QQoUBi66xm2f",
    "refund key order order_EKwxwAgItmmXdp for 50000 paise",
    "the token was rejected; customer asked for a refund",
    "the keyboard AbCdEf0123456789XyZ9876q is unrelated",
    "monkey AbCdEf0123456789XyZ9876q",
    "secret santa gift was internationalization-related",
    "Signature mismatch, payment pay_29QQoUBi66xm2f marked failed",
  ])("does not over-redact ordinary text: %s", (input) => {
    expect(redactText(input)).toBe(input);
  });

  it("does not redact a long run far away from the trigger word", () => {
    const s = "key: see the attached ticket notes for AbCdEf0123456789XyZ9876q";
    expect(redactText(s)).toBe(s);
  });
});

describe("redact — round-2 security review findings", () => {
  it("redacts the verified round-2 key leaks", () => {
    expect(
      redact({
        pan_number: "ABCDE1234F",
        acc_no: 12345678901,
        beneficiary_account: "50100123456",
        notes: { customer: "Ravi Kumar", holder_name: "Ravi Kumar", payee_name: "Ravi" },
        card_id: { holder: "Ravi" },
      }),
    ).toEqual({
      pan_number: REDACTED,
      acc_no: REDACTED,
      beneficiary_account: REDACTED,
      notes: { customer: REDACTED, holder_name: REDACTED, payee_name: REDACTED },
      card_id: { holder: REDACTED },
    });
  });

  it.each([
    "pan_number",
    "PAN-No",
    "acc_no",
    "acct_no",
    "AccountNo",
    "beneficiary",
    "beneficiary_details",
    "card_holder",
    "account_holder",
    "payee",
    "payee_vpa_name",
    "customer",
    "Customer",
    "customer_name",
    "customerName",
  ])("redacts key %s whole", (key) => {
    expect(redact({ [key]: "x", keep: "y" })).toEqual({ [key]: REDACTED, keep: "y" });
  });

  it("keeps customer_id and other customer-prefixed ids", () => {
    const input: JsonValue = {
      customer_id: "cust_29QQoUBi66xm2f",
      customerId: "cust_29QQoUBi66xm2f",
    };
    expect(redact(input)).toEqual(input);
  });

  it.each([
    ["account", "50100123456"],
    ["account", 50100123456],
    ["payout_account", 123456789],
    ["bank_account_ref", "123456789012345678"],
    ["acc", 987654321],
    ["acct", " 501001234567 "],
    ["acct_num", 123456789],
  ])("redacts a 9-18 digit value under account-like key %s", (key, value) => {
    expect(redact({ [key]: value })).toEqual({ [key]: REDACTED });
  });

  it.each([
    ["account_id", "98765432101"],
    ["account_id", 50100123456],
    ["fund_account_id", "50100123456"],
    ["accountId", 50100123456],
    ["account", 12345678], // 8 digits: too short
    ["account", "1234567890123456789"], // 19 digits: too long for the account rule
    ["account_type", "savings"],
    ["account", 1.5],
  ])("keeps %s = %s", (key, value) => {
    const out = redact({ [key]: value }) as Record<string, JsonValue>;
    // 19-digit strings are still scrubbed by redactText's long-digit rule; everything else survives verbatim
    if (key === "account" && value === "1234567890123456789") {
      expect(out[key]).toBe(REDACTED);
    } else {
      expect(out[key]).toBe(value);
    }
  });

  it("exempts only exact amount keys and still redacts >= 13-digit amounts", () => {
    expect(
      redact({
        amount: 2500000,
        amount_refunded: 6000000000,
        amount_paid: 6000000000,
        amount_due: 6000000000,
        amount_paise: 999999999999,
        base_amount: 9876543210,
      }),
    ).toEqual({
      amount: 2500000,
      amount_refunded: 6000000000,
      amount_paid: 6000000000,
      amount_due: 6000000000,
      amount_paise: 999999999999,
      base_amount: 9876543210,
    });
    expect(
      redact({
        amount: 4111111111111111,
        amount_refunded: 1234567890123,
        amount_note: 9876543210,
        max_amount: 4111111111111111,
      }),
    ).toEqual({
      amount: REDACTED,
      amount_refunded: REDACTED,
      amount_note: REDACTED,
      max_amount: REDACTED,
    });
  });
});

describe("redactText — round-2 security review findings", () => {
  it.each([
    ["card 4111.1111.1111.1111 declined", `card ${REDACTED} declined`],
    ["mobile9876543210", `mobile${REDACTED}`],
    ["ph:9876543210.", `ph:${REDACTED}.`],
    ["PAN ABCDE1234F on file", `PAN ${REDACTED} on file`],
    ["pan:ABCDE1234F", `pan:${REDACTED}`],
  ])("redacts %s", (input, expected) => {
    expect(redactText(input)).toBe(expected);
  });

  it.each([
    "duplicate charge on pay_29QQoUBi66xm2f",
    "id cust_Ab9876543210 flagged",
    "order_EKwxwAgItmmXdp and rfnd_EKwxwAgItmmXdp",
    "refund 1234.56 rupees for 50000 paise",
    "v1.2.3 build 98765",
    "ABCDE1234 is not a PAN, nor is abcde1234f",
    "ref 12345678901",
  ])("does not over-redact %s", (input) => {
    expect(redactText(input)).toBe(input);
  });

  it("does not match a phone inside a longer digit run (left to the long-digit rule)", () => {
    expect(redactText("x 19876543210 y")).toBe("x 19876543210 y");
  });

  it("known limit: a bare 24-char secret with no trigger word is NOT redacted", () => {
    const s = "rotate AbCdEf0123456789XyZ9876q now";
    expect(redactText(s)).toBe(s);
  });
});

describe("redact — OTPs (T008)", () => {
  it("redacts otp_string but keeps payment_id", () => {
    expect(redact({ payment_id: "pay_29QQoUBi66xm2f", otp_string: "123456" })).toEqual({
      payment_id: "pay_29QQoUBi66xm2f",
      otp_string: REDACTED,
    });
  });

  it.each(["OTP", "otp", "Otp-String", "OTP_STRING"])("redacts key %s at any depth", (key) => {
    expect(redact({ nested: [{ [key]: 123456 }] })).toEqual({ nested: [{ [key]: REDACTED }] });
  });
});
