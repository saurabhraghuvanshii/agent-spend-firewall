import { ATTEMPT_MARKER_KEY, type UpstreamPaymentPort } from "@asf/proxy";
import { describe, expect, it } from "vitest";
import { parseVerifyArgs, renderTable, runLiveChecks, VERIFY_REFUND_PAISE } from "./verify-live.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const PAY = "pay_VERIFYabc";
const ORDER = "order_VERIFYabc";
const MARKER = "verify-11111111-2222-4333-8444-555555555555";
const PINNED =
  '{"error":{"code":"BAD_REQUEST_ERROR","description":"The refund amount provided is greater than amount captured"}}';

interface FakeOpts {
  readonly ignoreCount?: boolean;
  readonly dropNotes?: boolean;
  readonly rejection?: string;
  readonly orderMissingCurrency?: boolean;
}

function fake(o: FakeOpts = {}): { port: UpstreamPaymentPort; sent: string[] } {
  const refunds: {
    id: string;
    amount: number;
    payment_id: string;
    status: string;
    notes: unknown;
  }[] = [{ id: "rfnd_OLD1", amount: 100, payment_id: PAY, status: "processed", notes: [] }];
  const sent: string[] = [];
  const text = (v: unknown) => ({
    kind: "ok" as const,
    result: { content: [{ type: "text" as const, text: JSON.stringify(v) }] },
  });
  const port: UpstreamPaymentPort = {
    callTool: (name, args) => {
      sent.push(name);
      if (name === "fetch_payment") {
        return Promise.resolve(
          text({
            id: PAY,
            status: "captured",
            amount: 10_000,
            amount_refunded: 100,
            currency: "INR",
            email: "a@b.c",
          }),
        );
      }
      if (name === "fetch_order") {
        return Promise.resolve(
          text(
            o.orderMissingCurrency === true
              ? { id: ORDER, amount: 10_000 }
              : { id: ORDER, amount: 10_000, currency: "INR" },
          ),
        );
      }
      if (name === "create_refund") {
        const amount = args["amount"];
        if (typeof amount === "number" && amount > 10_000) {
          return Promise.resolve({
            kind: "ok" as const,
            result: {
              isError: true,
              content: [{ type: "text" as const, text: o.rejection ?? PINNED }],
            },
          });
        }
        const r = {
          id: "rfnd_NEW1",
          amount: typeof amount === "number" ? amount : 0,
          payment_id: PAY,
          status: "processed",
          notes: o.dropNotes === true ? [] : args["notes"],
        };
        refunds.unshift(r);
        return Promise.resolve(text(r));
      }
      if (name === "fetch_multiple_refunds_for_payment") {
        const count = typeof args["count"] === "number" ? args["count"] : 10;
        const items = o.ignoreCount === true ? refunds : refunds.slice(0, count);
        return Promise.resolve(text({ entity: "collection", count: items.length, items }));
      }
      return Promise.resolve({
        kind: "error" as const,
        error: "upstream_error" as const,
        message: "no",
        forwarded: false,
      });
    },
  };
  return { port, sent };
}

const INPUT = { paymentId: PAY, orderId: ORDER, marker: MARKER, keys: KEYS };

describe("runLiveChecks", () => {
  it("everything as assumed ⇒ all PASS (incl. the pinned rejection and the T010 verifier)", async () => {
    const { port, sent } = fake();
    const checks = await runLiveChecks(port, INPUT);
    expect(checks.filter((c) => !c.pass)).toEqual([]);
    expect(checks.map((c) => c.name)).toEqual([
      "fetch_payment matches razorpayPaymentSchema",
      "firewall payment lookup (≤1.9 s) succeeds",
      "fetch_order matches razorpayOrderSchema",
      "firewall order lookup (≤1.9 s) succeeds",
      "create_refund ₹1 with notes.asf_attempt",
      "create_refund echoes notes.asf_attempt",
      "fetch_multiple_refunds_for_payment honours count:1",
      "fetch_multiple_refunds_for_payment returns notes (marker round-trip)",
      "T010 verifier finds the marked refund (happened)",
      "over-refund rejected with the pinned error shape",
    ]);
    expect(sent.filter((s) => s === "create_refund")).toHaveLength(2);
    expect(VERIFY_REFUND_PAISE).toBe(100);
  });

  it("a plain-text rejection ⇒ FAIL (ambiguous), raw text shown redacted", async () => {
    const { port } = fake({
      rejection: `creating refund failed: The refund amount is invalid; key ${KEYS.keySecret} card 4111111111111111`,
    });
    const checks = await runLiveChecks(port, INPUT);
    const over = checks.find((c) => c.name.startsWith("over-refund"));
    expect(over?.pass).toBe(false);
    expect(over?.detail).toMatch(/classified ambiguous; raw \(redacted\): creating refund failed/);
    expect(over?.detail).not.toContain(KEYS.keySecret);
    expect(over?.detail).not.toContain("4111111111111111");
  });

  it("count ignored ⇒ FAIL; notes dropped ⇒ marker checks FAIL and the verifier can't find it", async () => {
    const c1 = await runLiveChecks(fake({ ignoreCount: true }).port, INPUT);
    expect(c1.find((c) => c.name.includes("count:1"))?.pass).toBe(false);
    const c2 = await runLiveChecks(fake({ dropNotes: true }).port, INPUT);
    expect(c2.find((c) => c.name.includes("echoes"))?.pass).toBe(false);
    expect(c2.find((c) => c.name.includes("marker round-trip"))?.pass).toBe(false);
    expect(c2.find((c) => c.name.startsWith("T010 verifier"))?.pass).toBe(false);
  });

  it("an order shape the proxy can't parse ⇒ FAIL naming the field, never the value", async () => {
    const checks = await runLiveChecks(fake({ orderMissingCurrency: true }).port, INPUT);
    const o = checks.find((c) => c.name.startsWith("fetch_order"));
    expect(o).toMatchObject({ pass: false });
    expect(o?.detail).toMatch(/currency/);
  });

  it("no order id ⇒ that check fails, the rest still run", async () => {
    const checks = await runLiveChecks(fake().port, { ...INPUT, orderId: undefined });
    expect(checks.find((c) => c.name.startsWith("fetch_order"))?.pass).toBe(false);
    expect(checks.find((c) => c.name.startsWith("T010"))?.pass).toBe(true);
  });

  it("the marker key is the firewall's", () => {
    expect(ATTEMPT_MARKER_KEY).toBe("asf_attempt");
  });
});

describe("parseVerifyArgs / renderTable", () => {
  it("--yes is required to move money; anything else is refused", () => {
    expect(parseVerifyArgs([])).toEqual({ ok: true, value: { yes: false } });
    expect(parseVerifyArgs(["--", "--yes"])).toEqual({ ok: true, value: { yes: true } });
    expect(parseVerifyArgs(["--force"]).ok).toBe(false);
  });

  it("renders PASS / FAIL rows, escaped", () => {
    const t = renderTable([
      { name: "a", pass: true, detail: "ok" },
      { name: "bb", pass: false, detail: "x\u001b" },
    ]);
    expect(t).toBe("PASS  a           ok\nFAIL  bb          x\\u001b");
  });
});
