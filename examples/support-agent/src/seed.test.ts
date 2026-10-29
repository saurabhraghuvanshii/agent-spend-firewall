import { APPROVAL_THRESHOLD_PAISE, HARD_CAP_PAISE, VELOCITY_MAX_PAISE } from "@asf/policies";
import { describe, expect, it } from "vitest";
import {
  describeSdkError,
  renderSeedOutput,
  rupees,
  SEED_PLAN,
  seedCollect,
  seedCreate,
  type SeedGateway,
} from "./seed.js";
import type { SeedOutput } from "./tickets.js";

/** Refund each scenario's ticket asks for (paise), and the injected amount. */
const REQUESTED: Record<string, number> = {
  "late-delivery": 30_000,
  timeout: 50_000,
  approval: 450_000,
};
const INJECTED = 2_500_000;

describe("SEED_PLAN vs policies/default.ts", () => {
  it("scenario 1 and 3 are allowed: under the approval threshold and within what was paid", () => {
    for (const k of ["late-delivery", "timeout"]) {
      const asked = REQUESTED[k] ?? 0;
      expect(asked).toBeLessThanOrEqual(APPROVAL_THRESHOLD_PAISE);
      expect(asked).toBeLessThanOrEqual(SEED_PLAN[k]?.amountPaise ?? 0);
    }
  });

  it("scenario 2's injected ₹25,000 is denied (over the hard cap and over what was paid)", () => {
    expect(INJECTED).toBeGreaterThan(HARD_CAP_PAISE);
    expect(INJECTED).toBeGreaterThan(SEED_PLAN["prompt-injection"]?.amountPaise ?? 0);
  });

  it("scenario 4's ₹4,500 needs approval (over the threshold, under the cap, within what was paid)", () => {
    const asked = REQUESTED["approval"] ?? 0;
    expect(asked).toBeGreaterThan(APPROVAL_THRESHOLD_PAISE);
    expect(asked).toBeLessThanOrEqual(HARD_CAP_PAISE);
    expect(asked).toBeLessThanOrEqual(SEED_PLAN["approval"]?.amountPaise ?? 0);
  });

  it("all demo refunds together stay under the hourly velocity cap; amounts are integer paise ≥ ₹1", () => {
    const sum = Object.values(REQUESTED).reduce((a, b) => a + b, 0);
    expect(sum).toBeLessThan(VELOCITY_MAX_PAISE);
    for (const p of Object.values(SEED_PLAN)) {
      expect(Number.isSafeInteger(p.amountPaise)).toBe(true);
      expect(p.amountPaise).toBeGreaterThanOrEqual(100);
    }
    expect(Object.keys(SEED_PLAN)).toContain("verify-live");
  });
});

interface FakeState {
  links: Map<string, { status: string; payments: { payment_id: string; status: string }[] | null }>;
  payments: Map<string, Record<string, unknown>>;
  captured: string[];
  created: unknown[];
}

function fakeGateway(state: FakeState): SeedGateway {
  let n = 0;
  return {
    createLink: (body) => {
      state.created.push(body);
      n++;
      return Promise.resolve({
        id: `plink_N${String(n)}`,
        short_url: `https://rzp.io/rzp/n${String(n)}`,
        amount: body.amount,
        currency: "INR",
      });
    },
    fetchLink: (id) => {
      const l = state.links.get(id);
      return l === undefined
        ? Promise.reject(
            Object.assign(new Error("x"), {
              statusCode: 400,
              error: { code: "BAD_REQUEST_ERROR", description: "secret?" },
            }),
          )
        : Promise.resolve({ id, ...l });
    },
    fetchPayment: (id) => Promise.resolve(state.payments.get(id)),
    capture: (id) => {
      state.captured.push(id);
      const p = state.payments.get(id);
      if (p !== undefined) p["status"] = "captured";
      return Promise.resolve(p);
    },
  };
}

function emptyState(): FakeState {
  return { links: new Map(), payments: new Map(), captured: [], created: [] };
}

describe("seedCreate", () => {
  it("creates one INR link per plan entry with asf_seed notes and no customer PII; re-run keeps existing", async () => {
    const st = emptyState();
    const r = await seedCreate(fakeGateway(st), undefined, () => "abcd1234");
    if (!r.ok) throw new Error(r.error.message);
    expect(Object.keys(r.value.entries).sort()).toEqual(Object.keys(SEED_PLAN).sort());
    expect(st.created).toHaveLength(Object.keys(SEED_PLAN).length);
    for (const b of st.created) {
      expect(b).toMatchObject({ currency: "INR", notify: { sms: false, email: false } });
      expect(JSON.stringify(b)).not.toMatch(/email"\s*:\s*"|contact/);
      expect((b as { notes: Record<string, string> }).notes["asf_seed"]).toBeDefined();
    }
    const again = await seedCreate(fakeGateway(st), r.value, () => "abcd1234");
    expect(st.created).toHaveLength(Object.keys(SEED_PLAN).length);
    expect(again.ok && again.value).toEqual(r.value);
    expect(() => renderSeedOutput(r.value)).not.toThrow();
  });

  it("an SDK error is reported by status + code only", async () => {
    const gw: SeedGateway = {
      ...fakeGateway(emptyState()),
      createLink: () =>
        Promise.reject(
          Object.assign(new Error("sdk"), {
            statusCode: 401,
            error: { code: "BAD_REQUEST_ERROR", description: "key rzp_test_X" },
          }),
        ),
    };
    const r = await seedCreate(gw, undefined, () => "abcd1234");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.message).toContain("HTTP 401 BAD_REQUEST_ERROR");
      expect(r.error.message).not.toContain("rzp_test_X");
    }
    expect(describeSdkError(new TypeError("boom"))).toBe("TypeError");
  });
});

const BASE: SeedOutput = {
  version: 1,
  entries: {
    "late-delivery": {
      paymentLinkId: "plink_A",
      shortUrl: "https://rzp.io/a",
      amountPaise: 120_000,
    },
  },
};
const payment = (over: Record<string, unknown> = {}) => ({
  id: "pay_A1",
  status: "captured",
  currency: "INR",
  amount: 120_000,
  amount_refunded: 0,
  order_id: "order_A1",
  ...over,
});

describe("seedCollect", () => {
  it("captured INR payment of the planned amount ⇒ collected with payment + order ids", async () => {
    const st = emptyState();
    st.links.set("plink_A", {
      status: "paid",
      payments: [{ payment_id: "pay_A1", status: "captured" }],
    });
    st.payments.set("pay_A1", payment());
    const { output, report } = await seedCollect(fakeGateway(st), BASE);
    expect(report).toEqual([{ key: "late-delivery", status: "collected", detail: "pay_A1" }]);
    expect(output.entries["late-delivery"]).toMatchObject({
      paymentId: "pay_A1",
      orderId: "order_A1",
    });
    expect(st.captured).toEqual([]);
  });

  it("authorized ⇒ captured first, then validated", async () => {
    const st = emptyState();
    st.links.set("plink_A", {
      status: "paid",
      payments: [{ payment_id: "pay_A1", status: "authorized" }],
    });
    st.payments.set("pay_A1", payment({ status: "authorized" }));
    const { report } = await seedCollect(fakeGateway(st), BASE);
    expect(st.captured).toEqual(["pay_A1"]);
    expect(report[0]?.status).toBe("collected");
  });

  it.each([
    ["non-INR", payment({ currency: "USD" })],
    ["wrong amount", payment({ amount: 100_000 })],
    ["failed", payment({ status: "failed" })],
    ["float amount", payment({ amount: 1200.5 })],
    ["different id", payment({ id: "pay_OTHER" })],
  ])("%s ⇒ invalid, nothing written for the entry", async (_l, p) => {
    const st = emptyState();
    st.links.set("plink_A", {
      status: "paid",
      payments: [{ payment_id: "pay_A1", status: "captured" }],
    });
    st.payments.set("pay_A1", p);
    const { output, report } = await seedCollect(fakeGateway(st), BASE);
    expect(report[0]?.status).toBe("invalid");
    expect(output.entries["late-delivery"]?.paymentId).toBeUndefined();
  });

  it("an authorized non-INR payment is never captured", async () => {
    const st = emptyState();
    st.links.set("plink_A", {
      status: "paid",
      payments: [{ payment_id: "pay_A1", status: "authorized" }],
    });
    st.payments.set("pay_A1", payment({ status: "authorized", currency: "USD" }));
    await seedCollect(fakeGateway(st), BASE);
    expect(st.captured).toEqual([]);
  });

  it("unpaid link ⇒ unpaid; already collected ⇒ untouched; SDK error ⇒ invalid", async () => {
    const st = emptyState();
    st.links.set("plink_A", { status: "created", payments: null });
    expect((await seedCollect(fakeGateway(st), BASE)).report[0]?.status).toBe("unpaid");
    const done: SeedOutput = {
      version: 1,
      entries: { a: { ...BASE.entries["late-delivery"]!, paymentId: "pay_Z" } },
    };
    expect((await seedCollect(fakeGateway(st), done)).report[0]?.status).toBe("already");
    const missing: SeedOutput = {
      version: 1,
      entries: {
        b: { paymentLinkId: "plink_MISSING", shortUrl: "https://rzp.io/m", amountPaise: 100 },
      },
    };
    const r = await seedCollect(fakeGateway(st), missing);
    expect(r.report[0]).toMatchObject({ status: "invalid" });
    expect(r.report[0]?.detail).not.toContain("secret?");
  });
});

describe("rupees", () => {
  it("formats integer paise without floating point", () => {
    expect(rupees(30_000)).toBe("₹300");
    expect(rupees(450_000)).toBe("₹4,500");
    expect(rupees(2_500_000)).toBe("₹25,000");
    expect(rupees(105)).toBe("₹1.05");
    expect(rupees(1.5)).toBe("₹?");
  });
});
