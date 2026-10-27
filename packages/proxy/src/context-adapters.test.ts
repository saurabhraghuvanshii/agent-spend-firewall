import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  compilePolicy,
  err,
  evaluate,
  fakeClock,
  fakeTimer,
  type CompiledPolicy,
  type EvalResult,
  type FakeClock,
  type Result,
} from "@asf/core";
import defaultPolicy, { VELOCITY_MAX_COUNT } from "@asf/policies";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  openAuditStore,
  type AuditActivity,
  type AuditOutcomeInput,
  type AuditStore,
  type RecordAttemptInput,
} from "./audit-store.js";
import {
  createHistoryPort,
  createOrderLookup,
  createPolicyDeps,
  createRazorpayLookup,
  createStatsPort,
  DEFAULT_LOOKUP_TIMEOUT_MS,
  DEFAULT_OPEN_LOOKBACK_MS,
  FETCH_ORDER_TOOL,
  FETCH_PAYMENT_TOOL,
  MAX_LOOKUP_TIMEOUT_MS,
  MAX_OPEN_LOOKBACK_MS,
  MIN_OPEN_LOOKBACK_MS,
  systemClock,
  systemTimer,
  type AdapterOpts,
  type UpstreamPaymentPort,
} from "./context-adapters.js";
import { classifyTool } from "./tool-classes.js";
import type { CallOptions, UpstreamCallOutcome } from "./upstream.js";

const T0 = Date.parse("2026-10-23T10:00:00.000Z");
const MIN = 60_000;
const HOUR = 60 * MIN;
const PAY = "pay_TEST123";
const TOOL = "create_refund";

let dir: string;
let clock: FakeClock;
let store: AuditStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-ctx-"));
  clock = fakeClock(T0);
  let n = 0;
  store = unwrap(
    openAuditStore({
      path: join(dir, "audit.db"),
      clock: () => new Date(clock.nowMs()),
      idGen: () => `gen-${String(++n)}`,
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r.value;
}

// ---------- fake upstream ----------

interface FakeCall {
  name: string;
  args: Record<string, unknown>;
  opts: CallOptions | undefined;
}

function fakeUpstream(
  respond: (args: Record<string, unknown>) => UpstreamCallOutcome = () => okPayment(),
): UpstreamPaymentPort & { calls: FakeCall[] } {
  const calls: FakeCall[] = [];
  return {
    calls,
    callTool(name, args, opts) {
      calls.push({ name, args, opts });
      return Promise.resolve(respond(args));
    },
  };
}

function textResult(text: string, isError = false): UpstreamCallOutcome {
  const result: CallToolResult = { content: [{ type: "text", text }] };
  if (isError) result.isError = true;
  return { kind: "ok", result };
}

function okPayment(over: Record<string, unknown> = {}): UpstreamCallOutcome {
  return textResult(
    JSON.stringify({
      id: PAY,
      entity: "payment",
      status: "captured",
      amount: 5_000_000,
      amount_refunded: 0,
      currency: "INR",
      email: "someone@example.com",
      contact: "+919999999999",
      ...over,
    }),
  );
}

function opts(over: Partial<AdapterOpts> = {}): AdapterOpts {
  return { store, upstream: fakeUpstream(), clock, ...over };
}

// ---------- seeding ----------

function seed(
  id: string,
  over: Partial<RecordAttemptInput> = {},
  outcome?: AuditOutcomeInput,
): void {
  unwrap(
    store.recordAttempt({
      sessionId: "sess",
      tool: TOOL,
      args: { payment_id: PAY, amount: 10_000 },
      reason: "customer asked for a refund",
      decision: "allow",
      matchedRules: ["refund.allow"],
      id,
      ...over,
    }),
  );
  if (outcome !== undefined) {
    unwrap(store.recordOutcome({ attemptId: id, outcome, latencyMs: 3 }));
  }
}

const stats = (o: AdapterOpts = opts(), windowMs = HOUR, tools: readonly string[] = [TOOL]) =>
  createStatsPort(o).sumLast({ tools, windowMs });

// ---------- stats ----------

describe("createStatsPort", () => {
  it("counts executed, possibly-executed and pending actions; excludes denied / not forwarded", async () => {
    seed("s-success", {}, "success");
    seed("s-timeout", {}, "timeout");
    seed("s-upstream-error", {}, "upstream_error");
    seed("s-dangling");
    seed("s-pending-approval", { decision: "require_approval" });
    seed("s-transform", { decision: "transform" }, "success");
    seed("x-deny", { decision: "deny" });
    seed("x-deny-denied", { decision: "deny" }, "denied");
    seed("x-allow-denied", {}, "denied");
    seed("x-approval-rejected", { decision: "require_approval" }, "denied");
    seed("x-not-forwarded", {}, "not_forwarded");
    expect(unwrap(await stats())).toEqual({ amountPaise: 60_000, count: 6 });
  });

  it("only counts the queried tools", async () => {
    seed("a");
    seed("b", { tool: "create_payout", args: { amount: 99_999 } });
    expect(unwrap(await stats())).toEqual({ amountPaise: 10_000, count: 1 });
    expect(unwrap(await stats(opts(), HOUR, [TOOL, "create_payout"]))).toEqual({
      amountPaise: 109_999,
      count: 2,
    });
  });

  it("window edge: a closed action exactly at now − window counts; 1 ms older does not", async () => {
    seed("edge", {}, "success");
    clock.set(T0 + HOUR);
    expect(unwrap(await stats())).toEqual({ amountPaise: 10_000, count: 1 });
    clock.set(T0 + HOUR + 1);
    expect(unwrap(await stats())).toEqual({ amountPaise: 0, count: 0 });
  });

  it("uses the later of attempt and outcome time", async () => {
    seed("approved-late", { decision: "require_approval" });
    clock.set(T0 + 50 * MIN);
    unwrap(store.recordOutcome({ attemptId: "approved-late", outcome: "success", latencyMs: 1 }));
    clock.set(T0 + 90 * MIN);
    expect(unwrap(await stats())).toEqual({ amountPaise: 10_000, count: 1 });
  });

  it("still counts a pending attempt after the window has passed (open attempts ignore the window)", async () => {
    seed("pending", { decision: "require_approval" });
    clock.set(T0 + 61 * MIN);
    expect(unwrap(await stats())).toEqual({ amountPaise: 10_000, count: 1 });
  });

  it("does not count an open attempt older than openLookbackMs", async () => {
    seed("stale-open", { decision: "require_approval" });
    clock.set(T0 + DEFAULT_OPEN_LOOKBACK_MS);
    expect(unwrap(await stats())).toEqual({ amountPaise: 10_000, count: 1 });
    clock.set(T0 + DEFAULT_OPEN_LOOKBACK_MS + 1);
    expect(unwrap(await stats())).toEqual({ amountPaise: 0, count: 0 });
    // A custom lookback is honoured.
    clock.set(T0 + 2 * HOUR);
    expect(unwrap(await stats(opts({ openLookbackMs: 3 * HOUR })))).toEqual({
      amountPaise: 10_000,
      count: 1,
    });
    expect(unwrap(await stats(opts({ openLookbackMs: HOUR })))).toEqual({
      amountPaise: 0,
      count: 0,
    });
  });

  it("does not count an attempt that completed and is now outside the window", async () => {
    seed("done", { decision: "require_approval" });
    clock.set(T0 + 5 * MIN);
    unwrap(store.recordOutcome({ attemptId: "done", outcome: "success", latencyMs: 1 }));
    clock.set(T0 + 5 * MIN + HOUR + 1);
    expect(unwrap(await stats())).toEqual({ amountPaise: 0, count: 0 });
  });

  it("reads the store once from min(window cutoff, now − openLookbackMs)", async () => {
    const calls: number[] = [];
    const o = opts({
      store: {
        readActivitySince: (since) => {
          calls.push(since);
          return store.readActivitySince(since);
        },
      },
    });
    await stats(o);
    expect(calls).toEqual([T0 - DEFAULT_OPEN_LOOKBACK_MS]);
    calls.length = 0;
    await stats(o, 2 * DEFAULT_OPEN_LOOKBACK_MS);
    expect(calls).toEqual([T0 - 2 * DEFAULT_OPEN_LOOKBACK_MS]);
  });

  it.each([0, -1, 1.5, MIN_OPEN_LOOKBACK_MS - 1, MAX_OPEN_LOOKBACK_MS + 1, Number.NaN])(
    "fails closed on an invalid openLookbackMs %d",
    async (v) => {
      seed("a");
      const r = await stats(opts({ openLookbackMs: v }));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("context.invalid_config");
      const h = await createHistoryPort(opts({ openLookbackMs: v })).hasRecent({
        tool: TOOL,
        match: { payment_id: PAY },
        withinMs: MIN,
      });
      expect(h.ok).toBe(false);
    },
  );

  it("skips excluded attempt ids", async () => {
    seed("a");
    seed("b");
    expect(unwrap(await stats(opts({ excludeAttemptIds: new Set(["a"]) })))).toEqual({
      amountPaise: 10_000,
      count: 1,
    });
  });

  it("fails closed when a counted action has a redacted or missing amount", async () => {
    // ≥ 13 digits under `amount` is redacted to "[REDACTED]" by the audit store.
    seed("huge", { args: { payment_id: PAY, amount: 1_234_567_890_123 } });
    const r = await stats();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("context.amount_unreadable");
  });

  it("fails closed when a counted action has no amount", async () => {
    seed("full", { args: { payment_id: PAY } });
    expect((await stats()).ok).toBe(false);
  });

  it("ignores missing amounts on actions that do not count", async () => {
    seed("full-denied", { decision: "deny", args: { payment_id: PAY } });
    expect(unwrap(await stats())).toEqual({ amountPaise: 0, count: 0 });
  });

  it("fails closed when the sum overflows", async () => {
    seed("a", { args: { amount: 999_999_999_999 } });
    const first = unwrap(store.readActivitySince(0))[0];
    if (first === undefined) throw new Error("seed failed");
    // 10,000 × ~10^12 paise exceeds Number.MAX_SAFE_INTEGER (~9×10^15).
    const o = opts({
      store: {
        readActivitySince: () => ({ ok: true, value: Array.from({ length: 10_000 }, () => first) }),
      },
    });
    const r = await stats(o);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("context.amount_overflow");
  });

  it("fails closed when the audit store cannot be read", async () => {
    const r = await stats(
      opts({ store: { readActivitySince: () => err("audit.read_failed", "x") } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("context.audit_unavailable");
    store.close();
    expect((await stats()).ok).toBe(false);
  });

  it("fails closed when the store throws", async () => {
    const r = await stats(
      opts({
        store: {
          readActivitySince: () => {
            throw new Error("boom");
          },
        },
      }),
    );
    expect(r.ok).toBe(false);
  });

  it.each([
    ["empty tools", { tools: [], windowMs: HOUR }],
    ["zero window", { tools: [TOOL], windowMs: 0 }],
    ["float window", { tools: [TOOL], windowMs: 1.5 }],
    ["empty tool name", { tools: [""], windowMs: HOUR }],
  ])("rejects an invalid query: %s", async (_n, q) => {
    const r = await createStatsPort(opts()).sumLast(q);
    expect(r.ok).toBe(false);
  });

  it("fails closed on an invalid clock", async () => {
    const r = await stats(opts({ clock: { nowMs: () => Number.NaN } }));
    expect(r.ok).toBe(false);
  });
});

// ---------- history ----------

describe("createHistoryPort", () => {
  const recent = (match: Record<string, string | number>, o: AdapterOpts = opts(), tool = TOOL) =>
    createHistoryPort(o).hasRecent({ tool, match, withinMs: 10 * MIN });

  it("finds a pending duplicate (awaiting approval)", async () => {
    seed("p", { decision: "require_approval", args: { payment_id: PAY, amount: 300_000 } });
    expect(unwrap(await recent({ payment_id: PAY, amount: 300_000 }))).toBe(true);
  });

  it("ignores denied actions", async () => {
    seed("d", { decision: "deny" });
    seed("r", { decision: "require_approval" }, "denied");
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(false);
  });

  it("ignores other tools, other amounts and other payments", async () => {
    seed("a", { tool: "create_payout" });
    seed("b", { args: { payment_id: PAY, amount: 20_000 } });
    seed("c", { args: { payment_id: "pay_OTHER", amount: 10_000 } });
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(false);
  });

  it("ignores closed actions outside the window and excluded ids", async () => {
    seed("old", {}, "success");
    clock.set(T0 + 11 * MIN);
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(false);
    seed("new");
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(true);
    expect(
      unwrap(
        await recent(
          { payment_id: PAY, amount: 10_000 },
          opts({ excludeAttemptIds: new Set(["new"]) }),
        ),
      ),
    ).toBe(false);
  });

  it("a pending approval still blocks a duplicate after the window (t0 + 11 min)", async () => {
    seed("p", { decision: "require_approval", args: { payment_id: PAY, amount: 300_000 } });
    clock.set(T0 + 11 * MIN);
    expect(unwrap(await recent({ payment_id: PAY, amount: 300_000 }))).toBe(true);
    // In-flight allow with no outcome yet: same.
    seed("inflight", { args: { payment_id: "pay_FLIGHT", amount: 1_000 } });
    clock.set(T0 + 30 * MIN);
    expect(unwrap(await recent({ payment_id: "pay_FLIGHT", amount: 1_000 }))).toBe(true);
  });

  it("an attempt that succeeded at t0 + 5 min is not a duplicate once outside the window", async () => {
    seed("p", { decision: "require_approval" });
    clock.set(T0 + 5 * MIN);
    unwrap(store.recordOutcome({ attemptId: "p", outcome: "success", latencyMs: 1 }));
    clock.set(T0 + 15 * MIN);
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(true);
    clock.set(T0 + 15 * MIN + 1);
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(false);
  });

  it("does not match an open attempt older than openLookbackMs", async () => {
    seed("p", { decision: "require_approval" });
    clock.set(T0 + DEFAULT_OPEN_LOOKBACK_MS + 1);
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(false);
  });

  it("refuses a match whose keys redaction would rename (unmatchable)", async () => {
    seed("p", { args: { payment_id: PAY, amount: 10_000 } });
    for (const match of [
      { "a@b.com": "x" },
      { payment_id: PAY, "a@b.com": 1 },
      { "9876543210": 1 },
    ]) {
      const r = await recent(match);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("history.unmatchable_query");
        expect(JSON.stringify(r.error)).not.toContain("a@b.com");
      }
    }
    // Values redacted to "[REDACTED]" are fine (over-match, fail closed).
    expect(unwrap(await recent({ customer_email: "a@b.com" }))).toBe(false);
    expect(unwrap(await recent({ payment_id: PAY, amount: 10_000 }))).toBe(true);
  });

  it("fails closed on store errors and invalid queries", async () => {
    const bad = opts({ store: { readActivitySince: () => err("audit.read_failed", "x") } });
    expect((await recent({ payment_id: PAY }, bad)).ok).toBe(false);
    const h = createHistoryPort(opts());
    expect((await h.hasRecent({ tool: "", match: {}, withinMs: MIN })).ok).toBe(false);
    expect((await h.hasRecent({ tool: TOOL, match: {}, withinMs: -1 })).ok).toBe(false);
  });
});

// ---------- razorpay lookup ----------

describe("createRazorpayLookup", () => {
  it("maps fetch_payment fields and calls upstream with the lookup timeout", async () => {
    const up = fakeUpstream();
    const p = unwrap(await createRazorpayLookup(opts({ upstream: up })).payment(PAY));
    expect(p).toEqual({
      id: PAY,
      status: "captured",
      amountPaise: 5_000_000,
      amountRefundedPaise: 0,
      currency: "INR",
    });
    expect(up.calls).toEqual([
      {
        name: FETCH_PAYMENT_TOOL,
        args: { payment_id: PAY },
        opts: { timeoutMs: DEFAULT_LOOKUP_TIMEOUT_MS },
      },
    ]);
  });

  it("passes the currency through verbatim", async () => {
    const up = fakeUpstream(() => okPayment({ currency: "inr" }));
    const p = unwrap(await createRazorpayLookup(opts({ upstream: up })).payment(PAY));
    expect(p.currency).toBe("inr");
  });

  it("honours a custom timeout", async () => {
    const up = fakeUpstream();
    unwrap(await createRazorpayLookup(opts({ upstream: up, lookupTimeoutMs: 700 })).payment(PAY));
    expect(up.calls[0]?.opts).toEqual({ timeoutMs: 700 });
  });

  const failures: [string, UpstreamCallOutcome, string][] = [
    ["isError", textResult('{"error":"not found"}', true), "razorpay.upstream_error"],
    [
      "timeout",
      { kind: "error", error: "upstream_timeout", message: "t", forwarded: true },
      "razorpay.timeout",
    ],
    [
      "unavailable",
      { kind: "error", error: "upstream_unavailable", message: "u", forwarded: false },
      "razorpay.unavailable",
    ],
    ["malformed JSON", textResult("payment: captured"), "razorpay.malformed"],
    ["id mismatch", okPayment({ id: "pay_OTHER" }), "razorpay.id_mismatch"],
    ["float amount", okPayment({ amount: 5000.5 }), "razorpay.malformed"],
    ["string amount", okPayment({ amount: "5000" }), "razorpay.malformed"],
    ["negative refunded", okPayment({ amount_refunded: -1 }), "razorpay.malformed"],
    ["refunded > amount", okPayment({ amount_refunded: 5_000_001 }), "razorpay.malformed"],
    ["missing currency", okPayment({ currency: undefined }), "razorpay.malformed"],
    ["JSON array", textResult("[]"), "razorpay.malformed"],
    ["no content", { kind: "ok", result: { content: [] } }, "razorpay.malformed"],
    [
      "two content items",
      {
        kind: "ok",
        result: {
          content: [
            { type: "text", text: "{}" },
            { type: "text", text: "{}" },
          ],
        },
      },
      "razorpay.malformed",
    ],
    [
      "image content",
      { kind: "ok", result: { content: [{ type: "image", data: "AA==", mimeType: "image/png" }] } },
      "razorpay.malformed",
    ],
  ];

  it.each(failures)("fails closed: %s", async (_n, outcome, code) => {
    const r = await createRazorpayLookup(opts({ upstream: fakeUpstream(() => outcome) })).payment(
      PAY,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe(code);
      // Never leak the payload (PII) in errors.
      expect(JSON.stringify(r.error)).not.toMatch(/example\.com|9999999999|captured/);
    }
  });

  it("fails closed when the result contains credential material", async () => {
    const leaked = okPayment({ notes: { k: "rzp_test_LEAKEDKEY123" } });
    const redact = (s: string): string => s.replaceAll("rzp_test_LEAKEDKEY123", "[REDACTED]");
    const r = await createRazorpayLookup(
      opts({ upstream: fakeUpstream(() => leaked), redact }),
    ).payment(PAY);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("razorpay.credential_leak");
  });

  it("fails closed when upstream throws", async () => {
    const up: UpstreamPaymentPort = {
      callTool: () => Promise.reject(new Error("boom")),
    };
    const r = await createRazorpayLookup(opts({ upstream: up })).payment(PAY);
    expect(r.ok).toBe(false);
  });

  it.each(["", "PAY_1", "pay_", "pay_abc-1", "pay_1 ", "rfnd_123", `pay_${"a".repeat(41)}`])(
    "refuses a bad id %j without calling upstream",
    async (id) => {
      const up = fakeUpstream();
      const r = await createRazorpayLookup(opts({ upstream: up })).payment(id);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("razorpay.invalid_id");
      expect(up.calls).toEqual([]);
    },
  );

  it("accepts the maximum lookup timeout", async () => {
    expect(MAX_LOOKUP_TIMEOUT_MS).toBe(1900);
    const up = fakeUpstream();
    unwrap(
      await createRazorpayLookup(
        opts({ upstream: up, lookupTimeoutMs: MAX_LOOKUP_TIMEOUT_MS }),
      ).payment(PAY),
    );
    expect(up.calls[0]?.opts).toEqual({ timeoutMs: MAX_LOOKUP_TIMEOUT_MS });
  });

  it.each([0, -1, 1.5, MAX_LOOKUP_TIMEOUT_MS + 1, 2000, 60_000])(
    "rejects an invalid lookup timeout %d",
    async (t) => {
      const up = fakeUpstream();
      const r = await createRazorpayLookup(opts({ upstream: up, lookupTimeoutMs: t })).payment(PAY);
      expect(r.ok).toBe(false);
      expect(up.calls).toEqual([]);
    },
  );
});

// ---------- order lookup ----------

const ORDER = "order_TEST123";

function okOrder(over: Record<string, unknown> = {}): UpstreamCallOutcome {
  return textResult(
    JSON.stringify({
      id: ORDER,
      entity: "order",
      amount: 50_000,
      amount_paid: 0,
      currency: "INR",
      status: "created",
      notes: { email: "someone@example.com" },
      ...over,
    }),
  );
}

describe("createOrderLookup", () => {
  it("uses the read tool fetch_order with the lookup timeout and maps id / amount / currency", async () => {
    expect(classifyTool(FETCH_ORDER_TOOL)).toBe("read");
    const up = fakeUpstream(() => okOrder());
    const o = unwrap(await createOrderLookup(opts({ upstream: up })).order(ORDER));
    expect(o).toEqual({ id: ORDER, amountPaise: 50_000, currency: "INR" });
    expect(up.calls).toEqual([
      {
        name: FETCH_ORDER_TOOL,
        args: { order_id: ORDER },
        opts: { timeoutMs: DEFAULT_LOOKUP_TIMEOUT_MS },
      },
    ]);
  });

  it("passes the currency through verbatim (USD stays USD)", async () => {
    const up = fakeUpstream(() => okOrder({ currency: "USD" }));
    expect(unwrap(await createOrderLookup(opts({ upstream: up })).order(ORDER)).currency).toBe(
      "USD",
    );
  });

  it.each<[string, UpstreamCallOutcome, string]>([
    ["isError", textResult("not found", true), "razorpay.upstream_error"],
    [
      "timeout",
      { kind: "error", error: "upstream_timeout", message: "t", forwarded: true },
      "razorpay.timeout",
    ],
    ["not JSON", textResult("order created"), "razorpay.malformed"],
    ["id mismatch", okOrder({ id: "order_OTHER" }), "razorpay.id_mismatch"],
    ["float amount", okOrder({ amount: 1.5 }), "razorpay.malformed"],
    ["negative amount", okOrder({ amount: -1 }), "razorpay.malformed"],
    ["missing currency", okOrder({ currency: undefined }), "razorpay.malformed"],
    ["no content", { kind: "ok", result: { content: [] } }, "razorpay.malformed"],
  ])("fails closed: %s", async (_n, outcome, code) => {
    const r = await createOrderLookup(opts({ upstream: fakeUpstream(() => outcome) })).order(ORDER);
    expect(!r.ok && r.error.code).toBe(code);
    if (!r.ok) expect(JSON.stringify(r.error)).not.toMatch(/example\.com/);
  });

  it("fails closed on credential material and when upstream throws", async () => {
    const leaked = okOrder({ notes: { k: "rzp_test_LEAKEDKEY123" } });
    const redact = (s: string): string => s.replaceAll("rzp_test_LEAKEDKEY123", "[REDACTED]");
    const r = await createOrderLookup(opts({ upstream: fakeUpstream(() => leaked), redact })).order(
      ORDER,
    );
    expect(!r.ok && r.error.code).toBe("razorpay.credential_leak");
    const thrower: UpstreamPaymentPort = { callTool: () => Promise.reject(new Error("boom")) };
    expect((await createOrderLookup(opts({ upstream: thrower })).order(ORDER)).ok).toBe(false);
  });

  it.each(["", "order_", "ORDER_1", "order_a-b", "pay_123", `order_${"a".repeat(41)}`])(
    "refuses a bad id %j without calling upstream",
    async (id) => {
      const up = fakeUpstream(() => okOrder());
      const r = await createOrderLookup(opts({ upstream: up })).order(id);
      expect(!r.ok && r.error.code).toBe("razorpay.invalid_id");
      expect(up.calls).toEqual([]);
    },
  );

  it.each([0, 1.5, MAX_LOOKUP_TIMEOUT_MS + 1])(
    "rejects an invalid lookup timeout %d",
    async (t) => {
      const up = fakeUpstream(() => okOrder());
      const r = await createOrderLookup(opts({ upstream: up, lookupTimeoutMs: t })).order(ORDER);
      expect(r.ok).toBe(false);
      expect(up.calls).toEqual([]);
    },
  );
});

// ---------- open deny attempts ----------

describe("open deny attempts never count", () => {
  it("a deny attempt with no outcome yet is ignored by history and stats", async () => {
    seed("deny-open", { decision: "deny", matchedRules: ["refund.hard_cap"] });
    expect(unwrap(await stats())).toEqual({ amountPaise: 0, count: 0 });
    expect(
      unwrap(
        await createHistoryPort(opts()).hasRecent({
          tool: TOOL,
          match: { payment_id: PAY, amount: 10_000 },
          withinMs: HOUR,
        }),
      ),
    ).toBe(false);
    // control: the same attempt as allow (open) does count
    seed("allow-open");
    expect(unwrap(await stats())).toEqual({ amountPaise: 10_000, count: 1 });
  });
});

// ---------- createPolicyDeps shared snapshot ----------

describe("createPolicyDeps activity snapshot", () => {
  function counting(fail = false) {
    const calls: number[] = [];
    const src = {
      readActivitySince: (since: number): Result<AuditActivity[]> => {
        calls.push(since);
        return fail ? err("audit.read_failed", "x") : store.readActivitySince(since);
      },
    };
    return { calls, src };
  }

  it("is lazy, shared by history and stats, and reused across calls", async () => {
    seed("a", {}, "success");
    const { calls, src } = counting();
    const deps = createPolicyDeps({ ...opts({ store: src }), timer: fakeTimer() });
    expect(calls).toEqual([]);
    expect(
      unwrap(
        await deps.history.hasRecent({
          tool: TOOL,
          match: { payment_id: PAY },
          withinMs: 10 * MIN,
        }),
      ),
    ).toBe(true);
    expect(unwrap(await deps.stats.sumLast({ tools: [TOOL], windowMs: HOUR }))).toEqual({
      amountPaise: 10_000,
      count: 1,
    });
    expect(unwrap(await deps.stats.sumLast({ tools: [TOOL], windowMs: 10 * MIN }))).toEqual({
      amountPaise: 10_000,
      count: 1,
    });
    expect(calls).toHaveLength(1);
    // A window longer than the snapshot forces a fresh read.
    await deps.stats.sumLast({ tools: [TOOL], windowMs: 2 * DEFAULT_OPEN_LOOKBACK_MS });
    expect(calls).toHaveLength(2);
  });

  it("caches a read error: both ports fail closed after a single read", async () => {
    const { calls, src } = counting(true);
    const deps = createPolicyDeps({ ...opts({ store: src }), timer: fakeTimer() });
    expect((await deps.stats.sumLast({ tools: [TOOL], windowMs: HOUR })).ok).toBe(false);
    expect((await deps.history.hasRecent({ tool: TOOL, match: {}, withinMs: MIN })).ok).toBe(false);
    expect(
      (await deps.stats.sumLast({ tools: [TOOL], windowMs: 2 * DEFAULT_OPEN_LOOKBACK_MS })).ok,
    ).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it("standalone ports are not memoised (fresh read per call)", async () => {
    const { calls, src } = counting();
    const s = createStatsPort(opts({ store: src }));
    await s.sumLast({ tools: [TOOL], windowMs: HOUR });
    seed("late", {}, "success");
    expect(unwrap(await s.sumLast({ tools: [TOOL], windowMs: HOUR }))).toEqual({
      amountPaise: 10_000,
      count: 1,
    });
    expect(calls).toHaveLength(2);
  });
});

// ---------- system clock / timer ----------

describe("systemClock / systemTimer", () => {
  it("systemClock returns the current epoch ms", () => {
    const before = Date.now();
    const now = systemClock.nowMs();
    expect(now).toBeGreaterThanOrEqual(before);
    expect(Number.isSafeInteger(now)).toBe(true);
  });

  it("systemTimer fires after the delay", async () => {
    const t0 = Date.now();
    await systemTimer.after(20).promise;
    expect(Date.now() - t0).toBeGreaterThanOrEqual(15);
  });

  it("a cancelled systemTimer never fires", async () => {
    const h = systemTimer.after(10);
    h.cancel();
    const fired = await Promise.race([
      h.promise.then(() => true),
      new Promise<boolean>((res) => setTimeout(() => res(false), 40)),
    ]);
    expect(fired).toBe(false);
  });
});

// ---------- integration: default policy + real adapters ----------

describe("defaultPolicy with real adapters", () => {
  function compiled(): CompiledPolicy {
    const r = compilePolicy(defaultPolicy);
    if (!r.ok) throw new Error(r.error.message);
    return r.value;
  }
  const policy = compiled();

  function refund(amount: number, o: Partial<AdapterOpts> = {}): Promise<EvalResult> {
    return evaluate(
      policy,
      {
        tool: TOOL,
        args: { payment_id: PAY, amount },
        reason: "customer was double charged",
        sessionId: "sess",
      },
      createPolicyDeps({ ...opts(o), timer: fakeTimer() }),
    );
  }

  it("allows a ₹300 refund with healthy data, looking the payment up once", async () => {
    const up = fakeUpstream();
    const r = await refund(30_000, { upstream: up });
    expect(r.decision.type).toBe("allow");
    expect(up.calls).toHaveLength(1);
  });

  it("denies when the payment lookup fails (fail closed)", async () => {
    const up = fakeUpstream(() => ({
      kind: "error",
      error: "upstream_timeout",
      message: "t",
      forwarded: true,
    }));
    const r = await refund(30_000, { upstream: up });
    expect(r.decision.type).toBe("deny");
    expect(r.decision.ruleId).toBe("engine-error");
  });

  it("denies a non-INR payment, even lower-case inr", async () => {
    const r = await refund(30_000, {
      upstream: fakeUpstream(() => okPayment({ currency: "inr" })),
    });
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "refund.currency_not_inr" });
  });

  it(`denies the ${String(VELOCITY_MAX_COUNT + 1)}th refund when ${String(VELOCITY_MAX_COUNT)} are pending`, async () => {
    for (let i = 0; i < VELOCITY_MAX_COUNT; i++) {
      seed(`pending-${String(i)}`, {
        decision: "require_approval",
        args: { payment_id: `pay_P${String(i)}`, amount: 1_000 },
      });
    }
    const r = await refund(30_000);
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "refund.velocity" });
  });

  it("denies a duplicate of a pending refund", async () => {
    seed("dup", { decision: "require_approval", args: { payment_id: PAY, amount: 30_000 } });
    const r = await refund(30_000);
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "refund.duplicate" });
  });

  it("does not treat a rejected approval as a duplicate", async () => {
    seed(
      "rej",
      { decision: "require_approval", args: { payment_id: PAY, amount: 30_000 } },
      "denied",
    );
    const r = await refund(30_000);
    expect(r.decision.type).toBe("allow");
  });

  it("denies when recent history is unreadable", async () => {
    seed("full", { args: { payment_id: "pay_X" } }); // counted, but no amount
    const r = await refund(30_000);
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
  });

  it("reads the audit store once per evaluation (history + stats share a snapshot)", async () => {
    let reads = 0;
    const counting = {
      readActivitySince: (since: number) => {
        reads++;
        return store.readActivitySince(since);
      },
    };
    seed("other", { args: { payment_id: "pay_OTHER", amount: 1_000 } }, "success");
    const r = await refund(30_000, { store: counting });
    expect(r.decision.type).toBe("allow");
    expect(reads).toBe(1);
  });

  it("caches a read error for the evaluation and denies", async () => {
    let reads = 0;
    const failing = {
      readActivitySince: () => {
        reads++;
        return err("audit.read_failed", "x");
      },
    };
    const r = await refund(30_000, { store: failing });
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(reads).toBe(1);
  });

  it("denies a duplicate of a refund still awaiting approval 11 minutes later", async () => {
    seed("dup", { decision: "require_approval", args: { payment_id: PAY, amount: 30_000 } });
    clock.set(T0 + 11 * MIN);
    const r = await refund(30_000);
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "refund.duplicate" });
  });

  it("works with the system clock and timer", async () => {
    const r = await evaluate(
      policy,
      {
        tool: TOOL,
        args: { payment_id: PAY, amount: 30_000 },
        reason: "customer was double charged",
        sessionId: "s",
      },
      createPolicyDeps({ store, upstream: fakeUpstream(), clock: systemClock, timer: systemTimer }),
    );
    expect(r.decision.type).toBe("allow");
  });
});

describe("T010: verifications in history / stats", () => {
  it("not_happened is not counted; happened counts; unknown counts even outside the window", async () => {
    const s = unwrap(openAuditStore({ path: ":memory:" }));
    const now = Date.now();
    const iso = (ago: number): string => new Date(now - ago).toISOString();
    const add = (
      id: string,
      ago: number,
      amount: number,
      result: "happened" | "not_happened" | "unknown",
    ): void => {
      unwrap(
        s.recordAttempt({
          id,
          ts: iso(ago),
          sessionId: "s",
          tool: TOOL,
          args: { payment_id: PAY, amount },
          reason: "r",
          decision: "allow",
          matchedRules: [],
        }),
      );
      unwrap(s.recordOutcome({ attemptId: id, ts: iso(ago), outcome: "timeout", latencyMs: 1 }));
      unwrap(
        s.recordVerification({
          attemptId: id,
          ts: iso(ago),
          trigger: "timeout",
          result,
          method: "refund_notes_marker",
          needsHuman: result === "unknown",
        }),
      );
    };
    add("u-old", 3 * HOUR, 300, "unknown"); // outside a 1 h window, still counted
    add("n1", 10 * MIN, 1_000, "not_happened");
    add("h1", 5 * MIN, 50, "happened");
    const upstream: UpstreamPaymentPort = {
      callTool: () => Promise.reject(new Error("unused")),
    };
    const stats = createStatsPort({ store: s, upstream, clock: systemClock });
    expect(unwrap(await stats.sumLast({ tools: [TOOL], windowMs: HOUR }))).toEqual({
      amountPaise: 350,
      count: 2,
    });
    const history = createHistoryPort({ store: s, upstream, clock: systemClock });
    expect(
      unwrap(await history.hasRecent({ tool: TOOL, match: { amount: 1_000 }, withinMs: HOUR })),
    ).toBe(false);
    expect(
      unwrap(await history.hasRecent({ tool: TOOL, match: { amount: 300 }, withinMs: MIN })),
    ).toBe(true);
    s.close();
  });
});
