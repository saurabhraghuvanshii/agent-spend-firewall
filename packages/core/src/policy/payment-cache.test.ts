import { describe, expect, it } from "vitest";
import { err, ok, type Result } from "../result.js";
import { compilePolicy } from "./compile.js";
import { PolicyFault, createContext, newEvalState } from "./context.js";
import { definePolicy, rule } from "./dsl.js";
import { evaluate } from "./engine.js";
import { fakeDeps, fakeRazorpay, fakeTimer } from "./fakes.js";
import type {
  CompiledPolicy,
  PaymentInfo,
  PolicySpec,
  RazorpayLookupPort,
  EvalResult,
  PolicyDeps,
} from "./types.js";

const T = "create_refund";
const PAY: PaymentInfo = {
  id: "pay_1",
  status: "captured",
  amountPaise: 100_000,
  amountRefundedPaise: 0,
  currency: "INR",
};

function compile(spec: PolicySpec): CompiledPolicy {
  const r = compilePolicy(spec);
  if (!r.ok) throw new Error(r.error.message);
  return r.value;
}

function run(policy: CompiledPolicy, deps: PolicyDeps, args: unknown = { payment_id: "pay_1" }) {
  return evaluate(policy, { tool: T, args, reason: "r", sessionId: "s" }, deps);
}

/** Port that counts calls and returns `results` in order (last one repeats). */
function countingPort(...results: Result<PaymentInfo>[]): RazorpayLookupPort & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    payment(id) {
      calls.push(id);
      const r = results[Math.min(calls.length - 1, results.length - 1)];
      return Promise.resolve(r ?? err("x", "none"));
    },
  };
}

/** Two gate rules that each look up the same payment. */
const twoLookups = compile(
  definePolicy({
    default: "deny",
    rules: [
      rule("a.currency")
        .on(T)
        .when(async (c) => (await c.razorpay.payment(c.string("payment_id"))).currency !== "INR")
        .deny("non-INR"),
      rule("b.captured")
        .on(T)
        .when(async (c) => (await c.razorpay.payment(c.string("payment_id"))).status !== "captured")
        .deny("not captured"),
      rule("ok").on(T).allow(),
    ],
  }),
);

describe("ctx.razorpay.payment per-evaluation cache", () => {
  it("two rules looking up the same id make ONE port call", async () => {
    const rp = fakeRazorpay([PAY]);
    const r = await run(twoLookups, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "allow", ruleId: "ok" });
    expect(rp.calls).toEqual(["pay_1"]);
  });

  it("concurrent lookups in one predicate share a single in-flight call", async () => {
    const rp = fakeRazorpay([PAY]);
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("both")
            .on(T)
            .when(async (c) => {
              const [x, y] = await Promise.all([
                c.razorpay.payment("pay_1"),
                c.razorpay.payment("pay_1"),
              ]);
              return x !== y;
            })
            .deny("different objects"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }));
    expect(r.decision.type).toBe("allow");
    expect(rp.calls).toEqual(["pay_1"]);
  });

  it("different ids are looked up separately", async () => {
    const rp = fakeRazorpay([PAY, { ...PAY, id: "pay_2" }]);
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("a")
            .on(T)
            .when(async (c) => (await c.razorpay.payment("pay_1")).id !== "pay_1")
            .deny("x"),
          rule("b")
            .on(T)
            .when(async (c) => (await c.razorpay.payment("pay_2")).id !== "pay_2")
            .deny("x"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }));
    expect(r.decision.type).toBe("allow");
    expect(rp.calls).toEqual(["pay_1", "pay_2"]);
  });

  it("is not shared across two evaluate() calls", async () => {
    const rp = fakeRazorpay([PAY]);
    const deps = fakeDeps({ razorpay: rp });
    await run(twoLookups, deps);
    await run(twoLookups, deps);
    expect(rp.calls).toEqual(["pay_1", "pay_1"]);
  });

  it("a second evaluation sees fresh data (no stale cached payment)", async () => {
    const rp = countingPort(ok(PAY), ok({ ...PAY, status: "refunded" }));
    const deps = fakeDeps({ razorpay: rp });
    expect((await run(twoLookups, deps)).decision.type).toBe("allow");
    expect((await run(twoLookups, deps)).decision).toMatchObject({
      type: "deny",
      ruleId: "b.captured",
    });
    expect(rp.calls).toHaveLength(2);
  });

  it("is shared between the transform phase and the gate phase", async () => {
    const rp = fakeRazorpay([PAY]);
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("clamp")
            .on(T)
            .transform(async (c) => {
              const pay = await c.razorpay.payment(c.string("payment_id"));
              return { amount: Math.min(c.amountPaise(), pay.amountPaise) };
            }),
          rule("captured")
            .on(T)
            .when(
              async (c) => (await c.razorpay.payment(c.string("payment_id"))).status !== "captured",
            )
            .deny("not captured"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }), { payment_id: "pay_1", amount: 500_000 });
    expect(r.decision).toMatchObject({
      type: "transform",
      ruleId: "clamp",
      patch: { amount: 100_000 },
    });
    expect(rp.calls).toEqual(["pay_1"]);
  });

  it("a cached failure denies, attributed to the first rule that awaited it", async () => {
    const rp = countingPort(err("razorpay.unavailable", "down"));
    const r = await run(twoLookups, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(r.decision.type === "deny" && r.decision.message).toMatch(/a\.currency.*lookup failed/);
    expect(rp.calls).toHaveLength(1);
  });

  it("a cached failure still denies when the rule swallowed it", async () => {
    const rp = countingPort(err("razorpay.unavailable", "down"));
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("first")
            .on(T)
            .when((c) =>
              c.razorpay.payment("pay_1").then(
                () => false,
                () => false,
              ),
            )
            .deny("x"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(r.decision.type === "deny" && r.decision.message).toMatch(/Rule "first".*lookup failed/);
    expect(rp.calls).toHaveLength(1);
  });

  it("every rule awaiting a cached failure gets its own fault (attributed to it)", async () => {
    const rp = countingPort(err("razorpay.unavailable", "down"));
    const state = newEvalState();
    const deps = fakeDeps({ razorpay: rp });
    const input = { tool: T, args: Object.freeze({}), reason: "r", sessionId: "s" };
    state.currentRuleId = "rule-a";
    const a = createContext(state, input, deps).razorpay.payment("pay_1");
    state.currentRuleId = "rule-b";
    const b = createContext(state, input, deps).razorpay.payment("pay_1");
    const [ea, eb] = await Promise.allSettled([a, b]);
    expect(ea).toMatchObject({
      status: "rejected",
      reason: { name: "PolicyFault", ruleId: "rule-a" },
    });
    expect(eb).toMatchObject({
      status: "rejected",
      reason: { name: "PolicyFault", ruleId: "rule-b", code: "engine-error" },
    });
    expect(ea.status === "rejected" && ea.reason).toBeInstanceOf(PolicyFault);
    expect(state.fault).toBeInstanceOf(PolicyFault);
    expect(state.paymentCache.size).toBe(1);
    expect(state.inflight).toHaveLength(2);
    expect(rp.calls).toEqual(["pay_1"]);
  });

  it("a cached throwing port denies every awaiting rule; port is called once", async () => {
    const calls: string[] = [];
    const rp: RazorpayLookupPort = {
      payment(id) {
        calls.push(id);
        return Promise.reject(new Error("boom"));
      },
    };
    const r = await run(twoLookups, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(r.decision.type === "deny" && r.decision.message).toMatch(/lookup threw/);
    expect(calls).toEqual(["pay_1"]);
  });

  it("a cached malformed value denies", async () => {
    const bad = { ...PAY, amountPaise: 1.5 };
    const rp = countingPort(ok(bad));
    const r = await run(twoLookups, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(r.decision.type === "deny" && r.decision.message).toMatch(/invalid value/);
  });

  it("returns a frozen snapshot: a rule cannot tamper with what later rules see", async () => {
    const source = { ...PAY };
    const rp = countingPort(ok(source));
    let mutationThrew = false;
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("tamper")
            .on(T)
            .when(async (c) => {
              const pay = await c.razorpay.payment("pay_1");
              try {
                (pay as { status: string }).status = "captured-ish";
              } catch {
                mutationThrew = true;
              }
              return false;
            })
            .deny("x"),
          rule("captured")
            .on(T)
            .when(async (c) => (await c.razorpay.payment("pay_1")).status !== "captured")
            .deny("not captured"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    // Port mutates its own object after returning: the snapshot is detached.
    const r = await run(p, fakeDeps({ razorpay: rp }));
    source.status = "refunded";
    expect(mutationThrew).toBe(true);
    expect(r.decision.type).toBe("allow");
  });

  it("an unawaited cached lookup that fails still denies (settleInflight)", async () => {
    const rp = countingPort(err("razorpay.unavailable", "down"));
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("fire-and-forget")
            .on(T)
            .when((c) => {
              void c.razorpay.payment("pay_1").catch(() => undefined);
              void c.razorpay.payment("pay_1").catch(() => undefined);
              return false;
            })
            .deny("x"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(r.decision.type === "deny" && r.decision.message).toMatch(/unawaited/);
    expect(rp.calls).toHaveLength(1);
  });

  it("a cache hit after the evaluation timed out is refused", async () => {
    const timer = fakeTimer();
    let late: Promise<string> | undefined;
    let release: () => void = () => undefined;
    const gate = new Promise<void>((res) => {
      release = res;
    });
    const rp = fakeRazorpay([PAY]);
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("slow")
            .on(T)
            .when(async (c) => {
              await c.razorpay.payment("pay_1");
              await gate;
              late = c.razorpay.payment("pay_1").then(
                () => "resolved",
                (e: unknown) => (e instanceof Error ? e.message : "rejected"),
              );
              return false;
            })
            .deny("x"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const pending: Promise<EvalResult> = run(p, fakeDeps({ razorpay: rp, timer }));
    await Promise.resolve();
    await Promise.resolve();
    timer.fire();
    const r = await pending;
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-timeout" });
    release();
    await new Promise<void>((res) => queueMicrotask(res));
    for (let i = 0; i < 5 && late === undefined; i++) await Promise.resolve();
    expect(await late).toBe("evaluation already finished");
    expect(rp.calls).toEqual(["pay_1"]);
  });

  it("rejects a port value whose id differs from the requested id", async () => {
    const rp = countingPort(ok({ ...PAY, id: "pay_OTHER" }));
    const r = await run(twoLookups, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    expect(r.decision.type === "deny" && r.decision.message).toMatch(
      /a\.currency.*razorpay payment lookup returned an invalid value/,
    );
    expect(rp.calls).toEqual(["pay_1"]);
  });
});

/** Port whose single lookup stays pending until the test calls `fail()`. */
function deferredFailingPort(): RazorpayLookupPort & { calls: string[]; fail(): void } {
  const calls: string[] = [];
  let settle: (r: Result<PaymentInfo>) => void = () => undefined;
  const pending = new Promise<Result<PaymentInfo>>((res) => {
    settle = res;
  });
  return {
    calls,
    payment(id) {
      calls.push(id);
      return pending;
    },
    fail() {
      settle(err("razorpay.unavailable", "down"));
    },
  };
}

async function flush(): Promise<void> {
  for (let i = 0; i < 10; i++) await Promise.resolve();
}

/**
 * Attribution rule (documented): a failing shared lookup is attributed per caller to the rule
 * that called `payment(id)` (captured at call time, never at settle time). The evaluation's
 * recorded fault, and so the deny message, names the FIRST rule that called `payment(id)` for
 * that id — a rule that was merely current when the lookup settled is never named.
 */
describe("shared payment lookup fault attribution", () => {
  it("a lookup failing while an unrelated rule is current is not attributed to it", async () => {
    const rp = deferredFailingPort();
    const state = newEvalState();
    const deps = fakeDeps({ razorpay: rp });
    const input = { tool: T, args: Object.freeze({}), reason: "r", sessionId: "s" };
    state.currentRuleId = "starter";
    const a = createContext(state, input, deps).razorpay.payment("pay_1");
    state.currentRuleId = "bystander";
    rp.fail();
    await expect(a).rejects.toMatchObject({ name: "PolicyFault", ruleId: "starter" });
    expect(state.fault?.ruleId).toBe("starter");
  });

  it("engine: starter rule fires lookup, bystander is current at failure ⇒ deny names starter", async () => {
    const rp = deferredFailingPort();
    let bystanderRan = false;
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("starter")
            .on(T)
            .when((c) => {
              void c.razorpay.payment("pay_1").catch(() => undefined);
              return false;
            })
            .deny("x"),
          rule("bystander")
            .on(T)
            .when(async () => {
              bystanderRan = true;
              rp.fail();
              await flush();
              return false;
            })
            .deny("y"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }));
    expect(bystanderRan).toBe(true);
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    const msg = r.decision.type === "deny" ? r.decision.message : "";
    expect(msg).toMatch(/Rule "starter".*lookup failed/);
    expect(msg).not.toMatch(/bystander/);
    expect(rp.calls).toEqual(["pay_1"]);
  });

  it("rule A starts the lookup, rule B awaits the cached failing lookup ⇒ deny, never a rule that did not touch it", async () => {
    const rp = deferredFailingPort();
    let bSaw: unknown;
    const p = compile(
      definePolicy({
        default: "deny",
        rules: [
          rule("a.starts")
            .on(T)
            .when((c) => {
              void c.razorpay.payment("pay_1").catch(() => undefined);
              return false;
            })
            .deny("x"),
          rule("b.awaits")
            .on(T)
            .when(async (c) => {
              const pending = c.razorpay.payment("pay_1");
              rp.fail();
              try {
                await pending;
              } catch (e) {
                bSaw = e;
              }
              return false;
            })
            .deny("y"),
          rule("ok").on(T).allow(),
        ],
      }),
    );
    const r = await run(p, fakeDeps({ razorpay: rp }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
    // B's own rejection is attributed to B (the rule evaluating when it awaited)...
    expect(bSaw).toBeInstanceOf(PolicyFault);
    expect(bSaw).toMatchObject({ ruleId: "b.awaits", code: "engine-error" });
    // ...and the evaluation's deny names the first caller, A (deterministic: first registered).
    expect(r.decision.type === "deny" && r.decision.message).toMatch(
      /Rule "a\.starts".*lookup failed/,
    );
    expect(rp.calls).toEqual(["pay_1"]);
  });
});
