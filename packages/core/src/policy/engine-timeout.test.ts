import { describe, expect, it } from "vitest";
import { ok } from "../result.js";
import { compilePolicy } from "./compile.js";
import { definePolicy, rule } from "./dsl.js";
import { evaluate } from "./engine.js";
import { fakeDeps, fakeTimer } from "./fakes.js";
import type { CompiledPolicy, EvalInput, PolicySpec, Rule, Timer } from "./types.js";

const T = "create_refund";
const INPUT: EvalInput = {
  tool: T,
  args: { amount: 30_000 },
  reason: "customer refund",
  sessionId: "s",
};

function compile(rules: Rule[], extra: Partial<PolicySpec> = {}): CompiledPolicy {
  const r = compilePolicy(definePolicy({ rules, default: "deny", ...extra }));
  if (!r.ok) throw new Error(r.error.message);
  return r.value;
}

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve: (v: T) => void = () => undefined;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

/** Real timer for tests only (core src cannot use setTimeout — D-007). */
const realTimer: Timer = {
  after(ms) {
    let id: ReturnType<typeof setTimeout> | undefined;
    const promise = new Promise<void>((res) => {
      id = setTimeout(res, ms);
    });
    return { promise, cancel: () => clearTimeout(id) };
  },
};

describe("evaluate — timeout", () => {
  it("arms the timer with the policy budget (default 2000ms)", async () => {
    const timer = fakeTimer();
    await evaluate(compile([rule("ok").on(T).allow()]), INPUT, fakeDeps({ timer }));
    expect(timer.armed.map((t) => t.ms)).toEqual([2000]);
    await evaluate(
      compile([rule("ok").on(T).allow()], { timeoutMs: 50 }),
      INPUT,
      fakeDeps({ timer }),
    );
    expect(timer.armed.map((t) => t.ms)).toEqual([2000, 50]);
  });

  it("slow predicate ⇒ deny engine-timeout when the timer fires", async () => {
    const timer = fakeTimer();
    const hang = deferred<boolean>();
    const p = evaluate(
      compile([
        rule("ok").on(T).allow(),
        rule("slow")
          .on(T)
          .when(() => hang.promise)
          .deny("x"),
      ]),
      INPUT,
      fakeDeps({ timer }),
    );
    await Promise.resolve();
    timer.fire();
    const r = await p;
    expect(r.decision).toEqual({
      type: "deny",
      ruleId: "engine-timeout",
      message: 'Policy evaluation exceeded 2000ms in rule "slow"; action denied',
      matchedRules: ["ok"],
    });
    expect(r.trace).toEqual([{ ruleId: "ok", action: "allow", result: "matched" }]);
  });

  it("slow port call ⇒ engine-timeout", async () => {
    const timer = fakeTimer();
    const p = evaluate(
      compile([
        rule("look")
          .on(T)
          .when((c) => c.razorpay.payment("pay_1").then(() => false))
          .deny("x"),
        rule("ok").on(T).allow(),
      ]),
      INPUT,
      fakeDeps({ timer, razorpay: { payment: () => new Promise(() => undefined) } }),
    );
    timer.fire();
    expect((await p).decision).toMatchObject({ type: "deny", ruleId: "engine-timeout" });
  });

  it("cancels the timer when evaluation finishes first", async () => {
    const timer = fakeTimer();
    const r = await evaluate(compile([rule("ok").on(T).allow()]), INPUT, fakeDeps({ timer }));
    expect(r.decision.type).toBe("allow");
    expect(timer.armed).toEqual([{ ms: 2000, cancelled: true, fired: false }]);
  });

  it("cancels the timer on failure paths too", async () => {
    const timer = fakeTimer();
    await evaluate(
      compile([rule("ok").on(T).allow()]),
      { ...INPUT, args: null },
      fakeDeps({ timer }),
    );
    expect(timer.armed[0]?.cancelled).toBe(true);
  });

  it("ignores a late result after the timeout and refuses late port calls", async () => {
    const timer = fakeTimer();
    const hang = deferred<boolean>();
    let lateLookup: Promise<unknown> | undefined;
    let lookups = 0;
    const deps = fakeDeps({
      timer,
      razorpay: {
        payment: () => {
          lookups++;
          return Promise.resolve(
            ok({
              id: "p",
              status: "captured",
              amountPaise: 1,
              amountRefundedPaise: 0,
              currency: "INR",
            }),
          );
        },
      },
    });
    const p = evaluate(
      compile([
        rule("slow")
          .on(T)
          .when(async (c) => {
            const v = await hang.promise;
            lateLookup = c.razorpay.payment("p").then(
              () => "resolved",
              (e: unknown) => (e instanceof Error ? e.message : "?"),
            );
            return v;
          })
          .allow(),
      ]),
      INPUT,
      deps,
    );
    timer.fire();
    const r = await p;
    const snapshot = JSON.stringify(r);
    hang.resolve(true);
    await new Promise((res) => setTimeout(res, 0));
    expect(JSON.stringify(r)).toBe(snapshot);
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-timeout" });
    expect(await lateLookup).toBe("evaluation already finished");
    expect(lookups).toBe(0);
  });

  it("a timer whose promise rejects ⇒ engine-error", async () => {
    const timer: Timer = {
      after: () => ({ promise: Promise.reject(new Error("timer broke")), cancel: () => undefined }),
    };
    const hang = deferred<boolean>();
    const r = await evaluate(
      compile([
        rule("slow")
          .on(T)
          .when(() => hang.promise)
          .allow(),
      ]),
      INPUT,
      fakeDeps({ timer }),
    );
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
  });

  it("a timer whose cancel throws ⇒ engine-error (fail closed even after an allow)", async () => {
    const timer: Timer = {
      after: () => ({
        promise: new Promise(() => undefined),
        cancel: () => {
          throw new Error("x");
        },
      }),
    };
    const r = await evaluate(compile([rule("ok").on(T).allow()]), INPUT, fakeDeps({ timer }));
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-error" });
  });

  it("with a real timer, a slow async predicate is denied after ~timeoutMs", async () => {
    const started = Date.now();
    const r = await evaluate(
      compile(
        [
          rule("slow")
            .on(T)
            .when(() => new Promise<boolean>((res) => setTimeout(() => res(false), 2_000)))
            .deny("x"),
          rule("ok").on(T).allow(),
        ],
        { timeoutMs: 30 },
      ),
      INPUT,
      fakeDeps({ timer: realTimer }),
    );
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "engine-timeout" });
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});
