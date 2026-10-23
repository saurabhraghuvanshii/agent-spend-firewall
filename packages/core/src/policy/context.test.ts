import { describe, expect, it } from "vitest";
import { createContext, deepFreeze, newEvalState, toFrozenJsonObject } from "./context.js";
import { compilePolicy } from "./compile.js";
import { definePolicy, rule } from "./dsl.js";
import { evaluate } from "./engine.js";
import { fakeDeps } from "./fakes.js";
import type { Args, PolicyContext } from "./types.js";

const T = "create_refund";

function ctxFor(args: Args): { ctx: PolicyContext; state: ReturnType<typeof newEvalState> } {
  const state = newEvalState();
  state.currentRuleId = "r1";
  const frozen = toFrozenJsonObject(args);
  if (frozen === undefined) throw new Error("bad args");
  return {
    ctx: createContext(state, { tool: T, args: frozen, reason: "why", sessionId: "s" }, fakeDeps()),
    state,
  };
}

describe("ctx.amountPaise", () => {
  it("returns a positive safe integer from `amount` by default", () => {
    expect(ctxFor({ amount: 30_000 }).ctx.amountPaise()).toBe(30_000);
    expect(ctxFor({ amount: 1 }).ctx.amountPaise()).toBe(1);
    expect(ctxFor({ amount: Number.MAX_SAFE_INTEGER }).ctx.amountPaise()).toBe(
      Number.MAX_SAFE_INTEGER,
    );
  });

  it("reads another field when asked", () => {
    expect(ctxFor({ max_amount: 7 }).ctx.amountPaise("max_amount")).toBe(7);
  });

  it.each([
    ["string", { amount: "300" }],
    ["negative", { amount: -1 }],
    ["zero", { amount: 0 }],
    ["null", { amount: null }],
    ["missing", {}],
    ["object", { amount: { value: 1 } }],
  ] as [string, Args][])("rejects %s and records an invalid-amount fault", (_n, args) => {
    const { ctx, state } = ctxFor(args);
    expect(() => ctx.amountPaise()).toThrow(/positive integer amount in paise/);
    expect(state.fault?.code).toBe("invalid-amount");
    expect(state.fault?.ruleId).toBe("r1");
  });

  it.each([
    ["float 300.5", 300.5],
    ["unsafe 2**53", 2 ** 53],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
  ])("rejects %s (args never even reach rules: invalid-args)", async (_n, amount) => {
    const p = compilePolicy(definePolicy({ rules: [rule("ok").on(T).allow()], default: "deny" }));
    if (!p.ok) throw new Error("compile");
    const r = await evaluate(
      p.value,
      { tool: T, args: { amount }, reason: "r", sessionId: "s" },
      fakeDeps(),
    );
    expect(r.decision).toMatchObject({ type: "deny", ruleId: "invalid-args" });
  });

  it("the engine denies a rule that hits a bad amount with invalid-amount", async () => {
    const p = compilePolicy(
      definePolicy({
        rules: [
          rule("cap")
            .on(T)
            .when((c) => c.amountPaise() > 5)
            .deny("cap"),
          rule("ok").on(T).allow(),
        ],
        default: "deny",
      }),
    );
    if (!p.ok) throw new Error("compile");
    for (const amount of ["300", -1, 0]) {
      const r = await evaluate(
        p.value,
        { tool: T, args: { amount }, reason: "r", sessionId: "s" },
        fakeDeps(),
      );
      expect(r.decision).toMatchObject({ type: "deny", ruleId: "invalid-amount" });
      if (r.decision.type === "deny") {
        expect(r.decision.message).toContain('"cap"');
        expect(r.decision.message).not.toContain(String(amount));
      }
    }
    const missing = await evaluate(
      p.value,
      { tool: T, args: {}, reason: "r", sessionId: "s" },
      fakeDeps(),
    );
    expect(missing.decision).toMatchObject({ type: "deny", ruleId: "invalid-amount" });
  });

  it("does not echo hostile field names", () => {
    const { ctx } = ctxFor({});
    expect(() => ctx.amountPaise("4111 1111 1111 1111")).toThrow("field [field]");
  });

  it("ignores inherited properties", () => {
    const { ctx } = ctxFor({});
    expect(() => ctx.amountPaise("constructor")).toThrow();
    expect(ctx.has("toString")).toBe(false);
  });
});

describe("ctx.has / ctx.string", () => {
  it("has() is true only for own, non-null values", () => {
    const { ctx } = ctxFor({ a: 0, b: null, c: "" });
    expect([ctx.has("a"), ctx.has("b"), ctx.has("c"), ctx.has("d")]).toEqual([
      true,
      false,
      true,
      false,
    ]);
  });

  it("string() returns non-empty strings and faults otherwise", () => {
    const { ctx, state } = ctxFor({ id: "pay_1", empty: "", n: 5 });
    expect(ctx.string("id")).toBe("pay_1");
    expect(() => ctx.string("empty")).toThrow();
    expect(() => ctx.string("n")).toThrow();
    expect(state.fault?.code).toBe("invalid-args");
  });
});

describe("args isolation", () => {
  it("args are deep-frozen; mutation attempts throw and do not leak to later rules", async () => {
    const seen: unknown[] = [];
    const p = compilePolicy(
      definePolicy({
        rules: [
          rule("mutate")
            .on(T)
            .when((c) => {
              try {
                (c.args as Record<string, unknown>)["amount"] = 1;
              } catch {
                seen.push("top-level frozen");
              }
              try {
                ((c.args["notes"] as Record<string, unknown>)["x"] as unknown[]).push(9);
              } catch {
                seen.push("nested frozen");
              }
              return false;
            })
            .deny("x"),
          rule("check")
            .on(T)
            .when((c) => {
              seen.push(c.amountPaise(), c.args["notes"]);
              return true;
            })
            .allow(),
        ],
        default: "deny",
      }),
    );
    if (!p.ok) throw new Error("compile");
    const args = { amount: 500, notes: { x: [1] } };
    const r = await evaluate(p.value, { tool: T, args, reason: "r", sessionId: "s" }, fakeDeps());
    expect(seen).toEqual(["top-level frozen", "nested frozen", 500, { x: [1] }]);
    expect(r.decision).toMatchObject({ type: "allow", ruleId: "check" });
    expect(r.finalArgs).toEqual({ amount: 500, notes: { x: [1] } });
    expect(Object.isFrozen(r.finalArgs)).toBe(true);
  });

  it("args are a copy: caller mutation after the call does not affect rules", async () => {
    const args: Record<string, unknown> = { amount: 500 };
    let seenAmount = 0;
    const p = compilePolicy(
      definePolicy({
        rules: [
          rule("read")
            .on(T)
            .when(async (c) => {
              await Promise.resolve();
              seenAmount = c.amountPaise();
              return true;
            })
            .allow(),
        ],
        default: "deny",
      }),
    );
    if (!p.ok) throw new Error("compile");
    const pending = evaluate(p.value, { tool: T, args, reason: "r", sessionId: "s" }, fakeDeps());
    args["amount"] = 999_999;
    await pending;
    expect(seenAmount).toBe(500);
  });

  it("toFrozenJsonObject rejects non-plain objects and returns a detached copy", () => {
    expect(toFrozenJsonObject([1])).toBeUndefined();
    expect(toFrozenJsonObject(new Map())).toBeUndefined();
    const src = { a: { b: 1 } };
    const copy = toFrozenJsonObject(src);
    expect(copy).toEqual(src);
    expect(copy).not.toBe(src);
    expect(Object.isFrozen(src)).toBe(false);
    const nullProto = Object.assign(Object.create(null) as Record<string, unknown>, { a: 1 });
    expect(toFrozenJsonObject(nullProto)).toEqual({ a: 1 });
  });

  it("deepFreeze freezes nested arrays and objects", () => {
    const v = deepFreeze({ a: [{ b: 1 }] });
    expect(Object.isFrozen(v.a)).toBe(true);
    expect(Object.isFrozen(v.a[0])).toBe(true);
  });
});

describe("ctx ports and clock", () => {
  it("clock returning garbage ⇒ fault", () => {
    const state = newEvalState();
    const ctx = createContext(
      state,
      { tool: T, args: {}, reason: "", sessionId: "s" },
      fakeDeps({ clock: { nowMs: () => Number.NaN } }),
    );
    expect(() => ctx.nowMs()).toThrow();
    expect(state.fault?.code).toBe("engine-error");
  });

  it.each([
    [
      "empty match tool",
      (c: PolicyContext) => c.history.hasRecent({ tool: "", match: {}, withinMs: 1 }),
    ],
    ["zero window", (c: PolicyContext) => c.history.hasRecent({ tool: T, match: {}, withinMs: 0 })],
    ["empty stats tools", (c: PolicyContext) => c.stats.sumLast({ tools: [], windowMs: 1 })],
    ["float stats window", (c: PolicyContext) => c.stats.sumLast({ tools: [T], windowMs: 1.5 })],
    ["empty payment id", (c: PolicyContext) => c.razorpay.payment("")],
  ])("invalid query (%s) rejects with an engine-error fault", async (_n, call) => {
    const { ctx, state } = ctxFor({});
    await expect(call(ctx)).rejects.toThrow();
    expect(state.fault?.code).toBe("engine-error");
  });

  it("valid queries reach the port as frozen copies", async () => {
    const { ctx } = ctxFor({});
    await expect(ctx.stats.sumLast({ tools: [T], windowMs: 1 })).resolves.toEqual({
      amountPaise: 0,
      count: 0,
    });
    await expect(ctx.history.hasRecent({ tool: T, match: { a: 1 }, withinMs: 1 })).resolves.toBe(
      false,
    );
  });
});
