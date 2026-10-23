import { describe, expect, it } from "vitest";
import { compilePolicy } from "./compile.js";
import { definePolicy, rule } from "./dsl.js";
import type { PolicySpec, Rule } from "./types.js";

const T = "create_refund";

function compileErr(spec: PolicySpec): string {
  const r = compilePolicy(spec);
  if (r.ok) throw new Error("expected compile error");
  return r.error.code;
}

describe("rule builder", () => {
  it("builds a deny rule", () => {
    const r = rule("a").on(T).deny("no");
    expect(r).toEqual({
      kind: "rule",
      id: "a",
      tools: [T],
      action: { kind: "deny", message: "no" },
    });
    expect(Object.isFrozen(r)).toBe(true);
    expect("when" in r).toBe(false);
  });

  it("builds a require_approval rule", () => {
    const r = rule("a")
      .on([T, "create_payout"])
      .when(() => true)
      .requireApproval({ via: "dashboard", timeoutMin: 15, message: "check" });
    expect(r.tools).toEqual([T, "create_payout"]);
    expect(r.action).toEqual({
      kind: "require_approval",
      via: "dashboard",
      timeoutMin: 15,
      message: "check",
    });
    expect(typeof r.when).toBe("function");
  });

  it("builds transform and allow rules", () => {
    const fn = () => ({ amount: 1 });
    expect(rule("t").on(T).transform(fn).action).toEqual({ kind: "transform", fn });
    expect(rule("a").on(T).allow().action).toEqual({ kind: "allow" });
  });

  it("copies the tools array so later caller mutation has no effect", () => {
    const tools = [T];
    const r = rule("a").on(tools).allow();
    tools.push("other");
    expect(r.tools).toEqual([T]);
  });

  it("unfinished builders are not assignable to Rule (type level)", () => {
    // @ts-expect-error — no action chosen
    const a: Rule = rule("a").on(T);
    // @ts-expect-error — no action chosen after when()
    const b: Rule = rule("a")
      .on(T)
      .when(() => true);
    // @ts-expect-error — no tools chosen
    const c: Rule = rule("a");
    expect([a, b, c]).toHaveLength(3);
  });

  it("definePolicy freezes and keeps timeoutMs only when given", () => {
    const p = definePolicy({ rules: [rule("a").on(T).allow()], default: "deny" });
    expect(Object.isFrozen(p)).toBe(true);
    expect("timeoutMs" in p).toBe(false);
    expect(definePolicy({ rules: [], default: "allow", timeoutMs: 50 }).timeoutMs).toBe(50);
  });
});

describe("compilePolicy", () => {
  it("compiles a valid policy with default timeout 2000", () => {
    const r = compilePolicy(
      definePolicy({
        rules: [
          rule("a")
            .on(T)
            .when(() => true)
            .deny("x"),
          rule("b").on([T, T]).allow(),
        ],
        default: "deny",
      }),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.timeoutMs).toBe(2000);
    expect(r.value.default).toBe("deny");
    expect(r.value.rules.map((x) => [x.index, x.id])).toEqual([
      [0, "a"],
      [1, "b"],
    ]);
    expect([...(r.value.rules[1]?.tools ?? [])]).toEqual([T]);
  });

  it("accepts an empty rule list", () => {
    expect(compilePolicy({ rules: [], default: "allow" }).ok).toBe(true);
  });

  it("rejects duplicate rule ids", () => {
    expect(
      compileErr({ rules: [rule("a").on(T).allow(), rule("a").on(T).deny("x")], default: "deny" }),
    ).toBe("policy.duplicate_rule_id");
  });

  it.each(["", "A", "-a", ".a", "a b", "a/b", "x".repeat(65), "ünï"])(
    "rejects invalid rule id %j",
    (id) => {
      expect(compileErr({ rules: [rule(id).on(T).allow()], default: "deny" })).toBe(
        "policy.invalid_rule_id",
      );
    },
  );

  it("accepts a 64-char id", () => {
    expect(compilePolicy({ rules: [rule("a".repeat(64)).on(T).allow()], default: "deny" }).ok).toBe(
      true,
    );
  });

  it.each([
    "engine-error",
    "engine-x",
    "policy-default",
    "policy-y",
    "invalid-args",
    "invalid-amount",
  ])("rejects reserved rule id %s", (id) => {
    expect(compileErr({ rules: [rule(id).on(T).allow()], default: "deny" })).toBe(
      "policy.reserved_rule_id",
    );
  });

  it("rejects .on() with no tools", () => {
    expect(compileErr({ rules: [rule("a").on([]).allow()], default: "deny" })).toBe(
      "policy.missing_tools",
    );
  });

  it("rejects a rule without .on() (built by hand)", () => {
    const r = { kind: "rule", id: "a", action: { kind: "allow" } } as unknown as Rule;
    expect(compileErr({ rules: [r], default: "deny" })).toBe("policy.missing_tools");
  });

  it.each([[""], ["  "], [[T, ""]], [[42]], [" create_refund"], ["create_refund "], [[T, "\tx"]]])(
    "rejects empty/non-string/whitespace-padded tool %j",
    (tools) => {
      expect(
        compileErr({
          rules: [
            rule("a")
              .on(tools as string[])
              .allow(),
          ],
          default: "deny",
        }),
      ).toBe("policy.invalid_tool");
    },
  );

  it("compiled tool list is frozen; mutation attempts throw and have no effect", () => {
    const r = compilePolicy(
      definePolicy({ rules: [rule("a").on([T, T]).allow()], default: "deny" }),
    );
    if (!r.ok) throw new Error(r.error.message);
    const compiled = r.value.rules[0];
    if (compiled === undefined) throw new Error("missing rule");
    expect(Object.isFrozen(compiled.tools)).toBe(true);
    expect(compiled.tools).toEqual([T]);
    const mutable = compiled.tools as string[];
    expect(() => mutable.push("create_payout")).toThrow(TypeError);
    expect(() => {
      mutable[0] = "create_payout";
    }).toThrow(TypeError);
    expect(() => {
      (compiled as { tools: readonly string[] }).tools = ["create_payout"];
    }).toThrow(TypeError);
    expect(compiled.tools).toEqual([T]);
  });

  it("rejects an unfinished builder (no action) smuggled in via a cast", () => {
    const unfinished = rule("a").on(T) as unknown as Rule;
    expect(compileErr({ rules: [unfinished], default: "deny" })).toBe("policy.missing_action");
    const noAction = { kind: "rule", id: "b", tools: [T] } as unknown as Rule;
    expect(compileErr({ rules: [noAction], default: "deny" })).toBe("policy.missing_action");
  });

  it("rejects an unknown action kind", () => {
    const r = { kind: "rule", id: "a", tools: [T], action: { kind: "maybe" } } as unknown as Rule;
    expect(compileErr({ rules: [r], default: "deny" })).toBe("policy.invalid_action");
  });

  it("rejects a non-function predicate or transform", () => {
    const badWhen = { kind: "rule", id: "a", tools: [T], when: true, action: { kind: "allow" } };
    expect(compileErr({ rules: [badWhen as unknown as Rule], default: "deny" })).toBe(
      "policy.invalid_predicate",
    );
    const badFn = { kind: "rule", id: "a", tools: [T], action: { kind: "transform", fn: 1 } };
    expect(compileErr({ rules: [badFn as unknown as Rule], default: "deny" })).toBe(
      "policy.invalid_action",
    );
  });

  it("rejects empty deny / approval messages", () => {
    expect(compileErr({ rules: [rule("a").on(T).deny(" ")], default: "deny" })).toBe(
      "policy.invalid_action",
    );
    expect(
      compileErr({
        rules: [rule("a").on(T).requireApproval({ via: "telegram", timeoutMin: 5, message: "" })],
        default: "deny",
      }),
    ).toBe("policy.invalid_action");
  });

  it.each([0, -1, 1.5, 1441, Number.NaN])("rejects approval timeoutMin %s", (timeoutMin) => {
    expect(
      compileErr({
        rules: [rule("a").on(T).requireApproval({ via: "telegram", timeoutMin, message: "m" })],
        default: "deny",
      }),
    ).toBe("policy.invalid_action");
  });

  it.each([1, 1440])("accepts approval timeoutMin %s", (timeoutMin) => {
    const spec = {
      rules: [rule("a").on(T).requireApproval({ via: "telegram", timeoutMin, message: "m" })],
      default: "deny",
    } as const;
    expect(compilePolicy(spec).ok).toBe(true);
  });

  it("rejects an unknown approval channel", () => {
    const opts = { via: "email", timeoutMin: 5, message: "m" } as unknown as {
      via: "telegram";
      timeoutMin: number;
      message: string;
    };
    expect(compileErr({ rules: [rule("a").on(T).requireApproval(opts)], default: "deny" })).toBe(
      "policy.invalid_action",
    );
  });

  it.each([0, -5, 1.5, 10_001, Number.POSITIVE_INFINITY])("rejects timeoutMs %s", (timeoutMs) => {
    expect(compileErr({ rules: [], default: "deny", timeoutMs })).toBe("policy.invalid_timeout");
  });

  it.each([1, 10_000])("accepts timeoutMs %s", (timeoutMs) => {
    expect(compilePolicy({ rules: [], default: "deny", timeoutMs }).ok).toBe(true);
  });

  it.each(["block", undefined, null])("rejects default %j", (d) => {
    expect(compileErr({ rules: [], default: d } as unknown as PolicySpec)).toBe(
      "policy.invalid_default",
    );
  });

  it("rejects a non-object spec or non-array rules", () => {
    expect(compileErr(null as unknown as PolicySpec)).toBe("policy.invalid_spec");
    expect(compileErr({ rules: {}, default: "deny" } as unknown as PolicySpec)).toBe(
      "policy.invalid_spec",
    );
    expect(compileErr({ rules: [null], default: "deny" } as unknown as PolicySpec)).toBe(
      "policy.invalid_rule",
    );
  });

  it("never throws, even on a hostile spec", () => {
    const hostile = {
      default: "deny",
      get rules(): never {
        throw new Error("boom");
      },
    } as unknown as PolicySpec;
    expect(compileErr(hostile)).toBe("policy.compile_exception");
  });
});
