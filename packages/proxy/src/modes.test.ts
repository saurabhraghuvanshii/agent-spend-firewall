import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  compilePolicy,
  definePolicy,
  err,
  evaluate,
  rule,
  fakeDeps,
  type CompiledPolicy,
  type EvalResult,
  type PolicySpec,
  type Result,
} from "@asf/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openAuditStore, type AuditStore } from "./audit-store.js";
import {
  createModePreCheck,
  createModeStore,
  DEFAULT_MODE,
  describeMode,
  effectiveMode,
  isShadowableDecision,
  KILL_SWITCH_MESSAGE,
  KILL_SWITCH_RULE,
  MODE_UNREADABLE_MESSAGE,
  type ModeStore,
} from "./modes.js";
import type { CallContext } from "./server.js";

let dir: string;
const stores: AuditStore[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-modes-unit-"));
});
afterEach(() => {
  for (const s of stores.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

function openStore(name = "audit.db"): AuditStore {
  const s = unwrap(openAuditStore({ path: join(dir, name) }));
  stores.push(s);
  return s;
}

const CTX = {} as unknown as CallContext;

describe("createModeStore", () => {
  it("defaults to both off; set merges and reports who / when", () => {
    const m = createModeStore(openStore());
    expect(unwrap(m.read())).toEqual(DEFAULT_MODE);
    const r = unwrap(m.set({ killSwitch: true, actor: "cli:ops" }));
    expect(r.changed).toBe(true);
    expect(r.mode).toMatchObject({ killSwitch: true, shadow: false, actor: "cli:ops" });
    expect(r.mode.changedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    const s = unwrap(m.set({ shadow: true, actor: "cli:ops" }));
    expect(s.mode).toMatchObject({ killSwitch: true, shadow: true });
    expect(unwrap(m.set({ shadow: true, actor: "cli:ops" })).changed).toBe(false);
  });

  it("persists across a restart (new store on the same file)", () => {
    const a = openStore();
    unwrap(createModeStore(a).set({ killSwitch: true, shadow: true, actor: "cli:ops" }));
    a.close();
    expect(unwrap(createModeStore(openStore()).read())).toMatchObject({
      killSwitch: true,
      shadow: true,
      actor: "cli:ops",
    });
  });

  it("maps store errors and throws to err (never throws)", () => {
    const failing = createModeStore({
      readMode: () => err("audit.read_failed", "x"),
      changeMode: () => {
        throw new Error("boom");
      },
    });
    expect(failing.read()).toMatchObject({ ok: false, error: { code: "mode.unreadable" } });
    expect(failing.set({ killSwitch: true, actor: "cli:ops" })).toMatchObject({
      ok: false,
      error: { code: "mode.write_failed" },
    });
    const throwing = createModeStore({
      readMode: () => {
        throw new Error("boom");
      },
      changeMode: () => err("audit.invalid_input", "bad"),
    });
    expect(throwing.read().ok).toBe(false);
    expect(throwing.set({ killSwitch: true, actor: "bad" })).toMatchObject({
      ok: false,
      error: { code: "audit.invalid_input" },
    });
  });
});

describe("effectiveMode / createModePreCheck", () => {
  it("unreadable ⇒ kill switch ON, shadow off", () => {
    expect(effectiveMode(err("mode.unreadable", "x"))).toEqual({
      killSwitch: true,
      shadow: false,
      readable: false,
    });
  });

  const fixed = (r: Result<typeof DEFAULT_MODE>): Pick<ModeStore, "read"> => ({ read: () => r });

  it("kill on ⇒ deny kill-switch (even with shadow on)", () => {
    for (const shadow of [false, true]) {
      const pre = createModePreCheck(fixed({ ok: true, value: { killSwitch: true, shadow } }));
      expect(pre(CTX)).toEqual({ ruleId: KILL_SWITCH_RULE, message: KILL_SWITCH_MESSAGE });
    }
  });

  it("shadow on ⇒ shadow verdict; both off ⇒ nothing", () => {
    expect(
      createModePreCheck(fixed({ ok: true, value: { killSwitch: false, shadow: true } }))(CTX),
    ).toEqual({
      shadow: true,
    });
    expect(createModePreCheck(fixed({ ok: true, value: DEFAULT_MODE }))(CTX)).toBeUndefined();
  });

  it("unreadable or throwing reader ⇒ deny kill-switch + a log line", () => {
    const logs: string[] = [];
    const pre = createModePreCheck(fixed(err("mode.unreadable", "db gone")), (l) => logs.push(l));
    expect(pre(CTX)).toEqual({ ruleId: KILL_SWITCH_RULE, message: MODE_UNREADABLE_MESSAGE });
    const throwing = createModePreCheck(
      {
        read: () => {
          throw new Error("boom");
        },
      },
      (l) => logs.push(l),
    );
    expect(throwing(CTX)).toEqual({ ruleId: KILL_SWITCH_RULE, message: MODE_UNREADABLE_MESSAGE });
    expect(logs).toHaveLength(2);
    expect(logs.every((l) => l.includes("kill switch treated as ON"))).toBe(true);
  });

  it("reads the mode on every call", () => {
    const m = createModeStore(openStore());
    const pre = createModePreCheck(m);
    expect(pre(CTX)).toBeUndefined();
    unwrap(m.set({ killSwitch: true, actor: "cli:ops" }));
    expect(pre(CTX)).toMatchObject({ ruleId: KILL_SWITCH_RULE });
    unwrap(m.set({ killSwitch: false, shadow: true, actor: "cli:ops" }));
    expect(pre(CTX)).toEqual({ shadow: true });
  });
});

describe("isShadowableDecision", () => {
  function compiled(spec: PolicySpec): CompiledPolicy {
    const c = compilePolicy(spec);
    if (!c.ok) throw new Error(c.error.code);
    return c.value;
  }
  const policy = compiled(
    definePolicy({
      default: "deny",
      rules: [
        rule("r.crash")
          .on("t_crash")
          .when(() => {
            throw new Error("bug");
          })
          .deny("never"),
        rule("r.deny").on("t_deny").deny("no"),
        rule("r.approve")
          .on("t_approve")
          .requireApproval({ via: "telegram", timeoutMin: 5, message: "ask" }),
        rule("r.transform")
          .on("t_transform")
          .transform(() => ({ amount: 1 })),
        rule("r.allow").on(["t_allow", "t_transform"]).allow(),
      ],
    }),
  );
  const run = (tool: string, args: Record<string, unknown> = { amount: 5 }): Promise<EvalResult> =>
    evaluate(policy, { tool, args, reason: "a reason here", sessionId: "s" }, fakeDeps());

  it.each([
    ["policy deny rule", "t_deny", true],
    ["policy default deny", "t_unknown", true],
    ["require_approval", "t_approve", true],
    ["transform", "t_transform", true],
    ["allow", "t_allow", true],
    ["a rule that threw (engine-error)", "t_crash", false],
  ])("%s ⇒ %s", async (_label, tool, expected) => {
    expect(isShadowableDecision(policy, await run(tool))).toBe(expected);
  });

  it("engine-produced denies are never shadowable", async () => {
    const bad = await run("t_allow", { amount: 1.5 });
    expect(bad.decision.type).toBe("deny");
    expect(isShadowableDecision(policy, bad)).toBe(false);
    for (const ruleId of [
      "engine-error",
      "engine-timeout",
      "engine-invalid-patch",
      "invalid-args",
    ]) {
      const forged: EvalResult = {
        decision: { type: "deny", ruleId, message: "x", matchedRules: [] },
        finalArgs: {},
        trace: [],
      };
      expect(isShadowableDecision(policy, forged)).toBe(false);
    }
  });
});

describe("describeMode", () => {
  it("states both switches, who and when; kill wins note", () => {
    expect(describeMode(DEFAULT_MODE)).toBe(
      "kill switch off; shadow mode off; never changed (defaults)",
    );
    expect(
      describeMode({
        killSwitch: true,
        shadow: true,
        actor: "cli:ops",
        changedAt: "2026-10-29T10:00:00.000Z",
      }),
    ).toBe(
      "kill switch ON; shadow mode ON; (kill switch wins: every money call is denied); last changed 2026-10-29T10:00:00.000Z by cli:ops",
    );
  });
});
