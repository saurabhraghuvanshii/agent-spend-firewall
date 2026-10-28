/**
 * T012 — kill switch and shadow mode through the full money pipeline (agent ⇄ proxy ⇄ fake upstream), with the real
 * mode store over the audit log and a second store connection standing in for the CLI.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compilePolicy,
  definePolicy,
  err,
  rule,
  type CompiledPolicy,
  type PolicySpec,
  type Result,
} from "@asf/core";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createInMemoryApprovalStub, type InMemoryApprovalStub } from "./approval-port.js";
import {
  openAuditStore,
  type AuditAttemptRecord,
  type AuditOutcomeRecord,
  type AuditStore,
} from "./audit-store.js";
import { systemClock, systemTimer } from "./context-adapters.js";
import {
  createFirewallInterceptor,
  createMoneyPipeline,
  type MoneyPipeline,
  type MoneyPipelineOptions,
  type PipelineStore,
} from "./interceptor.js";
import {
  createModePreCheck,
  createModeStore,
  KILL_SWITCH_MESSAGE,
  KILL_SWITCH_RULE,
  MODE_UNREADABLE_MESSAGE,
  type ModeStore,
} from "./modes.js";
import { redactSensitiveResult } from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { createProxyServer, type ProxyServer } from "./server.js";
import { fakeUpstream, jsonOf, type FakeUpstream } from "./test-support/fake-upstream.js";
import { Upstream } from "./upstream.js";

const REASON = "Customer cust_123 was double charged for order_456; refunding it.";
const here = dirname(fileURLToPath(import.meta.url));
const TOOLS = (
  JSON.parse(readFileSync(resolve(here, "../../../docs/razorpay-tools.json"), "utf8")) as {
    tools: Tool[];
  }
).tools;

function compiled(spec: PolicySpec): CompiledPolicy {
  const c = compilePolicy(spec);
  if (!c.ok) throw new Error(`policy: ${c.error.code}`);
  return c.value;
}

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

/** Small refunds allowed, mid ones need approval, big ones denied, payment links transformed. */
const POLICY = compiled(
  definePolicy({
    default: "deny",
    rules: [
      rule("refund.too_big")
        .on("create_refund")
        .when((ctx) => ctx.amountPaise() > 400_000)
        .deny("refund too big"),
      rule("refund.approval")
        .on("create_refund")
        .when((ctx) => ctx.amountPaise() > 200_000)
        .requireApproval({ via: "telegram", timeoutMin: 30, message: "needs approval" }),
      rule("refund.halve")
        .on("create_refund")
        .transform((ctx) => (ctx.amountPaise() === 150_000 ? { amount: 75_000 } : {})),
      rule("refund.allow").on("create_refund").allow(),
      rule("refund.crash")
        .on("capture_payment")
        .when(() => {
          throw new Error("rule bug");
        })
        .deny("never"),
    ],
  }),
);

/** Denies a refund once ANY refund was counted in the last hour (velocity of 1). */
const VELOCITY_ONE = compiled(
  definePolicy({
    default: "deny",
    rules: [
      rule("refund.velocity")
        .on("create_refund")
        .when(async (ctx) => {
          const s = await ctx.stats.sumLast({ tools: ["create_refund"], windowMs: 3_600_000 });
          return s.count >= 1;
        })
        .deny("velocity"),
      rule("refund.allow").on("create_refund").allow(),
    ],
  }),
);

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  store: AuditStore;
  /** A second connection to the same audit DB: the operator's CLI. */
  cli: ModeStore;
  cliStore: AuditStore;
  pipeline: MoneyPipeline;
  approvals: InMemoryApprovalStub;
  logs: string[];
}

let dir: string;
const open: Harness[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-modes-"));
});

afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.agent.close();
    await h.proxy.close();
    h.pipeline.close();
    await h.upstream.close();
    expect(unwrap(h.store.verify()).ok).toBe(true);
    h.store.close();
    h.cliStore.close();
  }
  rmSync(dir, { recursive: true, force: true });
});

interface SetupOpts {
  policy?: CompiledPolicy;
  dbName?: string;
  /** Wrap the mode store the pipeline reads (failure injection). */
  wrapModes?: (m: ModeStore) => ModeStore;
  wrapStore?: (s: AuditStore) => PipelineStore;
  startDegraded?: MoneyPipelineOptions["startDegraded"];
}

async function setup(opts: SetupOpts = {}): Promise<Harness> {
  const fake = fakeUpstream({
    tools: TOOLS,
    handler: (name, args) => {
      const a = args ?? {};
      if (name === "fetch_payment") {
        const id = a["payment_id"];
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                id,
                status: "captured",
                amount: 500_000,
                amount_refunded: 0,
                currency: id === "pay_USD1" ? "USD" : "INR",
              }),
            },
          ],
        });
      }
      if (name === "create_refund") {
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                id: "rfnd_M1abcdefgh",
                entity: "refund",
                amount: a["amount"],
              }),
            },
          ],
        });
      }
      return Promise.resolve({
        content: [{ type: "text", text: JSON.stringify({ id: `obj_${name}` }) }],
      });
    },
  });
  const logs: string[] = [];
  const upstream = new Upstream({
    factory: fake.factory,
    logger: (l) => logs.push(l),
    sleep: () => Promise.resolve(),
  });
  const path = join(dir, opts.dbName ?? `audit-${String(open.length)}.db`);
  const store = unwrap(openAuditStore({ path }));
  const cliStore = unwrap(openAuditStore({ path }));
  const modes = createModeStore(store);
  const approvals = createInMemoryApprovalStub();
  const pipeline = createMoneyPipeline({
    policy: opts.policy ?? POLICY,
    store: opts.wrapStore === undefined ? store : opts.wrapStore(store),
    upstream,
    approvals,
    clock: systemClock,
    timer: systemTimer,
    logger: (l) => logs.push(l),
    preCheck: createModePreCheck(
      opts.wrapModes === undefined ? modes : opts.wrapModes(modes),
      (l) => logs.push(l),
    ),
    ...(opts.startDegraded === undefined ? {} : { startDegraded: opts.startDegraded }),
  });
  const proxy = createProxyServer({
    upstream,
    interceptor: createFirewallInterceptor(pipeline, { logger: (l) => logs.push(l) }),
    advertise: advertiseTool,
    resultFilter: redactSensitiveResult,
    logger: (l) => logs.push(l),
    sessionId: "sess-modes",
  });
  await upstream.connect();
  const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);
  const agent = new Client({ name: "agent", version: "0" }, { capabilities: {} });
  await agent.connect(agentSide);
  const h: Harness = {
    agent,
    fake,
    upstream,
    proxy,
    store,
    cli: createModeStore(cliStore),
    cliStore,
    pipeline,
    approvals,
    logs,
  };
  open.push(h);
  return h;
}

function call(h: Harness, name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  return h.agent.request(
    { method: "tools/call", params: { name, arguments: args } },
    CallToolResultSchema,
  );
}
const refund = (h: Harness, args: Record<string, unknown>): Promise<CallToolResult> =>
  call(h, "create_refund", { reason: REASON, ...args });
const sent = (h: Harness, name: string) => h.fake.calls.filter((c) => c.name === name);

function rows(h: Harness): { attempts: AuditAttemptRecord[]; outcomes: AuditOutcomeRecord[] } {
  const attempts: AuditAttemptRecord[] = [];
  const outcomes: AuditOutcomeRecord[] = [];
  for (const r of unwrap(h.store.readAll())) {
    if ("invalid" in r) throw new Error("invalid row");
    if (r.kind === "attempt") attempts.push(r);
    else if (r.kind === "outcome") outcomes.push(r);
  }
  return { attempts, outcomes };
}
const outcomeOf = (h: Harness, id: string | undefined) =>
  rows(h).outcomes.find((o) => o.attemptId === id);

function expectKillDeny(r: CallToolResult, message = KILL_SWITCH_MESSAGE): void {
  expect(r.isError).toBe(true);
  expect(jsonOf(r)).toEqual({ decision: "deny", ruleId: KILL_SWITCH_RULE, message });
}

const set = (h: Harness, change: { killSwitch?: boolean; shadow?: boolean }): void => {
  unwrap(h.cli.set({ ...change, actor: "cli:ops" }));
};

// ---------------------------------------------------------------------------------------------------------------

describe("kill switch", () => {
  it("ON ⇒ every money call denied kill-switch (audited, nothing sent, no lookup); read tools still work", async () => {
    const h = await setup();
    set(h, { killSwitch: true });
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }));
    expectKillDeny(
      await call(h, "capture_payment", {
        reason: REASON,
        payment_id: "pay_A1",
        amount: 1_000,
        currency: "INR",
      }),
    );
    expect(sent(h, "create_refund")).toEqual([]);
    expect(sent(h, "capture_payment")).toEqual([]);
    expect(sent(h, "fetch_payment")).toEqual([]);
    const { attempts } = rows(h);
    expect(attempts).toHaveLength(2);
    for (const a of attempts) {
      expect(a).toMatchObject({
        decision: "deny",
        matchedRules: [KILL_SWITCH_RULE],
        reason: REASON,
      });
      expect(outcomeOf(h, a.id)?.outcome).toBe("denied");
    }
    // Read tool passes straight through.
    const read = await call(h, "fetch_payment", { payment_id: "pay_A1" });
    expect(read.isError).not.toBe(true);
    expect(sent(h, "fetch_payment")).toHaveLength(1);
    expect(rows(h).attempts).toHaveLength(2);
  });

  it("is read per call: toggled from another connection (CLI) while running", async () => {
    const h = await setup();
    expect((await refund(h, { payment_id: "pay_A1", amount: 1_000 })).isError).not.toBe(true);
    set(h, { killSwitch: true });
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 2_000 }));
    set(h, { killSwitch: false });
    expect((await refund(h, { payment_id: "pay_A1", amount: 3_000 })).isError).not.toBe(true);
    expect(sent(h, "create_refund").map((c) => c.args?.["amount"])).toEqual([1_000, 3_000]);
  });

  it("wins over shadow mode", async () => {
    const h = await setup();
    set(h, { killSwitch: true, shadow: true });
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 900_000 }));
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }));
    expect(sent(h, "create_refund")).toEqual([]);
    expect(rows(h).attempts.every((a) => a.shadow === undefined)).toBe(true);
  });

  it("wins over the degraded latch (checked first)", async () => {
    const h = await setup({ startDegraded: { reason: "test", message: "audit broken" } });
    set(h, { killSwitch: true });
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }));
  });

  it("persists across a restart", async () => {
    const h1 = await setup({ dbName: "shared.db" });
    set(h1, { killSwitch: true });
    const h2 = await setup({ dbName: "shared.db" });
    expectKillDeny(await refund(h2, { payment_id: "pay_A1", amount: 1_000 }));
    expect(sent(h2, "create_refund")).toEqual([]);
  });

  it("turned ON while a call is in the pipeline ⇒ checked again before the send: not_forwarded kill-switch", async () => {
    const ref: { h?: Harness } = {};
    const h = await setup({
      wrapStore: (s) => ({
        recordAttempt: (i) => {
          const r = s.recordAttempt(i);
          if (i.decision === "allow" && ref.h !== undefined) set(ref.h, { killSwitch: true });
          return r;
        },
        recordOutcome: (i) => s.recordOutcome(i),
        recordVerification: (i) => s.recordVerification(i),
        readUnsettled: () => s.readUnsettled(),
        readActivitySince: (ms) => s.readActivitySince(ms),
        recordApproval: (i) => s.recordApproval(i),
        readAttempt: (id) => s.readAttempt(id),
      }),
    });
    ref.h = h;
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }));
    expect(sent(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a?.decision).toBe("allow");
    expect(outcomeOf(h, a?.id)).toMatchObject({
      outcome: "not_forwarded",
      errorCode: KILL_SWITCH_RULE,
    });
  });
});

describe("mode unreadable ⇒ kill switch treated as ON (fail closed)", () => {
  it.each([
    ["the store returns an error", (): Result<never> => err("mode.unreadable", "db gone")],
    [
      "the store throws",
      (): Result<never> => {
        throw new Error("boom");
      },
    ],
  ])("%s", async (_label, read) => {
    const h = await setup({ wrapModes: (m) => ({ read, set: (c) => m.set(c) }) });
    expectKillDeny(
      await refund(h, { payment_id: "pay_A1", amount: 1_000 }),
      MODE_UNREADABLE_MESSAGE,
    );
    expect(sent(h, "create_refund")).toEqual([]);
    expect(h.logs.join("\n")).toContain("kill switch treated as ON");
    expect(h.logs.join("\n")).not.toContain("boom");
    // Reads still work.
    expect((await call(h, "fetch_payment", { payment_id: "pay_A1" })).isError).not.toBe(true);
  });
});

describe("shadow mode", () => {
  it("a policy deny is forwarded with the original args and audited as wouldDecision deny", async () => {
    const h = await setup();
    set(h, { shadow: true });
    const r = await refund(h, { payment_id: "pay_A1", amount: 450_000 });
    expect(r.isError).not.toBe(true);
    expect(jsonOf(r)).toMatchObject({ entity: "refund", amount: 450_000 });
    const [c] = sent(h, "create_refund");
    expect(c?.args).toMatchObject({ payment_id: "pay_A1", amount: 450_000 });
    expect(c?.args).not.toHaveProperty("reason");
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({
      decision: "allow",
      shadow: true,
      wouldDecision: "deny",
      matchedRules: expect.arrayContaining(["refund.too_big"]) as string[],
      argsRedacted: expect.objectContaining({ amount: 450_000 }) as object,
    });
    expect(a).not.toHaveProperty("originalArgsRedacted");
    expect(outcomeOf(h, a?.id)?.outcome).toBe("success");
    expect(h.logs.join("\n")).toContain("shadow mode: create_refund would deny (refund.too_big)");
  });

  it("require_approval is forwarded without an approval request (wouldDecision require_approval)", async () => {
    const h = await setup();
    set(h, { shadow: true });
    const r = await refund(h, { payment_id: "pay_A1", amount: 300_000 });
    expect(r.isError).not.toBe(true);
    expect(jsonOf(r)).not.toHaveProperty("approvalId");
    expect(h.approvals.requests).toEqual([]);
    expect(rows(h).attempts[0]).toMatchObject({
      decision: "allow",
      shadow: true,
      wouldDecision: "require_approval",
    });
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("a transform is NOT applied: the original args are forwarded (wouldDecision transform)", async () => {
    const h = await setup();
    set(h, { shadow: true });
    await refund(h, { payment_id: "pay_A1", amount: 150_000 });
    expect(sent(h, "create_refund")[0]?.args?.["amount"]).toBe(150_000);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "allow", shadow: true, wouldDecision: "transform" });
    expect(a?.argsRedacted).toMatchObject({ amount: 150_000 });
    expect(a).not.toHaveProperty("originalArgsRedacted");
  });

  it("an allow is recorded as wouldDecision allow; the policy default deny as wouldDecision deny", async () => {
    const h = await setup();
    set(h, { shadow: true });
    await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    await call(h, "create_payment_link", {
      reason: REASON,
      amount: 1_000,
      currency: "INR",
      description: "x",
    });
    const [a1, a2] = rows(h).attempts;
    expect(a1).toMatchObject({ shadow: true, wouldDecision: "allow" });
    expect(a2).toMatchObject({
      tool: "create_payment_link",
      shadow: true,
      wouldDecision: "deny",
      matchedRules: ["policy-default"],
    });
    expect(sent(h, "create_payment_link")).toHaveLength(1);
  });

  it("an engine error is still a REAL deny (never shadowed)", async () => {
    const h = await setup();
    set(h, { shadow: true });
    const r = await call(h, "capture_payment", {
      reason: REASON,
      payment_id: "pay_A1",
      amount: 1_000,
      currency: "INR",
    });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "engine-error" });
    expect(sent(h, "capture_payment")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "deny" });
    expect(a).not.toHaveProperty("shadow");
    expect(outcomeOf(h, a?.id)?.outcome).toBe("denied");
  });

  it("still blocks duplicates (firewall invariant)", async () => {
    const h = await setup();
    set(h, { shadow: true });
    await refund(h, { payment_id: "pay_A1", amount: 450_000 });
    const dup = await refund(h, { payment_id: "pay_A1", amount: 450_000 });
    expect(jsonOf(dup)).toMatchObject({ decision: "deny", ruleId: "firewall.duplicate" });
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it.each([
    ["a float amount", { payment_id: "pay_A1", amount: 10.5, reason: REASON }],
    ["a string amount", { payment_id: "pay_A1", amount: "1000", reason: REASON }],
    ["no reason", { payment_id: "pay_A1", amount: 1_000 }],
    ["a short reason", { payment_id: "pay_A1", amount: 1_000, reason: "x" }],
  ])("still denies invalid args: %s", async (_label, args) => {
    const h = await setup();
    set(h, { shadow: true });
    const r = await call(h, "create_refund", args);
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ decision: "deny" });
    expect(sent(h, "create_refund")).toEqual([]);
    expect(rows(h).attempts.every((a) => a.decision === "deny" && a.shadow === undefined)).toBe(
      true,
    );
  });

  it("still enforces the INR invariant on the payment acted on", async () => {
    const h = await setup();
    set(h, { shadow: true });
    const r = await refund(h, { payment_id: "pay_USD1", amount: 1_000 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.currency_not_inr" });
    expect(sent(h, "create_refund")).toEqual([]);
  });

  it("shadowed actions count toward velocity as executed", async () => {
    const h = await setup({ policy: VELOCITY_ONE });
    set(h, { shadow: true });
    await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    await refund(h, { payment_id: "pay_A1", amount: 2_000 });
    expect(rows(h).attempts.map((a) => a.wouldDecision)).toEqual(["allow", "deny"]);
    set(h, { shadow: false });
    const r = await refund(h, { payment_id: "pay_A1", amount: 3_000 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "refund.velocity" });
    expect(sent(h, "create_refund")).toHaveLength(2);
  });

  it("off again ⇒ the policy is enforced", async () => {
    const h = await setup();
    set(h, { shadow: true });
    set(h, { shadow: false });
    const r = await refund(h, { payment_id: "pay_A1", amount: 450_000 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "refund.too_big" });
    expect(sent(h, "create_refund")).toEqual([]);
  });
});

describe("shadow mode turned OFF mid-call (M1)", () => {
  /** Pass-through store that runs `hook` after an attempt is recorded / before the activity read. */
  const hooked =
    (
      ref: { h?: Harness },
      on: { afterAttempt?: (h: Harness) => void; beforeRead?: (h: Harness) => void },
    ) =>
    (s: AuditStore): PipelineStore => ({
      recordAttempt: (i) => {
        const r = s.recordAttempt(i);
        if (r.ok && ref.h !== undefined) on.afterAttempt?.(ref.h);
        return r;
      },
      recordOutcome: (i) => s.recordOutcome(i),
      recordVerification: (i) => s.recordVerification(i),
      readUnsettled: () => s.readUnsettled(),
      readActivitySince: (ms) => {
        if (ref.h !== undefined) on.beforeRead?.(ref.h);
        return s.readActivitySince(ms);
      },
      recordApproval: (i) => s.recordApproval(i),
      readAttempt: (id) => s.readAttempt(id),
    });

  it("would-deny call: shadow turned off after the attempt ⇒ not sent, not_forwarded firewall.shadow_ended", async () => {
    const ref: { h?: Harness } = {};
    const h = await setup({
      wrapStore: hooked(ref, { afterAttempt: (x) => set(x, { shadow: false }) }),
    });
    ref.h = h;
    set(h, { shadow: true });
    const r = await refund(h, { payment_id: "pay_A1", amount: 450_000 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.shadow_ended" });
    expect(sent(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ shadow: true, wouldDecision: "deny" });
    expect(outcomeOf(h, a?.id)).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "firewall.shadow_ended",
    });
  });

  it("would-allow call: shadow turned off after the attempt ⇒ still sent (the policy allows it)", async () => {
    const ref: { h?: Harness } = {};
    const h = await setup({
      wrapStore: hooked(ref, { afterAttempt: (x) => set(x, { shadow: false }) }),
    });
    ref.h = h;
    set(h, { shadow: true });
    const r = await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    expect(r.isError).not.toBe(true);
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("shadow turned off between the mode read and the attempt write ⇒ audited deny firewall.shadow_ended", async () => {
    const ref: { h?: Harness } = {};
    const h = await setup({
      wrapStore: hooked(ref, { beforeRead: (x) => set(x, { shadow: false }) }),
    });
    ref.h = h;
    set(h, { shadow: true });
    const r = await refund(h, { payment_id: "pay_A1", amount: 450_000 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.shadow_ended" });
    expect(sent(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "deny", matchedRules: ["firewall.shadow_ended"] });
    expect(a).not.toHaveProperty("shadow");
  });

  it("kill switch still wins over shadow_ended", async () => {
    const ref: { h?: Harness } = {};
    const h = await setup({
      wrapStore: hooked(ref, { afterAttempt: (x) => set(x, { shadow: false, killSwitch: true }) }),
    });
    ref.h = h;
    set(h, { shadow: true });
    expectKillDeny(await refund(h, { payment_id: "pay_A1", amount: 450_000 }));
  });
});
