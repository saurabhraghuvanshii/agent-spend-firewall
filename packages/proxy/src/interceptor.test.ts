import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  compilePolicy,
  definePolicy,
  err,
  rule,
  UNTRUSTED_REASON_LABEL,
  type CompiledPolicy,
  type PolicySpec,
  type Result,
} from "@asf/core";
import defaultPolicy, { VELOCITY_MAX_COUNT } from "@asf/policies";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  checkFinalArgs,
  denyRuleOf,
  outcomeFor,
  upstreamRefOf,
  resourceLockKeys,
  retargetsIds,
  type MoneyPipeline,
  type MoneyPipelineOptions,
  type PipelineStore,
} from "./interceptor.js";
import { nodeHasher } from "./node-hasher.js";
import { redactSensitiveResult } from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { classifyTool } from "./tool-classes.js";
import { createProxyServer, denyResult, type ForwardReport, type ProxyServer } from "./server.js";
import { fakeUpstream, hang, jsonOf, type FakeUpstream } from "./test-support/fake-upstream.js";
import { redactSecrets } from "./tool-discovery.js";
import { Upstream, type Redactor } from "./upstream.js";

// ---------------------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------------------

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const redact: Redactor = (s) => redactSecrets(s, KEYS);
const REASON = "Customer cust_123 was double charged for order_456; refunding it.";

const here = dirname(fileURLToPath(import.meta.url));
const DOC_TOOLS = (
  JSON.parse(readFileSync(resolve(here, "../../../docs/razorpay-tools.json"), "utf8")) as {
    tools: Tool[];
  }
).tools;
const UNKNOWN_TOOL: Tool = {
  name: "brand_new_tool",
  description: "A tool upstream added that the firewall has never classified",
  inputSchema: {
    type: "object",
    properties: { payment_id: { type: "string" }, amount: { type: "number" } },
  },
};
const TOOLS: Tool[] = [...DOC_TOOLS, UNKNOWN_TOOL];

interface Payment {
  status: string;
  amount: number;
  amount_refunded: number;
  currency: string;
}

function compiled(spec: PolicySpec): CompiledPolicy {
  const c = compilePolicy(spec);
  if (!c.ok) throw new Error(`policy: ${c.error.code}`);
  return c.value;
}

const DEFAULT = compiled(defaultPolicy);
/** Allows every refund unconditionally (cannot be loaded by the CLI loader only because it lacks currency rules). */
const ALLOW_REFUNDS = compiled(
  definePolicy({ default: "deny", rules: [rule("all.allow").on("create_refund").allow()] }),
);

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

// ---------------------------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------------------------

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  store: AuditStore;
  pipeline: MoneyPipeline;
  approvals: InMemoryApprovalStub;
  logs: string[];
  payments: Map<string, Payment>;
  orders: Map<string, { amount: number; currency: string }>;
  /** Per-tool upstream handler overrides (checked first). */
  handlers: Map<
    string,
    (args: Record<string, unknown>, signal: AbortSignal) => Promise<CallToolResult>
  >;
  /** create_refund handler override. */
  refundHandler: {
    fn?: (args: Record<string, unknown>, signal: AbortSignal) => Promise<CallToolResult>;
  };
}

let dir: string;
const open: Harness[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-pipeline-"));
});

afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.agent.close();
    await h.proxy.close();
    await h.upstream.close();
    // Every scenario must leave a valid chain.
    const v = unwrap(h.store.verify());
    expect(v.ok).toBe(true);
    h.store.close();
  }
  rmSync(dir, { recursive: true, force: true });
});

interface SetupOpts {
  policy?: CompiledPolicy;
  preCheck?: MoneyPipelineOptions["preCheck"];
  lockWaitMs?: number;
  callTimeoutMs?: number;
  wrapStore?: (s: AuditStore) => PipelineStore;
  startDegraded?: MoneyPipelineOptions["startDegraded"];
}

let refundSeq = 0;

async function setup(opts: SetupOpts = {}): Promise<Harness> {
  const payments = new Map<string, Payment>([
    ["pay_A1", { status: "captured", amount: 500_000, amount_refunded: 0, currency: "INR" }],
    ["pay_B2", { status: "captured", amount: 500_000, amount_refunded: 0, currency: "INR" }],
    ["pay_USD1", { status: "captured", amount: 500_000, amount_refunded: 0, currency: "USD" }],
  ]);
  const orders: Harness["orders"] = new Map([
    ["order_A1", { amount: 500_000, currency: "INR" }],
    ["order_USD1", { amount: 500_000, currency: "USD" }],
  ]);
  const refundHandler: Harness["refundHandler"] = {};
  const handlers: Harness["handlers"] = new Map();
  const fake = fakeUpstream({
    tools: TOOLS,
    handler: (name, args, signal) => {
      const a = args ?? {};
      const override = handlers.get(name);
      if (override !== undefined) return override(a, signal);
      if (name === "fetch_payment") {
        const id = a["payment_id"];
        const p = typeof id === "string" ? payments.get(id) : undefined;
        if (p === undefined) {
          return Promise.resolve({
            isError: true,
            content: [{ type: "text", text: "payment not found" }],
          });
        }
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({ id, ...p, email: "buyer@example.com", vpa: "buyer@okhdfc" }),
            },
          ],
        });
      }
      if (name === "fetch_order") {
        const id = a["order_id"];
        const o = typeof id === "string" ? orders.get(id) : undefined;
        if (o === undefined) {
          return Promise.resolve({
            isError: true,
            content: [{ type: "text", text: "order not found" }],
          });
        }
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({ id, entity: "order", status: "created", ...o }),
            },
          ],
        });
      }
      if (name === "create_refund" && refundHandler.fn !== undefined) {
        return refundHandler.fn(a, signal);
      }
      if (name === "create_refund") {
        refundSeq++;
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({ id: `rfnd_T${String(refundSeq)}`, entity: "refund", ...a }),
            },
          ],
        });
      }
      return Promise.resolve({
        content: [{ type: "text", text: JSON.stringify({ id: `obj_${name}`, args: a }) }],
      });
    },
  });
  const logs: string[] = [];
  const upstream = new Upstream({
    factory: fake.factory,
    logger: (l) => logs.push(l),
    redact,
    sleep: () => Promise.resolve(),
  });
  const store = unwrap(openAuditStore({ path: join(dir, `audit-${String(open.length)}.db`) }));
  const approvals = createInMemoryApprovalStub();
  const pipeline = createMoneyPipeline({
    policy: opts.policy ?? DEFAULT,
    store: opts.wrapStore === undefined ? store : opts.wrapStore(store),
    upstream,
    approvals,
    clock: systemClock,
    timer: systemTimer,
    redact,
    logger: (l) => logs.push(l),
    ...(opts.lockWaitMs === undefined ? {} : { lockWaitMs: opts.lockWaitMs }),
    ...(opts.preCheck === undefined ? {} : { preCheck: opts.preCheck }),
    ...(opts.startDegraded === undefined ? {} : { startDegraded: opts.startDegraded }),
  });
  const proxy = createProxyServer({
    upstream,
    interceptor: createFirewallInterceptor(pipeline, { logger: (l) => logs.push(l) }),
    advertise: advertiseTool,
    resultFilter: redactSensitiveResult,
    logger: (l) => logs.push(l),
    redact,
    sessionId: "sess-test",
    ...(opts.callTimeoutMs === undefined ? {} : { callTimeoutMs: opts.callTimeoutMs }),
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
    pipeline,
    approvals,
    logs,
    payments,
    orders,
    handlers,
    refundHandler,
  };
  open.push(h);
  return h;
}

function call(
  h: Harness,
  name: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<CallToolResult> {
  return h.agent.request(
    { method: "tools/call", params: { name, arguments: args } },
    CallToolResultSchema,
    signal === undefined ? undefined : { signal },
  );
}

const refund = (
  h: Harness,
  args: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<CallToolResult> => call(h, "create_refund", { reason: REASON, ...args }, signal);

function rows(h: Harness): { attempts: AuditAttemptRecord[]; outcomes: AuditOutcomeRecord[] } {
  const all = unwrap(h.store.readAll());
  const attempts: AuditAttemptRecord[] = [];
  const outcomes: AuditOutcomeRecord[] = [];
  for (const r of all) {
    if ("invalid" in r) throw new Error("invalid row");
    if (r.kind === "attempt") attempts.push(r);
    else outcomes.push(r);
  }
  return { attempts, outcomes };
}

function outcomeOf(h: Harness, attemptId: string): AuditOutcomeRecord | undefined {
  return rows(h).outcomes.find((o) => o.attemptId === attemptId);
}

const upstreamCalls = (h: Harness, name: string) => h.fake.calls.filter((c) => c.name === name);

function expectDeny(r: CallToolResult, ruleId: string): void {
  expect(r.isError).toBe(true);
  const body = jsonOf(r);
  expect(body).toEqual({ decision: "deny", ruleId, message: expect.any(String) as string });
  expect(JSON.stringify(r)).not.toContain("double charged");
}

// ---------------------------------------------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------------------------------------------

describe("allow", () => {
  it("forwards exactly finalArgs (no reason); attempt before, success outcome with upstreamRef after", async () => {
    const h = await setup();
    const r = await refund(h, { payment_id: "pay_A1", amount: 5_000 });
    expect(r.isError).not.toBe(true);
    expect(jsonOf(r)).toMatchObject({ id: "rfnd_T" + String(refundSeq), entity: "refund" });
    expect(upstreamCalls(h, "create_refund").map((c) => c.args)).toEqual([
      { payment_id: "pay_A1", amount: 5_000 },
    ]);
    const { attempts, outcomes } = rows(h);
    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({
      tool: "create_refund",
      decision: "allow",
      argsRedacted: { payment_id: "pay_A1", amount: 5_000 },
      reason: REASON,
      sessionId: "sess-test",
      matchedRules: ["refund.allow"],
    });
    expect(attempts[0]).not.toHaveProperty("originalArgsRedacted");
    expect(outcomes).toEqual([
      expect.objectContaining({
        attemptId: attempts[0]?.id,
        outcome: "success",
        upstreamRef: `rfnd_T${String(refundSeq)}`,
      }),
    ]);
    // attempt is written before the outcome
    expect((attempts[0]?.seq ?? 0) < (outcomes[0]?.seq ?? 0)).toBe(true);
  });

  it("read tools pass through without audit; their results are redacted for the agent only", async () => {
    const h = await setup();
    const r = await call(h, "fetch_payment", { payment_id: "pay_A1" });
    expect(JSON.stringify(r)).not.toContain("buyer@");
    expect(jsonOf(r)).toMatchObject({ id: "pay_A1", currency: "INR", email: "[REDACTED]" });
    expect(rows(h).attempts).toEqual([]);
    // the policy's own lookup sees raw upstream data (unfiltered) and still works
    const ok = await refund(h, { payment_id: "pay_A1", amount: 5_000 });
    expect(ok.isError).not.toBe(true);
  });
});

describe("deny", () => {
  it("returns {decision, ruleId, message}, never calls create_refund, audits attempt + denied", async () => {
    const h = await setup();
    const r = await refund(h, { payment_id: "pay_A1", amount: 2_000_000 });
    expectDeny(r, "refund.hard_cap");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const { attempts } = rows(h);
    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({
      decision: "deny",
      argsRedacted: { payment_id: "pay_A1", amount: 2_000_000 },
    });
    expect(attempts[0]?.matchedRules).toContain("refund.hard_cap");
    expect(outcomeOf(h, attempts[0]?.id ?? "")).toMatchObject({ outcome: "denied", latencyMs: 0 });
  });

  it("policy default deny lists policy-default in matchedRules", async () => {
    const h = await setup();
    const r = await call(h, "create_instant_settlement", {
      amount: 500,
      settle_full_balance: true,
      reason: REASON,
    });
    expectDeny(r, "policy-default");
    expect(rows(h).attempts[0]?.matchedRules).toEqual(["policy-default"]);
  });
});

describe("transform", () => {
  const CLAMP = compiled(
    definePolicy({
      default: "deny",
      rules: [
        rule("refund.clamp")
          .on("create_refund")
          .when((ctx) => ctx.amountPaise() > 1_000)
          .transform((ctx) => ({ ...ctx.args, amount: 1_000 })),
        rule("refund.ok").on("create_refund").allow(),
      ],
    }),
  );

  it("forwards the patched args and audits both original and patched", async () => {
    const h = await setup({ policy: CLAMP });
    const r = await refund(h, { payment_id: "pay_A1", amount: 5_000 });
    expect(r.isError).not.toBe(true);
    expect(upstreamCalls(h, "create_refund").map((c) => c.args)).toEqual([
      { payment_id: "pay_A1", amount: 1_000 },
    ]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({
      decision: "transform",
      argsRedacted: { payment_id: "pay_A1", amount: 1_000 },
      originalArgsRedacted: { payment_id: "pay_A1", amount: 5_000 },
    });
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("success");
  });

  it("a transform that changes payment_id is denied firewall.transform_retarget", async () => {
    const RETARGET = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("refund.retarget")
            .on("create_refund")
            .transform((ctx) => ({ ...ctx.args, payment_id: "pay_B2" })),
          rule("refund.ok").on("create_refund").allow(),
        ],
      }),
    );
    const h = await setup({ policy: RETARGET });
    expectDeny(
      await refund(h, { payment_id: "pay_A1", amount: 1_000 }),
      "firewall.transform_retarget",
    );
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a?.decision).toBe("deny");
    expect(a?.matchedRules).toContain("firewall.transform_retarget");
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
  });
});

describe("require_approval", () => {
  it("returns pending_approval (isError false), binds the approval to sha256 of finalArgs, attempt stays open", async () => {
    const h = await setup();
    const r = await refund(h, { payment_id: "pay_A1", amount: 300_000 });
    expect(r.isError).toBe(false);
    const body = jsonOf(r);
    expect(body).toMatchObject({
      decision: "pending_approval",
      message: expect.stringContaining("NOT executed") as string,
    });
    expect(String(body["approvalId"])).toMatch(/^apr_[0-9a-f-]{36}$/);
    expect(upstreamCalls(h, "create_refund")).toEqual([]);

    expect(h.approvals.requests).toHaveLength(1);
    const req = h.approvals.requests[0];
    const finalArgs = { payment_id: "pay_A1", amount: 300_000 };
    expect(req?.finalArgs).toEqual(finalArgs);
    expect(req?.finalArgsRedacted).toEqual(finalArgs);
    expect(req?.argsHash).toBe(
      nodeHasher.sha256Hex(unwrap(canonicalJson({ tool: "create_refund", args: finalArgs }))),
    );
    expect(req).toMatchObject({
      tool: "create_refund",
      ruleId: "refund.approval",
      via: "telegram",
      timeoutMin: 30,
      untrustedReason: REASON,
      sessionId: "sess-test",
    });
    expect(req?.reasonForDisplay.label).toBe(UNTRUSTED_REASON_LABEL);
    const { attempts } = rows(h);
    expect(req?.attemptId).toBe(attempts[0]?.id);
    expect(attempts[0]?.decision).toBe("require_approval");
    expect(outcomeOf(h, attempts[0]?.id ?? "")).toBeUndefined();
    expect(unwrap(h.store.verify())).toMatchObject({
      ok: true,
      danglingAttempts: [attempts[0]?.id],
    });
  });

  it("the pending approval blocks an identical refund (duplicate)", async () => {
    const h = await setup();
    await refund(h, { payment_id: "pay_A1", amount: 300_000 });
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 300_000 }), "refund.duplicate");
  });

  it("approval store failure ⇒ not_forwarded outcome + firewall.approval_unavailable", async () => {
    const h = await setup();
    const spy = vi
      .spyOn(h.approvals, "create")
      .mockResolvedValue(err("approval.down", "store down"));
    expectDeny(
      await refund(h, { payment_id: "pay_A1", amount: 300_000 }),
      "firewall.approval_unavailable",
    );
    spy.mockRestore();
    const a = rows(h).attempts[0];
    expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "approval.unavailable",
    });
  });

  it("executeApproved is a T011 stub that never executes", async () => {
    const h = await setup();
    const r = await h.pipeline.executeApproved({
      approvalId: "apr_x",
      attemptId: "a",
      argsHash: "0".repeat(64),
    });
    expect(denyRuleOf(r)).toBe("firewall.not_implemented");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// INR invariant
// ---------------------------------------------------------------------------------------------------------------

describe("INR invariant (D-017)", () => {
  it("a non-INR payment is denied firewall.currency_not_inr even with an allow-all policy", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    expectDeny(
      await refund(h, { payment_id: "pay_USD1", amount: 1_000 }),
      "firewall.currency_not_inr",
    );
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "deny", matchedRules: ["firewall.currency_not_inr"] });
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
    // the same policy allows an INR payment
    expect((await refund(h, { payment_id: "pay_A1", amount: 1_000 })).isError).not.toBe(true);
  });

  it("payment lookup failure ⇒ firewall.payment_lookup_failed", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    expectDeny(
      await refund(h, { payment_id: "pay_MISSING", amount: 1_000 }),
      "firewall.payment_lookup_failed",
    );
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    expect(rows(h).attempts[0]?.matchedRules).toEqual(["firewall.payment_lookup_failed"]);
  });

  it("a non-string payment_id is denied without a lookup", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    expectDeny(await refund(h, { payment_id: 123, amount: 1_000 }), "firewall.invalid_args");
    expect(upstreamCalls(h, "fetch_payment")).toEqual([]);
  });

  it("a currency arg other than INR is denied (moneyArgsStage) and audited by the envelope", async () => {
    const h = await setup();
    expectDeny(
      await call(h, "create_order", { amount: 1_000, currency: "USD", reason: REASON }),
      "firewall.currency_not_inr",
    );
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ tool: "create_order", decision: "deny", reason: "" });
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Audit failures
// ---------------------------------------------------------------------------------------------------------------

function failing(s: AuditStore, flags: { attempt?: boolean; outcome?: boolean }): PipelineStore {
  return {
    recordAttempt: (i) =>
      flags.attempt === true ? err("audit.write_failed", "disk full") : s.recordAttempt(i),
    recordOutcome: (i) =>
      flags.outcome === true ? err("audit.write_failed", "disk full") : s.recordOutcome(i),
    readActivitySince: (ms) => s.readActivitySince(ms),
  };
}

describe("audit failures (fail closed)", () => {
  it("recordAttempt error ⇒ audit_unavailable, nothing forwarded", async () => {
    const flags = { attempt: true };
    const h = await setup({ policy: ALLOW_REFUNDS, wrapStore: (s) => failing(s, flags) });
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }), "audit_unavailable");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });

  it("args that can't be audited ⇒ audit.invalid_args, trail row closed as denied", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    // A float outside any amount field passes moneyArgsStage but not the engine / audit encoding.
    expectDeny(
      await refund(h, { payment_id: "pay_A1", amount: 1_000, notes: { ratio: 1.5 } }),
      "audit.invalid_args",
    );
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "deny", matchedRules: ["audit.invalid_args"] });
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
  });

  it("outcome write failure after sending ⇒ upstream result returned, latch ⇒ later money calls denied", async () => {
    const flags = { outcome: false };
    const h = await setup({ policy: ALLOW_REFUNDS, wrapStore: (s) => failing(s, flags) });
    flags.outcome = true;
    const first = await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    expect(first.isError).not.toBe(true);
    expect(h.pipeline.isDegraded()).toBe(true);
    expect(h.logs.some((l) => l.startsWith("AUDIT DEGRADED"))).toBe(true);
    flags.outcome = false;
    expectDeny(await refund(h, { payment_id: "pay_B2", amount: 1_000 }), "audit_unavailable");
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    // read tools still work
    expect((await call(h, "fetch_payment", { payment_id: "pay_A1" })).isError).not.toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Upstream failures ⇒ outcomes
// ---------------------------------------------------------------------------------------------------------------

describe("startDegraded (audit chain failed verification at startup)", () => {
  const START = {
    reason: "chain broken at seq 3 (hash_mismatch)",
    message: "startup degraded msg",
  };

  it("money calls are denied audit_unavailable with the given message, audited; reads still forwarded", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS, startDegraded: START });
    expect(h.pipeline.isDegraded()).toBe(true);
    expect(
      h.logs.some((l) => l.startsWith("AUDIT DEGRADED AT STARTUP: chain broken at seq 3")),
    ).toBe(true);
    const r = await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    expectDeny(r, "audit_unavailable");
    expect(jsonOf(r)).toMatchObject({ message: "startup degraded msg" });
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    expect(upstreamCalls(h, "fetch_payment")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "deny", matchedRules: ["audit_unavailable"] });
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
    const read = await call(h, "fetch_payment", { payment_id: "pay_A1" });
    expect(read.isError).not.toBe(true);
    expect(upstreamCalls(h, "fetch_payment")).toHaveLength(1);
  });

  it("the deny is returned even if auditing it fails (best-effort)", async () => {
    const h = await setup({
      policy: ALLOW_REFUNDS,
      startDegraded: START,
      wrapStore: (s) => failing(s, { attempt: true }),
    });
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }), "audit_unavailable");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });

  it("without startDegraded the pipeline starts healthy", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    expect(h.pipeline.isDegraded()).toBe(false);
    expect((await refund(h, { payment_id: "pay_A1", amount: 1_000 })).isError).not.toBe(true);
  });
});

describe("upstream failures are audited", () => {
  it("tool-level error (isError) ⇒ upstream_error upstream.tool_error", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    h.refundHandler.fn = () =>
      Promise.resolve({ isError: true, content: [{ type: "text", text: "BAD_REQUEST_ERROR" }] });
    const r = await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    expect(r.isError).toBe(true);
    const a = rows(h).attempts[0];
    expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
      outcome: "upstream_error",
      errorCode: "upstream.tool_error",
    });
  });

  it("timeout ⇒ timeout outcome (forwarded: true for the agent)", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS, callTimeoutMs: 30 });
    h.refundHandler.fn = (_a, signal) => hang(signal);
    const r = await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_timeout", forwarded: true });
    const a = rows(h).attempts[0];
    expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
      outcome: "timeout",
      errorCode: "upstream.timeout",
    });
  });

  it("agent cancels after sending ⇒ timeout upstream.cancelled", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    h.refundHandler.fn = (_a, signal) => hang(signal);
    const ac = new AbortController();
    const p = refund(h, { payment_id: "pay_A1", amount: 1_000 }, ac.signal);
    await vi.waitFor(() => {
      expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    });
    ac.abort();
    await expect(p).rejects.toThrow();
    await vi.waitFor(() => {
      const a = rows(h).attempts[0];
      expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
        outcome: "timeout",
        errorCode: "upstream.cancelled",
      });
    });
  });

  it("upstream unavailable at forward time ⇒ not_forwarded", async () => {
    // The connection drops while the policy is evaluating (after the lookup, before the send).
    const hook: { fn?: () => Promise<void> } = {};
    const DROP = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("refund.drop")
            .on("create_refund")
            .when(async () => {
              await hook.fn?.();
              return true;
            })
            .allow(),
        ],
      }),
    );
    const h = await setup({ policy: DROP });
    hook.fn = async () => {
      h.fake.setFailing(true);
      await h.fake.dropConnection();
    };
    const r = await refund(h, { payment_id: "pay_A1", amount: 1_000 });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ error: "upstream_unavailable", forwarded: false });
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a?.decision).toBe("allow");
    expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "firewall.forward_refused",
    });
  });
});

describe("outcomeFor mapping table", () => {
  const ok: CallToolResult = { content: [{ type: "text", text: '{"id":"rfnd_X1"}' }] };
  const bad: CallToolResult = { isError: true, content: [{ type: "text", text: "x" }] };
  const rep = (kind: ForwardReport["kind"], sent: boolean): ForwardReport => ({
    kind,
    sent,
    latencyMs: 7,
  });
  it.each<[string, CallToolResult, ForwardReport | undefined, Record<string, unknown>]>([
    ["ok", ok, rep("ok", true), { outcome: "success", upstreamRef: "rfnd_X1", latencyMs: 7 }],
    [
      "ok+isError",
      bad,
      rep("ok", true),
      { outcome: "upstream_error", errorCode: "upstream.tool_error" },
    ],
    [
      "credential leak",
      bad,
      rep("credential_leak", true),
      { outcome: "upstream_error", errorCode: "upstream.credential_leak" },
    ],
    [
      "timeout",
      bad,
      rep("upstream_timeout", true),
      { outcome: "timeout", errorCode: "upstream.timeout" },
    ],
    [
      "cancelled sent",
      bad,
      rep("cancelled", true),
      { outcome: "timeout", errorCode: "upstream.cancelled" },
    ],
    [
      "cancelled not sent",
      bad,
      rep("cancelled", false),
      { outcome: "not_forwarded", latencyMs: 0 },
    ],
    ["unavailable not sent", bad, rep("upstream_unavailable", false), { outcome: "not_forwarded" }],
    ["unavailable sent", bad, rep("upstream_unavailable", true), { outcome: "upstream_error" }],
    ["error not sent", bad, rep("upstream_error", false), { outcome: "not_forwarded" }],
    [
      "error sent",
      bad,
      rep("upstream_error", true),
      { outcome: "upstream_error", errorCode: "upstream.error" },
    ],
    [
      "refused",
      bad,
      rep("refused", false),
      { outcome: "not_forwarded", errorCode: "firewall.forward_refused" },
    ],
    [
      "no report",
      ok,
      undefined,
      { outcome: "upstream_error", errorCode: "firewall.forward_unknown" },
    ],
  ])("%s", (_n, r, report, expected) => {
    expect(outcomeFor(r, report)).toMatchObject(expected);
  });

  it("upstreamRefOf only accepts a top-level id matching the ref shape", () => {
    const t = (text: string): CallToolResult => ({ content: [{ type: "text", text }] });
    expect(upstreamRefOf(t('{"id":"rfnd_1"}'))).toBe("rfnd_1");
    expect(upstreamRefOf(t('{"id":"bad id\\n"}'))).toBeUndefined();
    expect(upstreamRefOf(t('{"id":5}'))).toBeUndefined();
    expect(upstreamRefOf(t("[1]"))).toBeUndefined();
    expect(upstreamRefOf(t("not json"))).toBeUndefined();
    expect(denyRuleOf(denyResult("a.b", "m"))).toBe("a.b");
    expect(denyRuleOf(t('{"decision":"deny","ruleId":"x"}'))).toBeUndefined(); // not isError
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Sensitive / money-meaningful flags
// ---------------------------------------------------------------------------------------------------------------

describe("sensitive data and money-meaningful flags (default policy)", () => {
  it("submit_otp: the OTP never reaches the audit log", async () => {
    const h = await setup();
    const r = await call(h, "submit_otp", {
      payment_id: "pay_A1",
      otp_string: "887766",
      reason: REASON,
    });
    expectDeny(r, "policy-default");
    const text = JSON.stringify(unwrap(h.store.readAll()));
    expect(text).not.toContain("887766");
    expect(rows(h).attempts[0]?.argsRedacted).toMatchObject({ otp_string: "[REDACTED]" });
    expect(upstreamCalls(h, "submit_otp")).toEqual([]);
  });

  it.each<[string, Record<string, unknown>]>([
    ["create_instant_settlement", { amount: 500, settle_full_balance: true }],
    ["create_payment_link", { amount: 1_000, currency: "INR", accept_partial: true }],
    ["create_order", { amount: 1_000, currency: "INR", partial_payment: true }],
    [
      "create_order",
      {
        amount: 1_000,
        currency: "INR",
        token: { max_amount: 100, frequency: "monthly", type: "single_block_multiple_debit" },
      },
    ],
    ["create_qr_code", { type: "upi_qr", usage: "multiple_use", fixed_amount: false }],
  ])("%s %j ⇒ denied policy-default, not forwarded", async (tool, args) => {
    const h = await setup();
    expectDeny(await call(h, tool, { ...args, reason: REASON }), "policy-default");
    expect(upstreamCalls(h, tool)).toEqual([]);
    expect(rows(h).attempts[0]).toMatchObject({ tool, decision: "deny" });
  });

  it("an unknown upstream tool is gated as money and denied, never forwarded", async () => {
    const h = await setup();
    const listed = await h.agent.listTools();
    expect(listed.tools.find((t) => t.name === "brand_new_tool")?.inputSchema.required).toContain(
      "reason",
    );
    expectDeny(
      await call(h, "brand_new_tool", { payment_id: "pay_A1", amount: 100, reason: REASON }),
      "policy-default",
    );
    expect(upstreamCalls(h, "brand_new_tool")).toEqual([]);
    // case variants never resolve to a real tool
    expectDeny(
      await call(h, "Create_Refund", { payment_id: "pay_A1", amount: 100, reason: REASON }),
      "firewall.unknown_tool",
    );
  });

  it("moneyArgsStage denies are audited by the envelope (args minus reason, empty reason)", async () => {
    const h = await setup();
    expectDeny(
      await call(h, "create_refund", { payment_id: "pay_A1", amount: 100 }),
      "firewall.reason_required",
    );
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 10.5 }), "firewall.invalid_amount");
    const { attempts } = rows(h);
    expect(attempts.map((a) => a.matchedRules)).toEqual([
      ["firewall.reason_required"],
      ["firewall.invalid_amount"],
    ]);
    expect(attempts[0]).toMatchObject({
      decision: "deny",
      reason: "",
      argsRedacted: { payment_id: "pay_A1", amount: 100 },
    });
    expect(JSON.stringify(attempts)).not.toContain("double charged");
    for (const a of attempts) expect(outcomeOf(h, a.id)?.outcome).toBe("denied");
    expect(upstreamCalls(h, "fetch_payment")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------------------------------------------

describe("concurrency", () => {
  it("two identical refunds at once ⇒ exactly one create_refund, the other refund.duplicate", async () => {
    const h = await setup();
    const results = await Promise.all([
      refund(h, { payment_id: "pay_A1", amount: 5_000 }),
      refund(h, { payment_id: "pay_A1", amount: 5_000 }),
    ]);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    const denied = results.filter((r) => r.isError === true);
    expect(denied).toHaveLength(1);
    expect(jsonOf(denied[0])).toMatchObject({ ruleId: "refund.duplicate" });
  });

  it("velocity spans payments: 9 recent refunds + two concurrent ⇒ one forwarded, one refund.velocity", async () => {
    const h = await setup();
    for (let i = 0; i < VELOCITY_MAX_COUNT - 1; i++) {
      const a = unwrap(
        h.store.recordAttempt({
          sessionId: "seed",
          tool: "create_refund",
          args: { payment_id: `pay_SEED${String(i)}`, amount: 100 },
          reason: "seeded refund for the test",
          decision: "allow",
          matchedRules: ["refund.allow"],
        }),
      );
      unwrap(h.store.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 1 }));
    }
    const results = await Promise.all([
      refund(h, { payment_id: "pay_A1", amount: 1_000 }),
      refund(h, { payment_id: "pay_B2", amount: 1_000 }),
    ]);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    const denied = results.filter((r) => r.isError === true);
    expect(denied).toHaveLength(1);
    expect(jsonOf(denied[0])).toMatchObject({ ruleId: "refund.velocity" });
  });

  it("waiting longer than lockWaitMs for the same payment ⇒ firewall.busy (audited)", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS, lockWaitMs: 50 });
    let release: (() => void) | undefined;
    h.refundHandler.fn = (args) =>
      new Promise((resolve) => {
        release = () => {
          resolve({
            content: [{ type: "text", text: JSON.stringify({ id: "rfnd_SLOW", ...args }) }],
          });
        };
      });
    const first = refund(h, { payment_id: "pay_A1", amount: 1_000 });
    await vi.waitFor(() => {
      expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    });
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 2_000 }), "firewall.busy");
    release?.();
    expect((await first).isError).not.toBe(true);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    const busy = rows(h).attempts.find((a) => a.matchedRules.includes("firewall.busy"));
    expect(busy?.decision).toBe("deny");
    expect(outcomeOf(h, busy?.id ?? "")?.outcome).toBe("denied");
  });
});

describe("wiring guards", () => {
  it("the stage without its envelope fails closed", async () => {
    const h = await setup();
    const r = await h.pipeline.stage(
      {
        tool: "create_refund",
        toolClass: "money",
        args: { payment_id: "pay_A1", amount: 100 },
        inputSchema: { type: "object" },
        untrustedReason: REASON,
        sessionId: "s",
        signal: new AbortController().signal,
      },
      () => Promise.resolve({ content: [] }),
    );
    expect(denyRuleOf(r)).toBe("firewall.internal_error");
  });

  it("a stage that renames the tool is denied firewall.tool_mismatch", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    const renaming = h.pipeline.envelope({
      intercept: (ctx, forward) =>
        h.pipeline.stage({ ...ctx, tool: "create_refund", untrustedReason: REASON }, (c) =>
          forward({ ...c.args }),
        ),
    });
    const r = await renaming.intercept(
      {
        tool: "update_refund",
        toolClass: "money",
        args: { refund_id: "rfnd_1" },
        inputSchema: { type: "object" },
        sessionId: "s",
        signal: new AbortController().signal,
      },
      () => Promise.resolve({ content: [] }),
    );
    expect(denyRuleOf(r)).toBe("firewall.tool_mismatch");
    expect(rows(h).attempts[0]).toMatchObject({ tool: "update_refund", decision: "deny" });
  });

  it("missing untrustedReason on a money call ⇒ firewall.internal_error", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    const noReason = h.pipeline.envelope({
      intercept: (ctx, forward) => h.pipeline.stage(ctx, (c) => forward({ ...c.args })),
    });
    let forwarded = false;
    const r = await noReason.intercept(
      {
        tool: "create_refund",
        toolClass: "money",
        args: { payment_id: "pay_A1", amount: 100 },
        inputSchema: { type: "object" },
        sessionId: "s",
        signal: new AbortController().signal,
      },
      () => {
        forwarded = true;
        return Promise.resolve({ content: [] });
      },
    );
    expect(denyRuleOf(r)).toBe("firewall.internal_error");
    expect(forwarded).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Helpers for direct (non-MCP) interceptor calls
// ---------------------------------------------------------------------------------------------------------------

function schemaOf(tool: string): Tool["inputSchema"] {
  return TOOLS.find((t) => t.name === tool)?.inputSchema ?? { type: "object" };
}

/** Call the firewall interceptor directly (own signal / forward), bypassing the MCP server. */
function direct(
  h: Harness,
  tool: string,
  args: Record<string, unknown>,
  forward: (a: Record<string, unknown>) => Promise<CallToolResult>,
  signal: AbortSignal = new AbortController().signal,
): Promise<CallToolResult> {
  return createFirewallInterceptor(h.pipeline).intercept(
    {
      tool,
      toolClass: classifyTool(tool),
      args,
      inputSchema: schemaOf(tool),
      sessionId: "sess-direct",
      signal,
    },
    forward,
  );
}

const tick = (ms: number): Promise<void> =>
  new Promise((r) => {
    setTimeout(r, ms);
  });

// ---------------------------------------------------------------------------------------------------------------
// Transform output re-checks
// ---------------------------------------------------------------------------------------------------------------

describe("a transform's output is re-checked before forwarding", () => {
  const transformPolicy = (
    tool: string,
    patch: (args: Readonly<Record<string, unknown>>) => Record<string, unknown>,
  ): CompiledPolicy =>
    compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("t.patch")
            .on(tool)
            .transform((ctx) => patch(ctx.args) as typeof ctx.args),
          rule("t.ok").on(tool).allow(),
        ],
      }),
    );

  async function expectTransformDenied(
    tool: string,
    args: Record<string, unknown>,
    patch: (a: Readonly<Record<string, unknown>>) => Record<string, unknown>,
    ruleId: string,
  ): Promise<void> {
    const h = await setup({ policy: transformPolicy(tool, patch) });
    expectDeny(await call(h, tool, { ...args, reason: REASON }), ruleId);
    expect(upstreamCalls(h, tool)).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ tool, decision: "deny" });
    expect(a?.matchedRules).toContain(ruleId);
    if (ruleId.startsWith("firewall.")) expect(a?.matchedRules).toContain("t.patch");
    // the agent's (pre-transform) args are what was audited
    expect(a?.argsRedacted).toEqual(args);
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
  }

  it("transform sets currency USD ⇒ firewall.currency_not_inr", async () => {
    await expectTransformDenied(
      "create_order",
      { amount: 1_000, currency: "INR" },
      (a) => ({ ...a, currency: "USD" }),
      "firewall.currency_not_inr",
    );
  });

  it("transform adds a nested non-INR currency ⇒ firewall.currency_not_inr", async () => {
    await expectTransformDenied(
      "create_refund",
      { payment_id: "pay_A1", amount: 1_000 },
      (a) => ({ ...a, notes: { currency: "usd" } }),
      "firewall.currency_not_inr",
    );
  });

  it("transform changes order_id ⇒ firewall.transform_retarget", async () => {
    await expectTransformDenied(
      "initiate_payment",
      { order_id: "order_A1", amount: 1_000 },
      (a) => ({ ...a, order_id: "order_B2" }),
      "firewall.transform_retarget",
    );
  });

  it("transform adds payment_id ⇒ firewall.transform_retarget", async () => {
    await expectTransformDenied(
      "create_order",
      { amount: 1_000, currency: "INR" },
      (a) => ({ ...a, payment_id: "pay_A1" }),
      "firewall.transform_retarget",
    );
  });

  it("transform sets a nested float amount ⇒ denied (engine rejects the patch; firewall check backs it up)", async () => {
    await expectTransformDenied(
      "create_order",
      { amount: 1_000, currency: "INR" },
      (a) => ({ ...a, transfers: [{ account: "acc_1", amount: 10.5, currency: "INR" }] }),
      "engine-invalid-patch",
    );
    // the firewall's own re-check denies the same args independently of the engine
    expect(
      checkFinalArgs(
        { args: { amount: 1_000, currency: "INR" }, inputSchema: schemaOf("create_order") },
        { amount: 1_000, currency: "INR", transfers: [{ account: "acc_1", amount: 10.5 }] },
      ),
    ).toMatchObject({ ruleId: "firewall.invalid_amount" });
  });

  // The engine already rejects most bad patches (floats, added / raised amounts, `reason`, shallow merge never
  // removes keys); `checkFinalArgs` is the firewall's independent backstop, unit-tested here.
  it("checkFinalArgs: reason key, unsafe key, nested currency, amount 0 (top-level and nested), removed id, ok", () => {
    const ctx = {
      args: { payment_id: "pay_A1", amount: 1_000 },
      inputSchema: schemaOf("create_refund"),
    };
    expect(checkFinalArgs(ctx, { ...ctx.args, reason: "x" })).toMatchObject({
      ruleId: "firewall.invalid_args",
    });
    expect(checkFinalArgs(ctx, { ...ctx.args, "bad key": 1 })).toMatchObject({
      ruleId: "firewall.invalid_args",
    });
    expect(checkFinalArgs(ctx, { ...ctx.args, notes: { currency: "USD" } })).toMatchObject({
      ruleId: "firewall.currency_not_inr",
    });
    expect(checkFinalArgs(ctx, { ...ctx.args, amount: 0 })).toMatchObject({
      ruleId: "firewall.invalid_amount",
    });
    expect(
      checkFinalArgs(ctx, { ...ctx.args, transfers: [{ account: "acc_1", amount: 0 }] }),
    ).toMatchObject({ ruleId: "firewall.invalid_amount" });
    expect(checkFinalArgs(ctx, { amount: 1_000 })).toMatchObject({
      ruleId: "firewall.transform_retarget",
    });
    expect(checkFinalArgs(ctx, { ...ctx.args, amount: 500 })).toBeUndefined();
  });

  it("retargetsIds: only top-level *_id keys added / removed / changed", () => {
    expect(retargetsIds({ payment_id: "a" }, { payment_id: "a", amount: 1 })).toBe(false);
    expect(retargetsIds({ payment_id: "a" }, { payment_id: "b" })).toBe(true);
    expect(retargetsIds({ payment_id: "a" }, {})).toBe(true);
    expect(retargetsIds({}, { refund_id: "r" })).toBe(true);
    expect(retargetsIds({ notes: { x_id: "1" } }, { notes: { x_id: "2" } })).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// INR invariant for order-based money tools
// ---------------------------------------------------------------------------------------------------------------

const ALLOW_ALL_TEST_TOOLS = compiled(
  definePolicy({
    default: "deny",
    rules: [
      rule("t.initiate").on("initiate_payment").allow(),
      rule("t.update_order").on("update_order").allow(),
      rule("t.unknown").on("brand_new_tool").allow(),
      rule("t.refund").on("create_refund").allow(),
    ],
  }),
);

describe("INR invariant for orders (D-017)", () => {
  it("initiate_payment on a non-INR order ⇒ firewall.currency_not_inr even with an allow-all policy", async () => {
    const h = await setup({ policy: ALLOW_ALL_TEST_TOOLS });
    expectDeny(
      await call(h, "initiate_payment", { order_id: "order_USD1", amount: 1_000, reason: REASON }),
      "firewall.currency_not_inr",
    );
    expect(upstreamCalls(h, "fetch_order").map((c) => c.args)).toEqual([
      { order_id: "order_USD1" },
    ]);
    expect(upstreamCalls(h, "initiate_payment")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({ decision: "deny", matchedRules: ["firewall.currency_not_inr"] });
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
  });

  it("an INR order is forwarded", async () => {
    const h = await setup({ policy: ALLOW_ALL_TEST_TOOLS });
    const r = await call(h, "update_order", {
      order_id: "order_A1",
      notes: { k: "v" },
      reason: REASON,
    });
    expect(r.isError).not.toBe(true);
    expect(upstreamCalls(h, "update_order").map((c) => c.args)).toEqual([
      { order_id: "order_A1", notes: { k: "v" } },
    ]);
  });

  it("order lookup failure ⇒ firewall.order_lookup_failed (missing, malformed id, non-string id)", async () => {
    const h = await setup({ policy: ALLOW_ALL_TEST_TOOLS });
    expectDeny(
      await call(h, "initiate_payment", {
        order_id: "order_MISSING",
        amount: 1_000,
        reason: REASON,
      }),
      "firewall.order_lookup_failed",
    );
    expectDeny(
      await call(h, "initiate_payment", { order_id: "ord-1", amount: 1_000, reason: REASON }),
      "firewall.order_lookup_failed",
    );
    expectDeny(
      await call(h, "initiate_payment", { order_id: 7, amount: 1_000, reason: REASON }),
      "firewall.invalid_args",
    );
    expect(upstreamCalls(h, "fetch_order").map((c) => c.args)).toEqual([
      { order_id: "order_MISSING" },
    ]);
    expect(upstreamCalls(h, "initiate_payment")).toEqual([]);
    expect(rows(h).attempts.map((a) => a.matchedRules)).toEqual([
      ["firewall.order_lookup_failed"],
      ["firewall.order_lookup_failed"],
      ["firewall.invalid_args"],
    ]);
  });

  it("a call with both payment_id and order_id checks both (non-INR order denies)", async () => {
    const h = await setup({ policy: ALLOW_ALL_TEST_TOOLS });
    expectDeny(
      await call(h, "brand_new_tool", {
        payment_id: "pay_A1",
        order_id: "order_USD1",
        amount: 100,
        reason: REASON,
      }),
      "firewall.currency_not_inr",
    );
    expect(upstreamCalls(h, "fetch_payment")).toHaveLength(1);
    expect(upstreamCalls(h, "fetch_order")).toHaveLength(1);
  });
});

describe("resource locks (payment + order)", () => {
  it("resourceLockKeys: payment:<id> / order:<id>, sorted", () => {
    expect(resourceLockKeys({ payment: "pay_A1", order: "order_A1" })).toEqual([
      "order:order_A1",
      "payment:pay_A1",
    ]);
    expect(resourceLockKeys({ payment: "pay_A1" })).toEqual(["payment:pay_A1"]);
    expect(resourceLockKeys({})).toEqual([]);
  });

  it("a call holding both ids blocks calls on either id (busy, audited); reversed key order never deadlocks", async () => {
    const h = await setup({ policy: ALLOW_ALL_TEST_TOOLS, lockWaitMs: 50 });
    let release: (() => void) | undefined;
    h.handlers.set(
      "brand_new_tool",
      (args) =>
        new Promise((resolve) => {
          release = () => {
            resolve({
              content: [{ type: "text", text: JSON.stringify({ id: "obj_SLOW", args }) }],
            });
          };
        }),
    );
    const first = call(h, "brand_new_tool", {
      payment_id: "pay_A1",
      order_id: "order_A1",
      amount: 100,
      reason: REASON,
    });
    await vi.waitFor(() => {
      expect(upstreamCalls(h, "brand_new_tool")).toHaveLength(1);
    });
    expectDeny(
      await call(h, "initiate_payment", { order_id: "order_A1", amount: 100, reason: REASON }),
      "firewall.busy",
    );
    expectDeny(
      await call(h, "create_refund", { payment_id: "pay_A1", amount: 100, reason: REASON }),
      "firewall.busy",
    );
    release?.();
    expect((await first).isError).not.toBe(true);
    h.handlers.delete("brand_new_tool");

    // Same two ids, opposite insertion order, concurrently: both complete (sorted acquisition order).
    const h2 = await setup({ policy: ALLOW_ALL_TEST_TOOLS });
    const both = await Promise.all([
      call(h2, "brand_new_tool", {
        payment_id: "pay_A1",
        order_id: "order_A1",
        amount: 100,
        reason: REASON,
      }),
      call(h2, "brand_new_tool", {
        order_id: "order_A1",
        payment_id: "pay_A1",
        amount: 200,
        reason: REASON,
      }),
    ]);
    for (const r of both) expect(r.isError).not.toBe(true);
    expect(upstreamCalls(h2, "brand_new_tool")).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Pipeline failure paths
// ---------------------------------------------------------------------------------------------------------------

describe("pipeline failure paths", () => {
  it("preCheck deny ⇒ audited deny with its rule id; no lookup, nothing forwarded", async () => {
    const h = await setup({
      policy: ALLOW_REFUNDS,
      preCheck: () => ({ ruleId: "killswitch.engaged", message: "money actions are paused" }),
    });
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }), "killswitch.engaged");
    expect(upstreamCalls(h, "fetch_payment")).toEqual([]);
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({
      decision: "deny",
      matchedRules: ["killswitch.engaged"],
      reason: REASON,
    });
    expect(outcomeOf(h, a?.id ?? "")?.outcome).toBe("denied");
  });

  it("preCheck throws ⇒ firewall.internal_error (fail closed)", async () => {
    const h = await setup({
      policy: ALLOW_REFUNDS,
      preCheck: () => {
        throw new Error("kill switch store down");
      },
    });
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }), "firewall.internal_error");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    expect(rows(h).attempts[0]?.matchedRules).toEqual(["firewall.internal_error"]);
    expect(h.logs.join("\n")).not.toContain("kill switch store down");
  });

  it("abort after recordAttempt, before forward ⇒ not_forwarded agent.cancelled; forward never called", async () => {
    const ac = new AbortController();
    const h = await setup({
      policy: ALLOW_REFUNDS,
      wrapStore: (s) => ({
        recordAttempt: (i) => {
          const r = s.recordAttempt(i);
          if (i.decision === "allow") ac.abort();
          return r;
        },
        recordOutcome: (i) => s.recordOutcome(i),
        readActivitySince: (ms) => s.readActivitySince(ms),
      }),
    });
    const forward = vi.fn(() => Promise.resolve<CallToolResult>({ content: [] }));
    const r = await direct(
      h,
      "create_refund",
      { payment_id: "pay_A1", amount: 1_000, reason: REASON },
      forward,
      ac.signal,
    );
    expect(forward).not.toHaveBeenCalled();
    expect(jsonOf(r)).toMatchObject({ error: "cancelled", forwarded: false });
    const a = rows(h).attempts[0];
    expect(a?.decision).toBe("allow");
    expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "agent.cancelled",
    });
  });

  it("forward throwing ⇒ upstream_error firewall.forward_threw (may have been sent)", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    const r = await direct(
      h,
      "create_refund",
      { payment_id: "pay_A1", amount: 1_000, reason: REASON },
      () => Promise.reject(new Error("socket hang up")),
    );
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ error: "upstream_error", forwarded: true });
    const a = rows(h).attempts[0];
    expect(outcomeOf(h, a?.id ?? "")).toMatchObject({
      outcome: "upstream_error",
      errorCode: "firewall.forward_threw",
    });
    expect(h.pipeline.isDegraded()).toBe(false);
  });

  /** Policy whose create_order evaluation blocks (holding the global lock) until `gate.open()`. */
  function gatedPolicy(gate: { wait: Promise<void> }): CompiledPolicy {
    return compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("order.hold")
            .on("create_order")
            .when(async () => {
              await gate.wait;
              return false;
            })
            .deny("held"),
          rule("refund.ok").on("create_refund").allow(),
        ],
      }),
    );
  }

  function makeGate(): { wait: Promise<void>; open: () => void } {
    let open: () => void = () => undefined;
    const wait = new Promise<void>((r) => {
      open = r;
    });
    return { wait, open };
  }

  it("global lock busy ⇒ firewall.busy (audited), nothing forwarded", async () => {
    const gate = makeGate();
    const h = await setup({ policy: gatedPolicy(gate), lockWaitMs: 50 });
    const holder = call(h, "create_order", { amount: 1_000, currency: "INR", reason: REASON });
    await tick(20);
    expectDeny(await refund(h, { payment_id: "pay_A1", amount: 1_000 }), "firewall.busy");
    gate.open();
    await holder;
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const busy = rows(h).attempts.find((a) => a.matchedRules.includes("firewall.busy"));
    expect(busy).toMatchObject({ tool: "create_refund", decision: "deny" });
    expect(outcomeOf(h, busy?.id ?? "")?.outcome).toBe("denied");
  });

  it("cancelled while waiting for the global lock ⇒ firewall.cancelled (audited)", async () => {
    const gate = makeGate();
    const h = await setup({ policy: gatedPolicy(gate), lockWaitMs: 5_000 });
    const holder = call(h, "create_order", { amount: 1_000, currency: "INR", reason: REASON });
    await tick(20);
    const ac = new AbortController();
    const forward = vi.fn(() => Promise.resolve<CallToolResult>({ content: [] }));
    const waiting = direct(
      h,
      "create_payment_link",
      { amount: 1_000, currency: "INR", reason: REASON },
      forward,
      ac.signal,
    );
    await tick(20);
    ac.abort();
    const r = await waiting;
    expect(denyRuleOf(r)).toBe("firewall.cancelled");
    expect(forward).not.toHaveBeenCalled();
    gate.open();
    await holder;
    const c = rows(h).attempts.find((a) => a.matchedRules.includes("firewall.cancelled"));
    expect(c).toMatchObject({ tool: "create_payment_link", decision: "deny" });
  });

  it("approval-outcome write failure latches the pipeline degraded", async () => {
    const flags = { outcome: false };
    const h = await setup({ wrapStore: (s) => failing(s, flags) });
    const spy = vi
      .spyOn(h.approvals, "create")
      .mockResolvedValue(err("approval.down", "store down"));
    flags.outcome = true;
    expectDeny(
      await refund(h, { payment_id: "pay_A1", amount: 300_000 }),
      "firewall.approval_unavailable",
    );
    spy.mockRestore();
    expect(h.pipeline.isDegraded()).toBe(true);
    expect(h.logs.some((l) => l.startsWith("AUDIT DEGRADED"))).toBe(true);
    flags.outcome = false;
    expectDeny(await refund(h, { payment_id: "pay_B2", amount: 1_000 }), "audit_unavailable");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });

  it("latch set while a call waits for the global lock ⇒ that call is denied audit_unavailable, not forwarded", async () => {
    const flags = { outcome: false };
    const gate = makeGate();
    const upstreamGate = makeGate();
    const h = await setup({
      policy: gatedPolicy(gate),
      lockWaitMs: 5_000,
      wrapStore: (s) => failing(s, flags),
    });
    // C: forwarded (global lock released), upstream hangs until upstreamGate opens.
    h.refundHandler.fn = async (a) => {
      await upstreamGate.wait;
      return { content: [{ type: "text", text: JSON.stringify({ id: "rfnd_C1", ...a }) }] };
    };
    const c = refund(h, { payment_id: "pay_B2", amount: 1_000 });
    await tick(30);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    // A: holds the global lock (evaluation blocked on gate).
    const a = call(h, "create_order", { amount: 1_000, currency: "INR", reason: REASON });
    await tick(20);
    // B: passes the entry latch check (healthy), then waits on the global lock.
    expect(h.pipeline.isDegraded()).toBe(false);
    const b = refund(h, { payment_id: "pay_A1", amount: 1_000 });
    await tick(20);
    // C's outcome write fails ⇒ latch set while B is waiting.
    flags.outcome = true;
    upstreamGate.open();
    expect((await c).isError).not.toBe(true);
    expect(h.pipeline.isDegraded()).toBe(true);
    flags.outcome = false;
    gate.open();
    await a;
    expectDeny(await b, "audit_unavailable");
    // Only C reached upstream; B was never forwarded.
    const sent = upstreamCalls(h, "create_refund");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.args).toMatchObject({ payment_id: "pay_B2" });
    const bRow = rows(h).attempts.find(
      (r) => r.tool === "create_refund" && r.matchedRules.includes("audit_unavailable"),
    );
    expect(bRow).toMatchObject({ decision: "deny" });
    expect(outcomeOf(h, bRow?.id ?? "")?.outcome).toBe("denied");
  });
});

describe("per-call binding token", () => {
  it("a context rebuilt without the envelope's token (same signal) is not trusted", async () => {
    const h = await setup({ policy: ALLOW_REFUNDS });
    const rebuilding = h.pipeline.envelope({
      intercept: (ctx, forward) =>
        h.pipeline.stage(
          {
            tool: ctx.tool,
            toolClass: ctx.toolClass,
            args: ctx.args,
            inputSchema: ctx.inputSchema,
            untrustedReason: REASON,
            sessionId: ctx.sessionId,
            signal: ctx.signal,
          },
          (c) => forward({ ...c.args }),
        ),
    });
    let forwarded = false;
    const r = await rebuilding.intercept(
      {
        tool: "create_refund",
        toolClass: "money",
        args: { payment_id: "pay_A1", amount: 100 },
        inputSchema: { type: "object" },
        sessionId: "s",
        signal: new AbortController().signal,
      },
      () => {
        forwarded = true;
        return Promise.resolve({ content: [] });
      },
    );
    expect(denyRuleOf(r)).toBe("firewall.internal_error");
    expect(forwarded).toBe(false);
  });
});
