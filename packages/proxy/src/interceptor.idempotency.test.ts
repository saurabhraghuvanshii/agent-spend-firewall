/**
 * T009: duplicate detection in the money pipeline (firewall invariant), end to end through the MCP proxy with a fake
 * upstream and a file-backed audit store.
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
  type Clock,
  type CompiledPolicy,
  type PolicySpec,
  type Result,
} from "@asf/core";
import defaultPolicy from "@asf/policies";
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
import { systemTimer } from "./context-adapters.js";
import { DUPLICATE_MESSAGES, idempotencyKey } from "./idempotency.js";
import {
  createFirewallInterceptor,
  createMoneyPipeline,
  type MoneyPipelineOptions,
  type PipelineStore,
} from "./interceptor.js";
import { redactSensitiveResult } from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { createProxyServer, type ProxyServer } from "./server.js";
import { fakeUpstream, hang, jsonOf, type FakeUpstream } from "./test-support/fake-upstream.js";
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

/** No `refund.duplicate` rule: duplicates must be stopped by the firewall itself. */
const ALLOW = compiled(
  definePolicy({
    default: "deny",
    rules: [
      rule("money.allow").on(["create_refund", "create_payment_link", "initiate_payment"]).allow(),
    ],
  }),
);
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
const DEFAULT = compiled(defaultPolicy);

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  store: AuditStore;
  approvals: InMemoryApprovalStub;
  logs: string[];
  clock: { offsetMs: number; broken: boolean };
  handlers: Map<
    string,
    (args: Record<string, unknown>, signal: AbortSignal) => Promise<CallToolResult>
  >;
  closed: boolean;
}

interface SetupOpts {
  policy?: CompiledPolicy;
  dbPath?: string;
  callTimeoutMs?: number;
  wrapStore?: (s: AuditStore) => PipelineStore;
  duplicateWindowMs?: number;
  maxActivityRows?: number;
}

let dir: string;
const open: Harness[] = [];
let refundSeq = 0;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-idem-"));
});

async function close(h: Harness): Promise<void> {
  if (h.closed) return;
  h.closed = true;
  await h.agent.close();
  await h.proxy.close();
  await h.upstream.close();
  const v = unwrap(h.store.verify());
  expect(v.ok).toBe(true);
  h.store.close();
}

afterEach(async () => {
  for (const h of open.splice(0)) await close(h);
  rmSync(dir, { recursive: true, force: true });
});

async function setup(opts: SetupOpts = {}): Promise<Harness> {
  const handlers: Harness["handlers"] = new Map();
  const fake = fakeUpstream({
    tools: TOOLS,
    handler: (name, args, signal) => {
      const a = args ?? {};
      const override = handlers.get(name);
      if (override !== undefined) return override(a, signal);
      if (name === "fetch_payment") {
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                id: a["payment_id"],
                status: "captured",
                amount: 500_000,
                amount_refunded: 0,
                currency: "INR",
              }),
            },
          ],
        });
      }
      if (name === "create_refund") {
        refundSeq++;
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({ id: `rfnd_T${String(refundSeq)}abcdef`, entity: "refund" }),
            },
          ],
        });
      }
      return Promise.resolve({
        content: [{ type: "text", text: JSON.stringify({ id: "plink_ABC123xyz" }) }],
      });
    },
  });
  const logs: string[] = [];
  const upstream = new Upstream({
    factory: fake.factory,
    logger: (l) => logs.push(l),
    sleep: () => Promise.resolve(),
  });
  const store = unwrap(
    openAuditStore({
      path: opts.dbPath ?? join(dir, `audit-${String(open.length)}.db`),
      ...(opts.maxActivityRows === undefined ? {} : { maxActivityRows: opts.maxActivityRows }),
    }),
  );
  const approvals = createInMemoryApprovalStub();
  const clockState = { offsetMs: 0, broken: false };
  const clock: Clock = {
    nowMs: () => (clockState.broken ? Number.NaN : Date.now() + clockState.offsetMs),
  };
  const pipelineOpts: MoneyPipelineOptions = {
    policy: opts.policy ?? ALLOW,
    store: opts.wrapStore === undefined ? store : opts.wrapStore(store),
    upstream,
    approvals,
    clock,
    timer: systemTimer,
    logger: (l) => logs.push(l),
    ...(opts.duplicateWindowMs === undefined ? {} : { duplicateWindowMs: opts.duplicateWindowMs }),
  };
  const pipeline = createMoneyPipeline(pipelineOpts);
  const proxy = createProxyServer({
    upstream,
    interceptor: createFirewallInterceptor(pipeline, { logger: (l) => logs.push(l) }),
    advertise: advertiseTool,
    resultFilter: redactSensitiveResult,
    logger: (l) => logs.push(l),
    sessionId: "sess-idem",
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
    approvals,
    logs,
    clock: clockState,
    handlers,
    closed: false,
  };
  open.push(h);
  return h;
}

function call(h: Harness, name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  return h.agent.request(
    { method: "tools/call", params: { name, arguments: { reason: REASON, ...args } } },
    CallToolResultSchema,
  );
}
const refund = (h: Harness, args: Record<string, unknown>) => call(h, "create_refund", args);
const upstreamCalls = (h: Harness, name: string) => h.fake.calls.filter((c) => c.name === name);

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

function expectDuplicate(
  r: CallToolResult,
  status: keyof typeof DUPLICATE_MESSAGES,
): Record<string, unknown> {
  expect(r.isError).toBe(true);
  const body = jsonOf(r);
  expect(body).toMatchObject({
    decision: "deny",
    ruleId: "firewall.duplicate",
    message: DUPLICATE_MESSAGES[status],
    duplicateOf: { status, attemptId: expect.any(String) as string },
  });
  expect(JSON.stringify(r)).not.toContain("double charged");
  return body["duplicateOf"] as Record<string, unknown>;
}

const A1 = { payment_id: "pay_A1", amount: 5_000 };

// ---------------------------------------------------------------------------------------------------------------

describe("concurrent identical calls", () => {
  it("two identical create_refund ⇒ exactly one upstream call, the other denied executed", async () => {
    const h = await setup();
    const results = await Promise.all([refund(h, A1), refund(h, A1)]);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    const denied = results.filter((r) => r.isError === true);
    expect(denied).toHaveLength(1);
    // Same payment ⇒ the resource lock serialises them: the second sees the first EXECUTED.
    const dup = expectDuplicate(denied[0] as CallToolResult, "executed");
    expect(dup["upstreamRef"]).toMatch(/^rfnd_T\d+abcdef$/);
  });

  it("two identical create_payment_link ⇒ one upstream call, the second denied in_flight at once", async () => {
    const h = await setup();
    let release: (() => void) | undefined;
    h.handlers.set(
      "create_payment_link",
      () =>
        new Promise((res) => {
          release = () => {
            res({ content: [{ type: "text", text: JSON.stringify({ id: "plink_ABC123xyz" }) }] });
          };
        }),
    );
    const args = { amount: 10_000, currency: "INR", description: "Order 42" };
    const all = Promise.all([
      call(h, "create_payment_link", args),
      call(h, "create_payment_link", args),
    ]);
    // The duplicate is denied (and audited) while the first is still in flight upstream.
    await vi.waitFor(() => {
      expect(rows(h).attempts.some((a) => a.matchedRules.includes("firewall.duplicate"))).toBe(
        true,
      );
    });
    expect(upstreamCalls(h, "create_payment_link")).toHaveLength(1);
    release?.();
    const results = await all;
    expect(upstreamCalls(h, "create_payment_link")).toHaveLength(1);
    const denied = results.filter((r) => r.isError === true);
    expect(denied).toHaveLength(1);
    const dup = expectDuplicate(denied[0] as CallToolResult, "in_flight");
    const first = rows(h).attempts.find((a) => a.decision === "allow");
    expect(dup["attemptId"]).toBe(first?.id);
    expect(dup).not.toHaveProperty("upstreamRef");
  });
});

describe("repeats", () => {
  it("policy without refund.duplicate: repeat after success ⇒ executed + upstreamRef, upstream not called", async () => {
    const h = await setup({ policy: ALLOW });
    const first = await refund(h, A1);
    expect(first.isError).not.toBe(true);
    const ref = jsonOf(first)["id"];
    const dup = expectDuplicate(await refund(h, A1), "executed");
    expect(dup["upstreamRef"]).toBe(ref);
    expect(dup["attemptId"]).toBe(rows(h).attempts[0]?.id);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
  });

  it("after a timeout that can't be verified ⇒ unknown (flagged), then blocked may_have_executed", async () => {
    const h = await setup({ callTimeoutMs: 30 });
    h.handlers.set("create_refund", (_a, signal) => hang(signal));
    const first = await refund(h, A1);
    // T010: the refund list lookup is unreadable here ⇒ unknown, flagged for a human.
    expect(jsonOf(first)).toMatchObject({ outcome: "unknown", flaggedForHuman: true });
    expect(rows(h).outcomes[0]?.outcome).toBe("timeout");
    expectDuplicate(await refund(h, A1), "may_have_executed");
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
  });

  it("after not_forwarded ⇒ allowed", async () => {
    const h = await setup({ policy: DEFAULT });
    const spy = vi
      .spyOn(h.approvals, "create")
      .mockResolvedValueOnce(err("approval.down", "store down"));
    const big = { payment_id: "pay_A1", amount: 300_000 };
    expect(jsonOf(await refund(h, big))["ruleId"]).toBe("firewall.approval_unavailable");
    expect(rows(h).outcomes[0]?.outcome).toBe("not_forwarded");
    const again = await refund(h, big);
    expect(jsonOf(again)).toMatchObject({ decision: "pending_approval" });
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("after a policy deny ⇒ allowed", async () => {
    let denyNow = true;
    const ONCE = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("refund.blocked")
            .on("create_refund")
            .when(() => denyNow)
            .deny("blocked for now"),
          rule("refund.ok").on("create_refund").allow(),
        ],
      }),
    );
    const h = await setup({ policy: ONCE });
    expect(jsonOf(await refund(h, A1))["ruleId"]).toBe("refund.blocked");
    denyNow = false;
    const r = await refund(h, A1);
    expect(r.isError).not.toBe(true);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
  });

  it("different amount ⇒ allowed; same refund differing only in notes / receipt ⇒ blocked", async () => {
    const h = await setup();
    expect((await refund(h, A1)).isError).not.toBe(true);
    expect((await refund(h, { ...A1, amount: 5_001 })).isError).not.toBe(true);
    expectDuplicate(
      await refund(h, { ...A1, notes: { attempt: "2" }, receipt: "retry-2" }),
      "executed",
    );
    expect(upstreamCalls(h, "create_refund")).toHaveLength(2);
  });

  it.each([
    ["create_payment_link", { amount: 10_000, currency: "INR" }],
    ["initiate_payment", { amount: 10_000, currency: "INR", order_id: "order_ABC123xyz" }],
  ] as const)(
    "%s: repeat differing only in notes / description / receipt / reference_id ⇒ blocked; amount ⇒ allowed",
    async (tool, base) => {
      const h = await setup();
      h.handlers.set("fetch_order", (a) =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                id: a["order_id"],
                entity: "order",
                status: "created",
                amount: 10_000,
                currency: "INR",
              }),
            },
          ],
        }),
      );
      const first = await call(h, tool, { ...base, notes: { n: "1" } });
      expect(first.isError, JSON.stringify(first)).not.toBe(true);
      const variants: Array<Record<string, unknown>> = [
        { ...base, notes: { n: "2", why: "retry" } },
        { ...base, description: "Order 42 (second try)" },
        { ...base, receipt: "rcpt-2" },
        { ...base, reference_id: "ref-2" },
        { ...base, description: "d", receipt: "r", reference_id: "x", notes: {} },
      ];
      for (const v of variants) expectDuplicate(await call(h, tool, v), "executed");
      expect(upstreamCalls(h, tool)).toHaveLength(1);
      expect((await call(h, tool, { ...base, amount: 10_001 })).isError).not.toBe(true);
      expect(upstreamCalls(h, tool)).toHaveLength(2);
    },
  );

  it("pending approval ⇒ duplicate deny; approval port create called once", async () => {
    const h = await setup({ policy: DEFAULT });
    const spy = vi.spyOn(h.approvals, "create");
    const big = { payment_id: "pay_A1", amount: 300_000 };
    expect(jsonOf(await refund(h, big))).toMatchObject({ decision: "pending_approval" });
    expectDuplicate(await refund(h, big), "pending_approval");
    expect(spy).toHaveBeenCalledTimes(1);
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });
});

describe("transforms", () => {
  it("transformed refund, then a repeat with the ORIGINAL args ⇒ blocked (and with the final args too)", async () => {
    const h = await setup({ policy: CLAMP });
    expect((await refund(h, A1)).isError).not.toBe(true);
    expect(upstreamCalls(h, "create_refund").map((c) => c.args)).toEqual([
      { payment_id: "pay_A1", amount: 1_000, notes: { asf_attempt: rows(h).attempts[0]?.id } },
    ]);
    expectDuplicate(await refund(h, A1), "executed");
    expectDuplicate(await refund(h, { payment_id: "pay_A1", amount: 1_000 }), "executed");
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
  });

  it("a transform that turns a new call into a repeat of an earlier one ⇒ blocked after the policy", async () => {
    const h = await setup({ policy: CLAMP });
    expect((await refund(h, { payment_id: "pay_A1", amount: 1_000 })).isError).not.toBe(true);
    // 7_000 is new for the agent's key, but the clamp would forward 1_000 again.
    expectDuplicate(await refund(h, { payment_id: "pay_A1", amount: 7_000 }), "executed");
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
    const dupRow = rows(h).attempts.at(-1);
    expect(dupRow).toMatchObject({ decision: "deny" });
    expect(dupRow?.matchedRules).toContain("refund.clamp");
    expect(dupRow?.matchedRules.at(-1)).toBe("firewall.duplicate");
  });
});

describe("persistence and windows", () => {
  it("restart (same DB file, new pipeline) ⇒ still blocked", async () => {
    const dbPath = join(dir, "persist", "audit.db");
    const h1 = await setup({ dbPath });
    expect((await refund(h1, A1)).isError).not.toBe(true);
    await close(h1);
    const h2 = await setup({ dbPath });
    expectDuplicate(await refund(h2, A1), "executed");
    expect(upstreamCalls(h2, "create_refund")).toEqual([]);
  });

  it("window elapsed (fake clock) ⇒ allowed", async () => {
    const h = await setup();
    expect((await refund(h, A1)).isError).not.toBe(true);
    h.clock.offsetMs = 9 * 60_000;
    expectDuplicate(await refund(h, A1), "executed");
    h.clock.offsetMs = 11 * 60_000;
    expect((await refund(h, A1)).isError).not.toBe(true);
    expect(upstreamCalls(h, "create_refund")).toHaveLength(2);
  });

  it("duplicateWindowMs is configurable", async () => {
    const h = await setup({ duplicateWindowMs: 60_000 });
    expect((await refund(h, A1)).isError).not.toBe(true);
    h.clock.offsetMs = 61_000;
    expect((await refund(h, A1)).isError).not.toBe(true);
  });

  it("a timed-out (may have executed) refund stays blocked past the window, up to 24 h", async () => {
    const h = await setup({ callTimeoutMs: 30 });
    h.handlers.set("create_refund", (_a, signal) => hang(signal));
    await refund(h, A1);
    expect(rows(h).outcomes[0]?.outcome).toBe("timeout");
    h.handlers.delete("create_refund");
    h.clock.offsetMs = 11 * 60_000;
    expectDuplicate(await refund(h, A1), "may_have_executed");
    h.clock.offsetMs = 23 * 60 * 60_000;
    expectDuplicate(await refund(h, A1), "may_have_executed");
    expect(upstreamCalls(h, "create_refund")).toHaveLength(1);
  });

  it("open actions block beyond the window (up to 24 h)", async () => {
    const h = await setup({ policy: DEFAULT });
    const big = { payment_id: "pay_A1", amount: 300_000 };
    await refund(h, big);
    h.clock.offsetMs = 23 * 60 * 60_000;
    expectDuplicate(await refund(h, big), "pending_approval");
  });

  it.each([0, 59_999, 86_400_001, 1.5, Number.NaN])(
    "invalid duplicateWindowMs %d ⇒ refuses to construct",
    async (w) => {
      await expect(setup({ duplicateWindowMs: w })).rejects.toThrow(/duplicateWindowMs/);
    },
  );
});

describe("fail closed", () => {
  it("audit read failure ⇒ firewall.duplicate_check_failed, nothing forwarded, deny audited", async () => {
    const h = await setup({
      wrapStore: (s) => ({
        recordAttempt: (i) => s.recordAttempt(i),
        recordOutcome: (i) => s.recordOutcome(i),
        recordVerification: (i) => s.recordVerification(i),
        readUnsettled: () => s.readUnsettled(),
        recordApproval: (i) => s.recordApproval(i),
        readAttempt: (id) => s.readAttempt(id),
        readActivitySince: () => err("audit.read_failed", "disk gone"),
      }),
    });
    const r = await refund(h, A1);
    expect(jsonOf(r)).toEqual({
      decision: "deny",
      ruleId: "firewall.duplicate_check_failed",
      message: expect.any(String) as string,
    });
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
    const a = rows(h).attempts[0];
    expect(a).toMatchObject({
      decision: "deny",
      matchedRules: ["firewall.duplicate_check_failed"],
    });
    expect(rows(h).outcomes[0]).toMatchObject({ attemptId: a?.id, outcome: "denied" });
  });

  it("too many activity rows ⇒ duplicate_check_failed", async () => {
    const h = await setup({ maxActivityRows: 2 });
    for (let i = 0; i < 3; i++) {
      unwrap(
        h.store.recordAttempt({
          sessionId: "seed",
          tool: "create_refund",
          args: { payment_id: `pay_S${String(i)}`, amount: 1 },
          reason: "seed",
          decision: "deny",
          matchedRules: ["x"],
        }),
      );
    }
    expect(jsonOf(await refund(h, A1))["ruleId"]).toBe("firewall.duplicate_check_failed");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });

  it("invalid clock ⇒ duplicate_check_failed", async () => {
    const h = await setup();
    h.clock.broken = true;
    expect(jsonOf(await refund(h, A1))["ruleId"]).toBe("firewall.duplicate_check_failed");
    expect(upstreamCalls(h, "create_refund")).toEqual([]);
  });

  it("args that can't be keyed (unlisted tool, float) ⇒ firewall.invalid_args", async () => {
    const h = await setup();
    const r = await call(h, "create_payment_link", {
      amount: 100,
      currency: "INR",
      description: "x",
      options: { ratio: 1.5 },
    });
    expect(jsonOf(r)["ruleId"]).toBe("firewall.invalid_args");
    // A float inside an excluded free-text field still can't be audited ⇒ denied, not forwarded.
    const n = await call(h, "create_payment_link", {
      amount: 100,
      currency: "INR",
      notes: { ratio: 1.5 },
    });
    expect(n.isError).toBe(true);
    expect(jsonOf(n)["decision"]).toBe("deny");
    expect(upstreamCalls(h, "create_payment_link")).toEqual([]);
  });
});

describe("audit trail", () => {
  it("the duplicate deny is audited (deny + denied, key stored), chain verifies, one read per call", async () => {
    let reads = 0;
    const h = await setup({
      policy: DEFAULT,
      wrapStore: (s) => ({
        recordAttempt: (i) => s.recordAttempt(i),
        recordOutcome: (i) => s.recordOutcome(i),
        recordVerification: (i) => s.recordVerification(i),
        readUnsettled: () => s.readUnsettled(),
        recordApproval: (i) => s.recordApproval(i),
        readAttempt: (id) => s.readAttempt(id),
        readActivitySince: (ms) => {
          reads++;
          return s.readActivitySince(ms);
        },
      }),
    });
    expect((await refund(h, A1)).isError).not.toBe(true);
    // The default policy queries history AND stats: still ONE audit read, shared with the duplicate check.
    expect(reads).toBe(1);
    expectDuplicate(await refund(h, A1), "executed");
    expect(reads).toBe(2);
    const { attempts, outcomes } = rows(h);
    const key = unwrap(idempotencyKey("create_refund", A1));
    expect(attempts).toHaveLength(2);
    expect(attempts[0]).toMatchObject({ decision: "allow", idempotencyKey: key });
    expect(attempts[1]).toMatchObject({
      decision: "deny",
      matchedRules: ["firewall.duplicate"],
      reason: REASON,
      idempotencyKey: key,
    });
    expect(outcomes.find((o) => o.attemptId === attempts[1]?.id)?.outcome).toBe("denied");
    expect(unwrap(h.store.verify()).ok).toBe(true);
  });

  it("the recorded attempt carries idempotencyKey of the FORWARDED (final) args", async () => {
    const h = await setup({ policy: CLAMP });
    await refund(h, { ...A1, notes: { k: "v" } });
    const a = rows(h).attempts[0];
    expect(a?.decision).toBe("transform");
    expect(a?.idempotencyKey).toBe(
      unwrap(idempotencyKey("create_refund", { payment_id: "pay_A1", amount: 1_000 })),
    );
  });
});
