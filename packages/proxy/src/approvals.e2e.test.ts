/**
 * T011 end to end: agent → proxy → money pipeline (`require_approval`) → approval service (SQLite store) → Telegram
 * approver over a FAKE transport (no network) → button press → `executeApproved` → fake upstream; plus the agent's
 * `firewall_check_approval` poll. Every scenario must leave a valid audit chain.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compilePolicy,
  definePolicy,
  rule,
  UNTRUSTED_REASON_LABEL,
  type CompiledPolicy,
  type PolicySpec,
  type Result,
} from "@asf/core";
import {
  ANSWERS,
  createCallbackSigner,
  createFakeTelegramTransport,
  createTelegramApprover,
  openApprovalStore,
  type ApprovalStore,
  type FakeTelegramTransport,
} from "@asf/approvals";
import defaultPolicy from "@asf/policies";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CHECK_APPROVAL_TOOL,
  createApprovalService,
  DECISION_ANSWERS,
  type ApprovalNotifier,
  type ApprovalService,
} from "./approval-service.js";
import { openAuditStore, type AuditStore } from "./audit-store.js";
import { systemClock, systemTimer } from "./context-adapters.js";
import { ATTEMPT_MARKER_KEY, REFUND_LIST_TOOL } from "./failure.js";
import { idempotencyKey } from "./idempotency.js";
import {
  APPROVAL_RULES,
  createFirewallInterceptor,
  createMoneyPipeline,
  type MoneyPipeline,
  type MoneyPipelineOptions,
  type PipelineStore,
} from "./interceptor.js";
import { createModePreCheck, createModeStore, KILL_SWITCH_RULE } from "./modes.js";
import { redactSensitiveResult } from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { createProxyServer, type ProxyServer } from "./server.js";
import { fakeUpstream, hang, jsonOf, type FakeUpstream } from "./test-support/fake-upstream.js";
import { redactSecrets } from "./tool-discovery.js";
import { Upstream, type Redactor } from "./upstream.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const redact: Redactor = (s) => redactSecrets(s, KEYS);
const REASON = "Customer was double charged for this order; refunding the duplicate charge.";
const CHAT = "424242";
const MIN = 60_000;

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
const DEFAULT = compiled(defaultPolicy);

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

interface Payment {
  status: string;
  amount: number;
  amount_refunded: number;
  currency: string;
}

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  store: AuditStore;
  approvalStore: ApprovalStore;
  pipeline: MoneyPipeline;
  service: ApprovalService;
  transport: FakeTelegramTransport;
  payments: Map<string, Payment>;
  refunds: Array<{
    id: string;
    amount: number;
    payment_id: string;
    status: string;
    notes: unknown;
  }>;
  refundHandler: {
    fn?: (args: Record<string, unknown>, s: AbortSignal) => Promise<CallToolResult>;
  };
  now: { ms: number };
  logs: string[];
}

let dir: string;
const open: Harness[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-approvals-e2e-"));
});

afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.service.idle();
    await h.agent.close();
    await h.proxy.close();
    h.pipeline.close();
    await h.upstream.close();
    const v = unwrap(h.store.verify());
    expect(v.ok).toBe(true);
    h.store.close();
    h.approvalStore.close();
  }
  rmSync(dir, { recursive: true, force: true });
});

interface SetupOpts {
  policy?: CompiledPolicy;
  callTimeoutMs?: number;
  notifier?: (inner: ApprovalNotifier, transport: FakeTelegramTransport) => ApprovalNotifier;
  preCheck?: MoneyPipelineOptions["preCheck"];
  wrapStore?: (s: AuditStore) => PipelineStore;
}

async function setup(o: SetupOpts = {}): Promise<Harness> {
  const payments = new Map<string, Payment>([
    ["pay_A1", { status: "captured", amount: 500_000, amount_refunded: 0, currency: "INR" }],
  ]);
  const refunds: Harness["refunds"] = [];
  const refundHandler: Harness["refundHandler"] = {};
  let seq = 0;
  const fake = fakeUpstream({
    tools: TOOLS,
    handler: (name, args, signal) => {
      const a = args ?? {};
      if (name === "fetch_payment") {
        const id = a["payment_id"];
        const p = typeof id === "string" ? payments.get(id) : undefined;
        return Promise.resolve(
          p === undefined
            ? { isError: true, content: [{ type: "text", text: "payment not found" }] }
            : { content: [{ type: "text", text: JSON.stringify({ id, ...p }) }] },
        );
      }
      if (name === REFUND_LIST_TOOL) {
        const items = refunds.filter((r) => r.payment_id === a["payment_id"]);
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({ entity: "collection", count: items.length, items }),
            },
          ],
        });
      }
      if (name === "create_refund") {
        seq++;
        const id = `rfnd_E${String(seq).padStart(7, "0")}`;
        refunds.push({
          id,
          amount: typeof a["amount"] === "number" ? a["amount"] : 0,
          payment_id: typeof a["payment_id"] === "string" ? a["payment_id"] : "",
          status: "processed",
          notes: a["notes"] ?? {},
        });
        if (refundHandler.fn !== undefined) return refundHandler.fn(a, signal);
        return Promise.resolve({
          content: [{ type: "text", text: JSON.stringify({ id, entity: "refund", ...a }) }],
        });
      }
      return Promise.resolve({ content: [{ type: "text", text: JSON.stringify({ id: "x" }) }] });
    },
  });
  const logs: string[] = [];
  const logger = (l: string): void => {
    logs.push(l);
  };
  const upstream = new Upstream({
    factory: fake.factory,
    logger,
    redact,
    sleep: () => Promise.resolve(),
  });
  const store = unwrap(openAuditStore({ path: join(dir, `audit-${String(open.length)}.db`) }));
  const approvalStore = unwrap(
    openApprovalStore({ path: join(dir, `approvals-${String(open.length)}.db`) }),
  );
  const transport = createFakeTelegramTransport();
  const now = { ms: Date.now() };
  const ref: { service?: ApprovalService } = {};
  const approver = createTelegramApprover({
    transport,
    chatId: CHAT,
    store: approvalStore,
    signer: createCallbackSigner(new Uint8Array(32).fill(5)),
    logger,
    onDecision: (d) => {
      if (ref.service === undefined) throw new Error("no service");
      return ref.service.decide(d);
    },
  });
  const service = createApprovalService({
    store: approvalStore,
    notifier: o.notifier === undefined ? approver : o.notifier(approver, transport),
    clock: { nowMs: () => now.ms },
    logger,
  });
  ref.service = service;
  const pipeline = createMoneyPipeline({
    policy: o.policy ?? DEFAULT,
    store: o.wrapStore === undefined ? store : o.wrapStore(store),
    upstream,
    approvals: service,
    clock: systemClock,
    timer: systemTimer,
    redact,
    logger,
    approvalIdOf: (id) => service.approvalIdOf(id),
    ...(o.preCheck === undefined ? {} : { preCheck: o.preCheck }),
  });
  const proxy = createProxyServer({
    upstream,
    interceptor: createFirewallInterceptor(pipeline, { logger }),
    advertise: advertiseTool,
    resultFilter: redactSensitiveResult,
    logger,
    redact,
    sessionId: "sess-test",
    localTools: [service.checkTool],
    ...(o.callTimeoutMs === undefined ? {} : { callTimeoutMs: o.callTimeoutMs }),
  });
  service.attach({ pipeline, openCall: proxy.openDirectCall });
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
    approvalStore,
    pipeline,
    service,
    transport,
    payments,
    refunds,
    refundHandler,
    now,
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

const BIG = { payment_id: "pay_A1", amount: 300_000 };

async function requestApproval(
  h: Harness,
  args: Record<string, unknown> = BIG,
): Promise<{ approvalId: string; attemptId: string }> {
  const r = await call(h, "create_refund", { reason: REASON, ...args });
  expect(r.isError).toBe(false);
  const body = jsonOf(r);
  expect(body).toMatchObject({ decision: "pending_approval" });
  const approvalId = body["approvalId"];
  if (typeof approvalId !== "string") throw new Error("no approval id");
  const row = unwrap(h.approvalStore.get(approvalId));
  if (row === undefined) throw new Error("no approval row");
  return { approvalId, attemptId: row.attemptId };
}

/** Press Approve (0) / Reject (1) on the latest approval message, as the configured chat by default. */
async function press(
  h: Harness,
  which: 0 | 1,
  over: { fromId?: number; chatId?: number; data?: string } = {},
): Promise<string | undefined> {
  const msg = h.transport.sent.at(-1);
  if (msg === undefined) throw new Error("no message");
  await h.transport.press({
    data: over.data ?? msg.buttons[which]?.data,
    fromId: over.fromId ?? Number(CHAT),
    chatId: over.chatId ?? Number(CHAT),
    messageId: msg.messageId,
  });
  // The approver answers at once; execution is tracked by the service.
  await h.service.idle();
  return h.transport.answers.at(-1)?.text;
}

const check = (h: Harness, approvalId: string): Promise<CallToolResult> =>
  call(h, CHECK_APPROVAL_TOOL, { approvalId });

function records(h: Harness, attemptId: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const r of unwrap(h.store.readAll())) {
    if ("invalid" in r) throw new Error("invalid row");
    if (r.id === attemptId || ("attemptId" in r && r.attemptId === attemptId)) {
      out.push(r as unknown as Record<string, unknown>);
    }
  }
  return out;
}

const refundCalls = (h: Harness) => h.fake.calls.filter((c) => c.name === "create_refund");

describe("require_approval ⇒ Telegram request + firewall_check_approval", () => {
  it("advertises firewall_check_approval; the message shows tool, ₹, payment, untrusted reason, rule", async () => {
    const h = await setup();
    const listed = await h.agent.listTools();
    const tool = listed.tools.find((t) => t.name === CHECK_APPROVAL_TOOL);
    expect(tool?.inputSchema.required).toEqual(["approvalId"]);
    expect(tool?.inputSchema.properties?.["reason"]).toBeUndefined();
    const { approvalId } = await requestApproval(h);
    const msg = h.transport.sent[0];
    expect(msg?.chatId).toBe(CHAT);
    expect(msg?.html).toContain("create_refund");
    expect(msg?.html).toContain("₹3,000.00");
    expect(msg?.html).toContain("pay_A1");
    expect(msg?.html).toContain(UNTRUSTED_REASON_LABEL);
    expect(msg?.html).toContain("refund.approval");
    expect(msg?.html).toContain(approvalId);
    expect(msg?.buttons.map((b) => b.text)).toEqual(["Approve", "Reject"]);
    const polled = await check(h, approvalId);
    expect(polled.isError).toBe(false);
    expect(jsonOf(polled)).toMatchObject({ approvalId, status: "pending" });
    expect(refundCalls(h)).toEqual([]);
  });

  it("approve ⇒ executes once via the normal path; approval chained before the outcome; agent sees it", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    expect(await press(h, 0)).toBe(DECISION_ANSWERS.approved);
    const calls = refundCalls(h);
    expect(calls).toHaveLength(1);
    // Exactly the approved args + the firewall's own marker (the asf_* check is not tripped by it).
    expect(calls[0]?.args).toEqual({ ...BIG, notes: { [ATTEMPT_MARKER_KEY]: attemptId } });
    const recs = records(h, attemptId);
    expect(recs.map((r) => r["kind"])).toEqual(["attempt", "approval", "outcome"]);
    expect(recs[1]).toMatchObject({
      decision: "approved",
      approver: `telegram:${CHAT}`,
      approvalId,
    });
    expect(recs[2]).toMatchObject({ outcome: "success", upstreamRef: "rfnd_E0000001" });
    const polled = await check(h, approvalId);
    expect(polled.isError).toBe(false);
    expect(jsonOf(polled)).toMatchObject({
      status: "approved",
      execution: { status: "executed", attemptId, upstreamRef: "rfnd_E0000001" },
    });
    expect(h.transport.edits.at(-1)?.html).toContain("APPROVED");
    expect(h.transport.edits.at(-1)?.html).toContain("executed");
  });

  it("double approve (and approve after reject) executes nothing more", async () => {
    const h = await setup();
    await requestApproval(h);
    await press(h, 0);
    expect(await press(h, 0)).toBe(DECISION_ANSWERS.alreadyDecided);
    expect(await press(h, 1)).toBe(DECISION_ANSWERS.alreadyDecided);
    expect(refundCalls(h)).toHaveLength(1);
  });

  it("concurrent double approve: one execution", async () => {
    const h = await setup();
    await requestApproval(h);
    const msg = h.transport.sent.at(-1);
    const data = msg?.buttons[0]?.data;
    await Promise.all([
      h.transport.press({ data, fromId: 424242, chatId: 424242, messageId: msg?.messageId }),
      h.transport.press({ data, fromId: 424242, chatId: 424242, messageId: msg?.messageId }),
    ]);
    await h.service.idle();
    expect(refundCalls(h)).toHaveLength(1);
  });

  it("reject ⇒ nothing executed, terminal not_forwarded approval.rejected, no longer counts", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    expect(await press(h, 1)).toBe(DECISION_ANSWERS.rejected);
    expect(refundCalls(h)).toEqual([]);
    const recs = records(h, attemptId);
    expect(recs.map((r) => r["kind"])).toEqual(["attempt", "approval", "outcome"]);
    expect(recs[1]).toMatchObject({ decision: "rejected", approver: `telegram:${CHAT}` });
    expect(recs[2]).toMatchObject({ outcome: "not_forwarded", errorCode: "approval.rejected" });
    const polled = await check(h, approvalId);
    expect(polled.isError).toBe(true);
    expect(jsonOf(polled)).toMatchObject({
      decision: "deny",
      ruleId: "approval.rejected",
      status: "rejected",
    });
    // The rejected attempt stops blocking: the same refund can be requested again (needs approval again).
    await requestApproval(h);
  });

  it("expired after the timeout ⇒ treated as rejected (approve too late, sweep, poll)", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    h.now.ms += 31 * MIN; // default policy: 30 min
    expect(await press(h, 0)).toBe(DECISION_ANSWERS.expired);
    expect(refundCalls(h)).toEqual([]);
    const recs = records(h, attemptId);
    expect(recs[1]).toMatchObject({ kind: "approval", decision: "expired" });
    expect(recs[1]?.["approver"]).toBeUndefined();
    expect(recs[2]).toMatchObject({ outcome: "not_forwarded", errorCode: "approval.expired" });
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      ruleId: "approval.expired",
      status: "expired",
    });
    expect(h.transport.edits.at(-1)?.html).toContain("EXPIRED");

    // Sweep and poll expire overdue approvals too.
    const second = await requestApproval(h);
    const third = await requestApproval(h, { payment_id: "pay_A1", amount: 250_000 });
    h.now.ms += 31 * MIN;
    expect(await h.service.sweepExpired()).toBe(2);
    expect(records(h, second.attemptId).at(-1)).toMatchObject({ errorCode: "approval.expired" });
    expect(jsonOf(await check(h, third.approvalId))).toMatchObject({ status: "expired" });
    const fourth = await requestApproval(h, { payment_id: "pay_A1", amount: 260_000 });
    h.now.ms += 31 * MIN;
    expect(jsonOf(await check(h, fourth.approvalId))).toMatchObject({ status: "expired" });
    expect(records(h, fourth.attemptId).at(-1)).toMatchObject({ errorCode: "approval.expired" });
  });

  it("wrong chat / wrong user / forged or tampered callback ⇒ nothing decided", async () => {
    const h = await setup();
    const { approvalId } = await requestApproval(h);
    expect(await press(h, 0, { chatId: 999, fromId: 999 })).toBe(ANSWERS.unauthorised);
    expect(await press(h, 0, { fromId: 999 })).toBe(ANSWERS.unauthorised);
    const approve = h.transport.sent.at(-1)?.buttons[0]?.data ?? "";
    const reject = h.transport.sent.at(-1)?.buttons[1]?.data ?? "";
    expect(await press(h, 0, { data: reject.replace("v1.r.", "v1.a.") })).toBe(ANSWERS.invalid);
    expect(await press(h, 0, { data: `${approve.slice(0, -2)}xx` })).toBe(ANSWERS.invalid);
    const otherRun = createCallbackSigner(new Uint8Array(32).fill(6));
    const nonce = unwrap(h.approvalStore.get(approvalId))?.callbackNonce ?? "";
    expect(await press(h, 0, { data: otherRun.sign("approve", nonce) })).toBe(ANSWERS.invalid);
    expect(refundCalls(h)).toEqual([]);
    expect(jsonOf(await check(h, approvalId))).toMatchObject({ status: "pending" });
  });

  it("the check tool only answers the session that created the approval and validates its input", async () => {
    const h = await setup();
    const { approvalId } = await requestApproval(h);
    const other = await h.service.checkTool.call(
      { approvalId },
      { sessionId: "another-session", signal: new AbortController().signal },
    );
    expect(jsonOf(other)).toMatchObject({ decision: "deny", ruleId: "approval.not_found" });
    expect(jsonOf(await call(h, CHECK_APPROVAL_TOOL, { approvalId: "apr_nope" }))).toMatchObject({
      ruleId: "firewall.invalid_args",
    });
    expect(jsonOf(await call(h, CHECK_APPROVAL_TOOL, { approvalId, extra: 1 }))).toMatchObject({
      ruleId: "firewall.invalid_args",
    });
    expect(jsonOf(await check(h, "apr_00000000-0000-4000-8000-000000000000"))).toMatchObject({
      ruleId: "approval.not_found",
    });
  });

  it("a notification failure ⇒ deny approval_unavailable and the approval can never be approved", async () => {
    const h = await setup();
    h.transport.failSends = true;
    const r = await call(h, "create_refund", { reason: REASON, ...BIG });
    expect(jsonOf(r)).toMatchObject({ ruleId: "firewall.approval_unavailable" });
    const rows = unwrap(h.approvalStore.listPending());
    expect(rows).toEqual([]);
  });

  it("agent notes are kept and the marker added; agent asf_* notes are still refused", async () => {
    const h = await setup();
    const { attemptId } = await requestApproval(h, { ...BIG, notes: { ticket: "T-1" } });
    await press(h, 0);
    expect(refundCalls(h)[0]?.args?.["notes"]).toEqual({
      ticket: "T-1",
      [ATTEMPT_MARKER_KEY]: attemptId,
    });
    const bad = await call(h, "create_refund", {
      reason: REASON,
      payment_id: "pay_A1",
      amount: 210_000,
      notes: { asf_attempt: "forged" },
    });
    expect(jsonOf(bad)).toMatchObject({ ruleId: "firewall.invalid_args" });
  });
});

describe("executeApproved re-checks (fail closed)", () => {
  it("policy now denies on re-evaluation ⇒ not executed, not_forwarded approval.policy_denied", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    // Meanwhile the payment was refunded elsewhere: refund.exceeds_paid now denies.
    const p = h.payments.get("pay_A1");
    if (p !== undefined) p.amount_refunded = 450_000;
    await press(h, 0);
    expect(refundCalls(h)).toEqual([]);
    expect(records(h, attemptId).at(-1)).toMatchObject({
      kind: "outcome",
      outcome: "not_forwarded",
      errorCode: APPROVAL_RULES.policyDenied,
    });
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      decision: "deny",
      ruleId: APPROVAL_RULES.policyDenied,
      execution: { status: "not_executed" },
    });
  });

  it("an engine error on re-evaluation ⇒ deny (fail closed)", async () => {
    let evaluations = 0;
    const policy = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("refund.approval")
            .on("create_refund")
            .when(() => {
              evaluations++;
              if (evaluations > 1) throw new Error("policy bug");
              return true;
            })
            .requireApproval({ via: "telegram", timeoutMin: 5, message: "needs a human" }),
        ],
      }),
    );
    const h = await setup({ policy });
    const { attemptId } = await requestApproval(h);
    await press(h, 0);
    expect(evaluations).toBe(2);
    expect(refundCalls(h)).toEqual([]);
    expect(records(h, attemptId).at(-1)).toMatchObject({
      outcome: "not_forwarded",
      errorCode: APPROVAL_RULES.policyDenied,
    });
  });

  it("re-evaluation requiring a different approval rule ⇒ approval.policy_changed", async () => {
    let n = 0;
    const policy = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("first.approval")
            .on("create_refund")
            .when(() => ++n === 1)
            .requireApproval({ via: "telegram", timeoutMin: 5, message: "a" }),
          rule("second.approval")
            .on("create_refund")
            .requireApproval({ via: "telegram", timeoutMin: 5, message: "b" }),
        ],
      }),
    );
    const h = await setup({ policy });
    const { attemptId } = await requestApproval(h);
    await press(h, 0);
    expect(refundCalls(h)).toEqual([]);
    expect(records(h, attemptId).at(-1)).toMatchObject({
      errorCode: APPROVAL_RULES.policyChanged,
    });
  });

  it("a transform on re-evaluation that changes the args ⇒ approval.args_mismatch", async () => {
    let n = 0;
    const policy = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("refund.shrink")
            .on("create_refund")
            .when(() => ++n > 1)
            .transform((ctx) => ({ ...ctx.args, amount: 100_000 })),
          rule("refund.approval")
            .on("create_refund")
            .requireApproval({ via: "telegram", timeoutMin: 5, message: "a" }),
        ],
      }),
    );
    const h = await setup({ policy });
    const { attemptId } = await requestApproval(h);
    await press(h, 0);
    expect(refundCalls(h)).toEqual([]);
    expect(records(h, attemptId).at(-1)).toMatchObject({
      errorCode: APPROVAL_RULES.argsMismatch,
    });
  });

  it("argsHash / finalArgs mismatch, wrong tool or session ⇒ approval.args_mismatch, nothing sent", async () => {
    const h = await setup();
    const cases: Array<
      (
        r: Parameters<MoneyPipeline["executeApproved"]>[0],
      ) => Parameters<MoneyPipeline["executeApproved"]>[0]
    > = [
      (r) => ({ ...r, argsHash: "0".repeat(64) }),
      (r) => ({ ...r, finalArgs: { ...r.finalArgs, amount: 300_001 } }),
      (r) => ({ ...r, sessionId: "someone-else" }),
      (r) => ({ ...r, tool: "update_refund" }),
    ];
    for (const [i, mutate] of cases.entries()) {
      const { approvalId, attemptId } = await requestApproval(h, {
        payment_id: "pay_A1",
        amount: 210_000 + i,
      });
      const row = unwrap(h.approvalStore.get(approvalId));
      if (row === undefined) throw new Error("row");
      const base = {
        approvalId,
        attemptId,
        argsHash: row.argsHash,
        tool: "create_refund",
        finalArgs: { payment_id: "pay_A1", amount: 210_000 + i },
        untrustedReason: REASON,
        sessionId: "sess-test",
        ruleId: "refund.approval",
        approver: "telegram:1",
      };
      const res = await h.pipeline.executeApproved(mutate(base), h.proxy.openDirectCall);
      expect(res).toMatchObject({ status: "not_executed", code: APPROVAL_RULES.argsMismatch });
      expect(records(h, attemptId).at(-1)).toMatchObject({
        outcome: "not_forwarded",
        errorCode: APPROVAL_RULES.argsMismatch,
      });
    }
    expect(refundCalls(h)).toEqual([]);
  });

  it("executing an already-closed attempt is refused without writing anything", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    await press(h, 1); // rejected and closed
    const row = unwrap(h.approvalStore.get(approvalId));
    if (row === undefined) throw new Error("row");
    const before = unwrap(h.store.readAll()).length;
    const res = await h.pipeline.executeApproved(
      {
        approvalId,
        attemptId,
        argsHash: row.argsHash,
        tool: "create_refund",
        finalArgs: BIG,
        untrustedReason: REASON,
        sessionId: "sess-test",
        ruleId: "refund.approval",
        approver: "telegram:1",
      },
      h.proxy.openDirectCall,
    );
    expect(res).toMatchObject({ status: "not_executed", code: "audit.invalid_approval" });
    expect(unwrap(h.store.readAll())).toHaveLength(before);
    expect(refundCalls(h)).toEqual([]);
  });

  it("an identical refund executed meanwhile ⇒ firewall.duplicate (the approved attempt excludes only itself)", async () => {
    const h = await setup();
    const { attemptId } = await requestApproval(h);
    // Another (already closed) identical refund lands in the audit log while the approval waits.
    const other = unwrap(
      h.store.recordAttempt({
        sessionId: "sess-other",
        tool: "create_refund",
        args: BIG,
        reason: REASON,
        decision: "allow",
        matchedRules: ["refund.allow"],
        idempotencyKey: unwrap(idempotencyKey("create_refund", BIG)),
      }),
    );
    unwrap(
      h.store.recordOutcome({
        attemptId: other.id,
        outcome: "success",
        latencyMs: 1,
        upstreamRef: "rfnd_OTHER0001",
      }),
    );
    await press(h, 0);
    expect(refundCalls(h)).toEqual([]);
    expect(records(h, attemptId).at(-1)).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "firewall.duplicate",
    });
  });

  it("a second identical request while one awaits approval is a duplicate; approving the first executes it", async () => {
    const h = await setup();
    const first = await requestApproval(h);
    const again = await call(h, "create_refund", { reason: REASON, ...BIG });
    expect(jsonOf(again)).toMatchObject({
      ruleId: "firewall.duplicate",
      duplicateOf: { attemptId: first.attemptId, status: "pending_approval" },
    });
    await press(h, 0);
    expect(refundCalls(h)).toHaveLength(1);
    expect(records(h, first.attemptId).at(-1)).toMatchObject({ outcome: "success" });
  });

  it("upstream timeout on the approved send ⇒ verified via the notes marker (T010), never blindly retried", async () => {
    const h = await setup({ callTimeoutMs: 80 });
    h.refundHandler.fn = (_a, signal) => hang(signal);
    const { approvalId, attemptId } = await requestApproval(h);
    await press(h, 0);
    expect(refundCalls(h)).toHaveLength(1);
    const recs = records(h, attemptId);
    expect(recs.map((r) => r["kind"])).toEqual(["attempt", "approval", "outcome", "verification"]);
    expect(recs[2]).toMatchObject({ outcome: "timeout" });
    expect(recs[3]).toMatchObject({ result: "happened", method: "refund_notes_marker" });
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      execution: { status: "executed", upstreamRef: "rfnd_E0000001" },
    });
  });

  it("upstream unreachable at execution ⇒ not executed, closed not_forwarded", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    await h.upstream.close();
    await press(h, 0);
    // The INR invariant's payment lookup fails first (fail closed).
    expect(records(h, attemptId).at(-1)).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "firewall.payment_lookup_failed",
    });
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      execution: { status: "not_executed" },
    });
  });

  it("no direct call available (tool gone from the live list) ⇒ upstream.unavailable, nothing sent", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    const row = unwrap(h.approvalStore.get(approvalId));
    if (row === undefined) throw new Error("row");
    const res = await h.pipeline.executeApproved(
      {
        approvalId,
        attemptId,
        argsHash: row.argsHash,
        tool: "create_refund",
        finalArgs: BIG,
        untrustedReason: REASON,
        sessionId: "sess-test",
        ruleId: "refund.approval",
        approver: "telegram:1",
      },
      () => Promise.resolve({ ok: false, error: { code: "firewall.unknown_tool", message: "x" } }),
    );
    expect(res).toMatchObject({ status: "not_executed", code: "upstream.unavailable" });
    expect(records(h, attemptId).at(-1)).toMatchObject({ errorCode: "upstream.unavailable" });
    expect(refundCalls(h)).toEqual([]);
  });
});

describe("audit failures around approvals (fail closed)", () => {
  function failing(which: "recordApproval" | "recordOutcome", code: string, after = 0) {
    return (s: AuditStore): PipelineStore => {
      let n = 0;
      return {
        recordAttempt: (i) => s.recordAttempt(i),
        recordOutcome: (i) =>
          which === "recordOutcome" && i.errorCode?.startsWith("approval.") === true && n++ >= after
            ? { ok: false, error: { code, message: "injected" } }
            : s.recordOutcome(i),
        readActivitySince: (ms) => s.readActivitySince(ms),
        recordVerification: (i) => s.recordVerification(i),
        readUnsettled: () => s.readUnsettled(),
        recordApproval: (i) =>
          which === "recordApproval"
            ? { ok: false, error: { code, message: "injected" } }
            : s.recordApproval(i),
        readAttempt: (id) => s.readAttempt(id),
      };
    };
  }

  it("the approval can't be chained ⇒ nothing executed and the pipeline latches degraded", async () => {
    const h = await setup({ wrapStore: failing("recordApproval", "audit.write_failed") });
    const { approvalId } = await requestApproval(h);
    await press(h, 0);
    expect(refundCalls(h)).toEqual([]);
    expect(h.pipeline.isDegraded()).toBe(true);
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      execution: { status: "not_executed" },
      ruleId: "audit_unavailable",
    });
    // Later money calls are denied.
    const r = await call(h, "create_refund", { reason: REASON, payment_id: "pay_A1", amount: 100 });
    expect(jsonOf(r)).toMatchObject({ ruleId: "audit_unavailable" });
  });

  it("a rejection whose outcome can't be written latches degraded", async () => {
    const h = await setup({ wrapStore: failing("recordOutcome", "audit.write_failed") });
    await requestApproval(h);
    await press(h, 1);
    expect(h.pipeline.isDegraded()).toBe(true);
    expect(refundCalls(h)).toEqual([]);
  });
});

describe("security review regressions (T011)", () => {
  it("M1: notification errors after delivery and the human approves meanwhile ⇒ pending, executed once, audit consistent", async () => {
    const h = await setup({
      notifier: (inner, transport) => ({
        showResolution: (row) => inner.showResolution(row),
        notify: async (n, nonce) => {
          const sent = await inner.notify(n, nonce);
          if (!sent.ok) return sent;
          const msg = transport.sent.at(-1);
          // The human taps Approve before Telegram's (late) error reaches the firewall.
          await transport.press({
            data: msg?.buttons[0]?.data,
            fromId: 424242,
            chatId: 424242,
            messageId: msg?.messageId,
          });
          return { ok: false, error: { code: "telegram.send_failed", message: "timeout" } };
        },
      }),
    });
    const { approvalId, attemptId } = await requestApproval(h);
    await h.service.idle();
    expect(refundCalls(h)).toHaveLength(1);
    expect(records(h, attemptId).map((r) => r["kind"])).toEqual(["attempt", "approval", "outcome"]);
    expect(records(h, attemptId).at(-1)).toMatchObject({ outcome: "success" });
    expect(h.pipeline.isDegraded()).toBe(false);
    expect(jsonOf(await check(h, approvalId))).toMatchObject({ execution: { status: "executed" } });
  });

  it("M1: an attempt closed meanwhile is never sent (re-read right before forward)", async () => {
    let reads = 0;
    const h = await setup({
      wrapStore: (s) => ({
        recordAttempt: (i) => s.recordAttempt(i),
        recordOutcome: (i) => s.recordOutcome(i),
        readActivitySince: (ms) => s.readActivitySince(ms),
        recordVerification: (i) => s.recordVerification(i),
        readUnsettled: () => s.readUnsettled(),
        recordApproval: (i) => s.recordApproval(i),
        readAttempt: (id) => {
          const r = s.readAttempt(id);
          reads++;
          if (reads < 2 || !r.ok || r.value === undefined) return r;
          // Simulate another writer closing the attempt after the binding checks.
          return {
            ok: true,
            value: {
              ...r.value,
              outcome: {
                kind: "outcome",
                id: "o-x",
                attemptId: id,
                ts: new Date().toISOString(),
                outcome: "not_forwarded",
                errorCode: "approval.unavailable",
                latencyMs: 0,
                seq: 999,
                prevHash: "0".repeat(64),
                hash: "0".repeat(64),
              },
            },
          };
        },
      }),
    });
    const { approvalId, attemptId } = await requestApproval(h);
    await press(h, 0);
    expect(refundCalls(h)).toEqual([]);
    expect(records(h, attemptId).at(-1)).toMatchObject({ kind: "approval" });
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      ruleId: APPROVAL_RULES.attemptClosed,
    });
  });

  it("M2: the pre-check (kill switch) runs for approved actions; deny or throw ⇒ not executed", async () => {
    const mode: { value: "off" | "deny" | "throw" } = { value: "off" };
    const h = await setup({
      preCheck: () => {
        if (mode.value === "throw") throw new Error("kill switch store down");
        return mode.value === "deny"
          ? { ruleId: "firewall.kill_switch", message: "money actions are paused" }
          : undefined;
      },
    });
    const first = await requestApproval(h);
    const second = await requestApproval(h, { payment_id: "pay_A1", amount: 250_000 });
    mode.value = "deny";
    await press(h, 0); // latest message = second
    expect(records(h, second.attemptId).at(-1)).toMatchObject({
      outcome: "not_forwarded",
      errorCode: "firewall.kill_switch",
    });
    mode.value = "throw";
    const row = unwrap(h.approvalStore.get(first.approvalId));
    if (row === undefined) throw new Error("row");
    const res = await h.pipeline.executeApproved(
      {
        approvalId: first.approvalId,
        attemptId: first.attemptId,
        argsHash: row.argsHash,
        tool: "create_refund",
        finalArgs: BIG,
        untrustedReason: REASON,
        sessionId: "sess-test",
        ruleId: "refund.approval",
        approver: "telegram:1",
      },
      h.proxy.openDirectCall,
    );
    expect(res).toMatchObject({ status: "not_executed", code: "firewall.internal_error" });
    expect(refundCalls(h)).toEqual([]);
  });

  it("L4: status comes from the firewall's settle result, not upstream JSON (a tool error claiming forwarded:false)", async () => {
    const h = await setup();
    // Razorpay applies the refund but answers with an error body that mimics a firewall "not sent" body.
    h.refundHandler.fn = () =>
      Promise.resolve({
        isError: true,
        content: [{ type: "text", text: JSON.stringify({ error: "x", forwarded: false }) }],
      });
    const { approvalId } = await requestApproval(h);
    await press(h, 0);
    // Verified through the notes marker: it DID execute.
    expect(jsonOf(await check(h, approvalId))).toMatchObject({
      execution: { status: "executed", upstreamRef: "rfnd_E0000001" },
    });
  });
});

describe("restart", () => {
  it("pending approvals of an earlier run are expired (store + audit) and their buttons are dead", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    // Simulate a restart: a new service + pipeline over the same DBs.
    const service2 = createApprovalService({
      store: h.approvalStore,
      notifier: {
        notify: () =>
          Promise.resolve(unwrap({ ok: true, value: { messageId: 1 } })).then((v) => ({
            ok: true as const,
            value: v,
          })),
        showResolution: () => Promise.resolve({ ok: true as const, value: null }),
      },
      clock: { nowMs: () => h.now.ms },
    });
    expect(unwrap(service2.expireStale())).toBe(1);
    const pipeline2 = createMoneyPipeline({
      policy: DEFAULT,
      store: h.store,
      upstream: h.upstream,
      approvals: service2,
      clock: systemClock,
      timer: systemTimer,
      approvalIdOf: (id) => service2.approvalIdOf(id),
      startReconciling: true,
    });
    const summary = unwrap(await pipeline2.reconcile());
    pipeline2.close();
    expect(summary.approvalsClosed).toBe(1);
    expect(records(h, attemptId).slice(1)).toEqual([
      expect.objectContaining({ kind: "approval", decision: "expired", approvalId }),
      expect.objectContaining({ outcome: "not_forwarded", errorCode: "approval.expired" }),
    ]);
    // An old button press can't approve it any more.
    expect(await press(h, 0)).toBe(DECISION_ANSWERS.alreadyDecided);
    expect(refundCalls(h)).toEqual([]);
  });
});

describe("T012: kill switch and pending approvals", () => {
  it("Approve pressed while the kill switch is ON ⇒ not executed (not_forwarded kill-switch), even after it is turned off", async () => {
    // A second connection to the same audit DB: the operator's CLI (and the mode reader).
    const cliStore = unwrap(openAuditStore({ path: join(dir, `audit-${String(open.length)}.db`) }));
    try {
      const cli = createModeStore(cliStore);
      const h = await setup({ preCheck: createModePreCheck(cli) });
      const { approvalId, attemptId } = await requestApproval(h);
      unwrap(cli.set({ killSwitch: true, actor: "cli:ops" }));
      await press(h, 0);
      expect(refundCalls(h)).toEqual([]);
      const recs = records(h, attemptId);
      expect(recs.map((r) => r["kind"])).toEqual(["attempt", "approval", "outcome"]);
      expect(recs[1]).toMatchObject({ decision: "approved", approver: `telegram:${CHAT}` });
      expect(recs[2]).toMatchObject({ outcome: "not_forwarded", errorCode: KILL_SWITCH_RULE });
      const polled = await check(h, approvalId);
      expect(polled.isError).toBe(true);
      expect(jsonOf(polled)).toMatchObject({ ruleId: KILL_SWITCH_RULE });
      // Turning the kill switch off does not resurrect it.
      unwrap(cli.set({ killSwitch: false, actor: "cli:ops" }));
      expect(jsonOf(await check(h, approvalId))).toMatchObject({ ruleId: KILL_SWITCH_RULE });
      expect(refundCalls(h)).toEqual([]);
      // New live calls go through the policy again.
      const next = await call(h, "create_refund", {
        reason: REASON,
        payment_id: "pay_A1",
        amount: 1_000,
      });
      expect(next.isError).not.toBe(true);
      expect(refundCalls(h)).toHaveLength(1);
    } finally {
      cliStore.close();
    }
  });

  it("shadow mode does not shadow an approved execution: the re-evaluation still enforces the policy", async () => {
    const cliStore = unwrap(openAuditStore({ path: join(dir, `audit-${String(open.length)}.db`) }));
    try {
      const cli = createModeStore(cliStore);
      const h = await setup({ preCheck: createModePreCheck(cli) });
      const { attemptId } = await requestApproval(h);
      unwrap(cli.set({ shadow: true, actor: "cli:ops" }));
      await press(h, 0);
      // Executed as the approved (non-shadow) action it is.
      expect(refundCalls(h)).toHaveLength(1);
      const recs = records(h, attemptId);
      expect(recs[0]).toMatchObject({ decision: "require_approval" });
      expect(recs[0]).not.toHaveProperty("shadow");
      expect(recs.at(-1)).toMatchObject({ kind: "outcome", outcome: "success" });
    } finally {
      cliStore.close();
    }
  });
});
