/**
 * T013 end to end: agent → proxy → money pipeline (`require_approval`) → approval service → dashboard API
 * (`@asf/api` over `createApiPorts`) → `decide()` → `executeApproved` → fake upstream. Same path as a Telegram press;
 * every scenario must leave a valid audit chain.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compilePolicy, type Result } from "@asf/core";
import {
  createCallbackSigner,
  createFakeTelegramTransport,
  createTelegramApprover,
  openApprovalStore,
  type ApprovalStore,
  type FakeTelegramTransport,
} from "@asf/approvals";
import { ADMIN_TOKEN_HEADER, createApi, type Api } from "@asf/api";
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
  approvalsPortOf,
  createApiPorts,
  dashboardOnlyNotifier,
  decisionStatusOf,
} from "./api-wiring.js";
import {
  createApprovalService,
  DECISION_ANSWERS,
  type ApprovalService,
} from "./approval-service.js";
import { openAuditStore, type AuditStore } from "./audit-store.js";
import { systemClock, systemTimer } from "./context-adapters.js";
import { REFUND_LIST_TOOL } from "./failure.js";
import {
  createFirewallInterceptor,
  createMoneyPipeline,
  type MoneyPipeline,
} from "./interceptor.js";
import { createModePreCheck, createModeStore } from "./modes.js";
import { redactSensitiveResult } from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { createProxyServer, type ProxyServer } from "./server.js";
import { fakeUpstream, jsonOf, type FakeUpstream } from "./test-support/fake-upstream.js";
import { redactSecrets } from "./tool-discovery.js";
import { Upstream } from "./upstream.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const REASON = "Customer was double charged for this order; refunding the duplicate charge.";
const TOKEN = "a".repeat(48);
const PORT = 8787;
const HOST = `127.0.0.1:${String(PORT)}`;
const CHAT = "424242";
const here = dirname(fileURLToPath(import.meta.url));
const TOOLS = (
  JSON.parse(readFileSync(resolve(here, "../../../docs/razorpay-tools.json"), "utf8")) as {
    tools: Tool[];
  }
).tools;

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}
const POLICY = unwrap(compilePolicy(defaultPolicy));

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  store: AuditStore;
  approvalStore: ApprovalStore;
  pipeline: MoneyPipeline;
  service: ApprovalService;
  api: Api;
  transport?: FakeTelegramTransport;
  req(path: string, method?: string, body?: unknown): Promise<Response>;
}

let dir: string;
const open: Harness[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-api-e2e-"));
});

afterEach(async () => {
  for (const h of open.splice(0)) {
    h.api.close();
    await h.service.idle();
    await h.agent.close();
    await h.proxy.close();
    h.pipeline.close();
    await h.upstream.close();
    expect(unwrap(h.store.verify()).ok).toBe(true);
    h.store.close();
    h.approvalStore.close();
  }
  rmSync(dir, { recursive: true, force: true });
});

async function setup(o: { telegram?: boolean; approvalsEnabled?: boolean } = {}): Promise<Harness> {
  let seq = 0;
  const refunds: Array<{ payment_id: string; notes: unknown; id: string; amount: number }> = [];
  const fake = fakeUpstream({
    tools: TOOLS,
    handler: (name, args) => {
      const a = args ?? {};
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
        const id = `rfnd_D${String(seq).padStart(7, "0")}`;
        refunds.push({
          id,
          payment_id: String(a["payment_id"]),
          amount: Number(a["amount"]),
          notes: a["notes"] ?? {},
        });
        return Promise.resolve({
          content: [{ type: "text", text: JSON.stringify({ id, entity: "refund", ...a }) }],
        });
      }
      return Promise.resolve({ content: [{ type: "text", text: "{}" }] });
    },
  });
  const logger = (): void => undefined;
  const redact = (s: string): string => redactSecrets(s, KEYS);
  const upstream = new Upstream({
    factory: fake.factory,
    logger,
    redact,
    sleep: () => Promise.resolve(),
  });
  const dbPath = join(dir, `audit-${String(open.length)}.db`);
  const store = unwrap(openAuditStore({ path: dbPath }));
  const approvalStore = unwrap(
    openApprovalStore({ path: join(dir, `approvals-${String(open.length)}.db`) }),
  );
  const modes = createModeStore(store);
  const ref: { service?: ApprovalService } = {};
  let transport: FakeTelegramTransport | undefined;
  let notifier = dashboardOnlyNotifier;
  if (o.telegram === true) {
    transport = createFakeTelegramTransport();
    notifier = createTelegramApprover({
      transport,
      chatId: CHAT,
      store: approvalStore,
      signer: createCallbackSigner(new Uint8Array(32).fill(7)),
      logger,
      onDecision: (d) => {
        if (ref.service === undefined) throw new Error("no service");
        return ref.service.decide(d);
      },
    });
  }
  const service = createApprovalService({
    store: approvalStore,
    notifier,
    clock: systemClock,
    logger,
  });
  ref.service = service;
  const pipeline = createMoneyPipeline({
    policy: POLICY,
    store,
    upstream,
    approvals: service,
    approvalIdOf: (id) => service.approvalIdOf(id),
    clock: systemClock,
    timer: systemTimer,
    redact,
    logger,
    preCheck: createModePreCheck(modes),
  });
  const proxy = createProxyServer({
    upstream,
    interceptor: createFirewallInterceptor(pipeline, { logger }),
    advertise: advertiseTool,
    resultFilter: redactSensitiveResult,
    logger,
    redact,
    sessionId: "sess-api",
    localTools: [service.checkTool],
  });
  service.attach({ pipeline, openCall: proxy.openDirectCall });
  await upstream.connect();
  const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);
  const agent = new Client({ name: "agent", version: "0" }, { capabilities: {} });
  await agent.connect(agentSide);
  const api = createApi({
    ...createApiPorts({ audit: store, modes, approvals: { service, store: approvalStore } }),
    adminToken: TOKEN,
    approvalsEnabled: o.approvalsEnabled ?? true,
    port: PORT,
  });
  const req = async (path: string, method = "GET", body?: unknown): Promise<Response> =>
    api.app.request(`http://${HOST}${path}`, {
      method,
      headers: { host: HOST, [ADMIN_TOKEN_HEADER]: TOKEN, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const h: Harness = {
    agent,
    fake,
    upstream,
    proxy,
    store,
    approvalStore,
    pipeline,
    service,
    api,
    req,
    ...(transport === undefined ? {} : { transport }),
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

async function requestApproval(h: Harness): Promise<{ approvalId: string; attemptId: string }> {
  const r = await call(h, "create_refund", {
    reason: REASON,
    payment_id: "pay_A1",
    amount: 300_000,
  });
  const body = jsonOf(r);
  expect(body).toMatchObject({ decision: "pending_approval" });
  const approvalId = String(body["approvalId"]);
  const row = unwrap(h.approvalStore.get(approvalId));
  if (row === undefined) throw new Error("no row");
  return { approvalId, attemptId: row.attemptId };
}

const refundCalls = (h: Harness) => h.fake.calls.filter((c) => c.name === "create_refund");

function recordsOf(h: Harness, attemptId: string): Array<Record<string, unknown>> {
  return unwrap(h.store.readAll())
    .filter(
      (r) =>
        !("invalid" in r) &&
        (r.id === attemptId || ("attemptId" in r && r.attemptId === attemptId)),
    )
    .map((r) => r as unknown as Record<string, unknown>);
}

async function json(r: Response): Promise<Record<string, unknown>> {
  return (await r.json()) as Record<string, unknown>;
}

describe("dashboard API over the real approval service", () => {
  it("GET /approvals lists the pending request (redacted, untrusted reason); approve executes once via decide()", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    const list = (await json(await h.req("/approvals?status=pending")))["approvals"] as Array<
      Record<string, unknown>
    >;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      approvalId,
      attemptId,
      tool: "create_refund",
      ruleId: "refund.approval",
      amountPaise: 300_000,
      reason: { untrusted: true },
    });
    expect(JSON.stringify(list)).not.toContain("callbackNonce");

    const r = await h.req(`/approvals/${approvalId}/approve`, "POST", { actor: "ops" });
    expect(r.status).toBe(200);
    await h.service.idle();
    expect(refundCalls(h)).toHaveLength(1);
    const recs = recordsOf(h, attemptId);
    expect(recs.map((x) => x["kind"])).toEqual(["attempt", "approval", "outcome"]);
    expect(recs[1]).toMatchObject({ decision: "approved", approver: "dashboard:ops", approvalId });
    expect(recs[2]).toMatchObject({ outcome: "success" });
    expect(unwrap(h.approvalStore.get(approvalId))?.decidedBy).toBe("dashboard:ops");
    expect((await json(await h.req("/approvals")))["approvals"]).toEqual([]);
  });

  it("double approve via the API (sequential and concurrent): one execution, the loser gets 409", async () => {
    const h = await setup();
    const { approvalId } = await requestApproval(h);
    const [a, b] = await Promise.all([
      h.req(`/approvals/${approvalId}/approve`, "POST", {}),
      h.req(`/approvals/${approvalId}/approve`, "POST", {}),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    const again = await h.req(`/approvals/${approvalId}/reject`, "POST", {});
    expect(again.status).toBe(409);
    expect(((await json(again))["error"] as { code: string }).code).toBe(
      "approval.already_decided",
    );
    await h.service.idle();
    expect(refundCalls(h)).toHaveLength(1);
  });

  it("API approve then a Telegram press: the button is single-use too", async () => {
    const h = await setup({ telegram: true });
    const { approvalId } = await requestApproval(h);
    expect((await h.req(`/approvals/${approvalId}/approve`, "POST", {})).status).toBe(200);
    const msg = h.transport?.sent.at(-1);
    await h.transport?.press({
      data: msg?.buttons[0]?.data,
      fromId: Number(CHAT),
      chatId: Number(CHAT),
      messageId: msg?.messageId,
    });
    await h.service.idle();
    expect(h.transport?.answers.at(-1)?.text).toBe(DECISION_ANSWERS.alreadyDecided);
    expect(refundCalls(h)).toHaveLength(1);
  });

  it("reject via the API ⇒ nothing executed, terminal not_forwarded approval.rejected", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    expect((await h.req(`/approvals/${approvalId}/reject`, "POST", {})).status).toBe(200);
    await h.service.idle();
    expect(refundCalls(h)).toEqual([]);
    const recs = recordsOf(h, attemptId);
    expect(recs[1]).toMatchObject({ decision: "rejected", approver: "dashboard:admin" });
    expect(recs[2]).toMatchObject({ outcome: "not_forwarded", errorCode: "approval.rejected" });
  });

  it("L3: approve while the kill switch is ON ⇒ 409 kill-switch, approval NOT consumed; after kill off it executes", async () => {
    const h = await setup();
    const { approvalId, attemptId } = await requestApproval(h);
    const k = await h.req("/killswitch", "POST", { on: true, actor: "ops" });
    expect(k.status).toBe(200);
    expect(await json(k)).toMatchObject({
      changed: true,
      mode: { killSwitch: true, actor: "dashboard:ops" },
    });
    const r = await h.req(`/approvals/${approvalId}/approve`, "POST", {});
    expect(r.status).toBe(409);
    expect(((await json(r))["error"] as { code: string }).code).toBe("kill-switch");
    expect(unwrap(h.approvalStore.get(approvalId))?.state).toBe("pending");
    expect(recordsOf(h, attemptId).map((x) => x["kind"])).toEqual(["attempt"]);
    expect((await h.req("/killswitch", "POST", { on: false })).status).toBe(200);
    expect((await h.req(`/approvals/${approvalId}/approve`, "POST", {})).status).toBe(200);
    await h.service.idle();
    expect(refundCalls(h)).toHaveLength(1);
  });

  it("M1/M2: without ASF_API_APPROVALS the API can't approve (403), even with Telegram configured; Telegram still can", async () => {
    const h = await setup({ telegram: true, approvalsEnabled: false });
    const { approvalId } = await requestApproval(h);
    const r = await h.req(`/approvals/${approvalId}/approve`, "POST", {});
    expect(r.status).toBe(403);
    expect(((await json(r))["error"] as { code: string }).code).toBe("api.approvals_disabled");
    expect(((await json(await h.req("/approvals")))["approvals"] as unknown[]).length).toBe(1);
    expect(unwrap(h.approvalStore.get(approvalId))?.state).toBe("pending");
    const msg = h.transport?.sent.at(-1);
    await h.transport?.press({
      data: msg?.buttons[0]?.data,
      fromId: Number(CHAT),
      chatId: Number(CHAT),
      messageId: msg?.messageId,
    });
    await h.service.idle();
    expect(refundCalls(h)).toHaveLength(1);
  });

  it("unknown approval id ⇒ 404; mode routes write chained mode records", async () => {
    const h = await setup();
    const r = await h.req(
      "/approvals/apr_00000000-0000-4000-8000-000000000000/approve",
      "POST",
      {},
    );
    expect(r.status).toBe(404);
    expect((await h.req("/mode", "POST", { mode: "shadow" })).status).toBe(200);
    expect(await json(await h.req("/mode"))).toMatchObject({
      mode: { shadow: true, actor: "dashboard:admin" },
    });
    const audit = (await json(await h.req("/audit?limit=1")))["records"] as Array<
      Record<string, unknown>
    >;
    expect(audit[0]).toMatchObject({
      kind: "mode",
      shadow: true,
      killSwitch: false,
      actor: "dashboard:admin",
    });
    expect(await json(await h.req("/audit/verify"))).toMatchObject({ ok: true });
  });

  it("session timeline and audit page come from the real store", async () => {
    const h = await setup();
    const { attemptId } = await requestApproval(h);
    const s = await json(await h.req("/sessions/sess-api"));
    const recs = s["records"] as Array<Record<string, unknown>>;
    expect(recs[0]).toMatchObject({
      kind: "attempt",
      id: attemptId,
      decision: "require_approval",
      amountPaise: 300_000,
    });
    expect(JSON.stringify(recs)).not.toContain('"reason":"');
    expect((await json(await h.req("/sessions/other")))["records"]).toEqual([]);
  });
});

describe("api-wiring adapters", () => {
  it("decisionStatusOf maps the fixed answers", () => {
    expect(decisionStatusOf(DECISION_ANSWERS.approved, "approved")).toBe("approved");
    expect(decisionStatusOf(DECISION_ANSWERS.rejected, "rejected")).toBe("rejected");
    expect(decisionStatusOf(DECISION_ANSWERS.approved, "rejected")).toBe("unavailable");
    expect(decisionStatusOf(DECISION_ANSWERS.expired, "approved")).toBe("expired");
    expect(decisionStatusOf(DECISION_ANSWERS.alreadyDecided, "approved")).toBe("already_decided");
    expect(decisionStatusOf(DECISION_ANSWERS.unavailable, "approved")).toBe("unavailable");
    expect(decisionStatusOf("something else", "approved")).toBe("unavailable");
  });

  it("store errors and throws become unavailable, never a decision", async () => {
    const calls: string[] = [];
    const service = {
      decide: () => {
        calls.push("decide");
        return Promise.reject(new Error("x"));
      },
    };
    const failing = approvalsPortOf(service, {
      get: () => ({ ok: false, error: { code: "approval.read_failed", message: "x" } }),
      listPending: () => {
        throw new Error("boom");
      },
    });
    expect(
      await failing.decide({ approvalId: "apr_x", decision: "approved", approver: "dashboard:a" }),
    ).toBe("unavailable");
    expect(calls).toEqual([]);
    expect(failing.listPending(1).ok).toBe(false);
    const throwing = approvalsPortOf(service, {
      get: () => ({ ok: true, value: { approvalId: "apr_x" } as never }),
      listPending: () => ({ ok: true, value: [] }),
    });
    expect(
      await throwing.decide({ approvalId: "apr_x", decision: "approved", approver: "dashboard:a" }),
    ).toBe("unavailable");
  });
});
