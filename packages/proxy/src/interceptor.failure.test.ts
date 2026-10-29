/**
 * T010 end to end: agent → proxy server → money pipeline → `Upstream` → scripted raw JSON-RPC upstream that answers
 * late and ignores cancellation. Short real timeouts (tens of ms) for the money call; every longer wait uses an
 * injected timer, so the suite stays fast and deterministic.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compilePolicy,
  definePolicy,
  rule,
  type CompiledPolicy,
  type PolicySpec,
  type Result,
  type Timer,
} from "@asf/core";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createInMemoryApprovalStub } from "./approval-port.js";
import {
  openAuditStore,
  type AuditAttemptRecord,
  type AuditOutcomeRecord,
  type AuditStore,
  type AuditVerificationRecord,
} from "./audit-store.js";
import { createStatsPort, systemClock, systemTimer } from "./context-adapters.js";
import { ATTEMPT_MARKER_KEY, REFUND_LIST_TOOL } from "./failure.js";
import { DUPLICATE_MESSAGES, idempotencyKey } from "./idempotency.js";
import {
  createFirewallInterceptor,
  createMoneyPipeline,
  NOT_RETRIED_MESSAGE,
  RECONCILING_MESSAGE,
  type MoneyPipeline,
  type MoneyPipelineOptions,
} from "./interceptor.js";
import { createModePreCheck, createModeStore, KILL_SWITCH_RULE } from "./modes.js";
import {
  redactSensitiveResult,
  UNKNOWN_OUTCOME_MESSAGE,
  VERIFIED_AFTER_TIMEOUT_MESSAGE,
  VERIFIED_AFTER_TIMEOUT_PENDING_MESSAGE,
} from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { createProxyServer, type ProxyServer } from "./server.js";
import {
  jsonOf,
  scriptedUpstream,
  type ScriptedReply,
  type ScriptedUpstream,
} from "./test-support/fake-upstream.js";
import { Upstream, type LateResponse } from "./upstream.js";

const here = dirname(fileURLToPath(import.meta.url));
const TOOLS = (
  JSON.parse(readFileSync(resolve(here, "../../../docs/razorpay-tools.json"), "utf8")) as {
    tools: Tool[];
  }
).tools;
const REASON = "Customer cust_123 was double charged for order_456; refunding it.";
const PAY = "pay_FAILabcdef";
const A1 = { payment_id: PAY, amount: 5_000 };
/** Razorpay's API error envelope: the only text that proves a rejection (D-038). */
const REJECTION_TEXT = '{"error":{"code":"BAD_REQUEST_ERROR","description":"invalid amount"}}';

function compiled(spec: PolicySpec): CompiledPolicy {
  const c = compilePolicy(spec);
  if (!c.ok) throw new Error(`policy: ${c.error.code}`);
  return c.value;
}

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

const ALLOW = compiled(
  definePolicy({
    default: "deny",
    rules: [
      rule("money.allow").on(["create_refund", "capture_payment", "create_payment_link"]).allow(),
    ],
  }),
);

const immediateTimer: Timer = {
  after: () => ({ promise: Promise.resolve(), cancel: () => undefined }),
};

interface FakeRefund {
  id: string;
  amount: number;
  payment_id: string;
  status: string;
  notes: Record<string, unknown> | unknown[];
}

/** Fake Razorpay state behind the scripted upstream. */
interface World {
  refunds: FakeRefund[];
  paymentStatus: string;
  listFails: boolean;
  /** Scripts for successive `create_refund` calls (default: execute + answer at once). */
  refundScript: Array<(args: Record<string, unknown>) => ScriptedReply>;
  moneyScript: Array<(name: string) => ScriptedReply>;
}

interface Harness {
  agent: Client;
  up: ScriptedUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  pipeline: MoneyPipeline;
  store: AuditStore;
  logs: string[];
  world: World;
}

const open: Harness[] = [];
let refundSeq = 0;

afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.agent.close();
    await h.proxy.close();
    h.pipeline.close();
    await h.upstream.close();
    expect(unwrap(h.store.verify()).ok).toBe(true);
    h.store.close();
  }
});

function text(json: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(json) }] };
}

/** Execute the refund in the fake Razorpay now. */
function execute(w: World, args: Record<string, unknown>): FakeRefund {
  refundSeq++;
  const r: FakeRefund = {
    id: `rfnd_E${String(refundSeq)}abcdefg`.replace(
      /[0-9]/g,
      (d) => "QRSTUVWXYZ"[Number(d)] ?? "Q",
    ),
    amount: typeof args["amount"] === "number" ? args["amount"] : 0,
    payment_id: typeof args["payment_id"] === "string" ? args["payment_id"] : "",
    status: "processed",
    notes: (args["notes"] as Record<string, unknown> | undefined) ?? [],
  };
  w.refunds.push(r);
  return r;
}

// Scripts for one create_refund call.
const executesNoAnswer =
  (w: World) =>
  (args: Record<string, unknown>): ScriptedReply => {
    execute(w, args);
    return { never: true };
  };
const failsLate = (delayMs: number) => (): ScriptedReply => ({
  delayMs,
  result: { isError: true, content: [{ type: "text", text: REJECTION_TEXT }] },
});
const hangs = (): ScriptedReply => ({ never: true });
const executesLate =
  (w: World, delayMs: number) =>
  (args: Record<string, unknown>): ScriptedReply => {
    // Executed only when the (late) answer goes out.
    setTimeout(() => execute(w, args), Math.max(0, delayMs - 1));
    return { delayMs, result: text({ id: "rfnd_LATEabcdef", entity: "refund" }) };
  };

interface SetupOpts {
  policy?: CompiledPolicy;
  /** Extra late-response events (merged with the real upstream's). */
  injectLate?: Set<(e: LateResponse) => void>;
  moneyTimeoutMs?: number;
  verifyWaitMs?: number;
  verifyTimer?: Timer;
  store?: AuditStore;
  startReconciling?: boolean;
  preCheck?: MoneyPipelineOptions["preCheck"];
}

async function setup(opts: SetupOpts = {}): Promise<Harness> {
  const world: World = {
    refunds: [],
    paymentStatus: "captured",
    listFails: false,
    refundScript: [],
    moneyScript: [],
  };
  const up = scriptedUpstream({
    tools: TOOLS,
    handler: (name, args) => {
      if (name === "fetch_payment") {
        return {
          result: text({
            id: args["payment_id"],
            status: world.paymentStatus,
            amount: 500_000,
            amount_refunded: 0,
            currency: "INR",
          }),
        };
      }
      if (name === REFUND_LIST_TOOL) {
        if (world.listFails) return { error: { code: -32603, message: "internal" } };
        const skip = typeof args["skip"] === "number" ? args["skip"] : 0;
        const count = typeof args["count"] === "number" ? args["count"] : 10;
        const items = world.refunds
          .filter((r) => r.payment_id === args["payment_id"])
          .slice(skip, skip + count);
        return { result: text({ entity: "collection", count: items.length, items }) };
      }
      if (name === "create_refund") {
        const script = world.refundScript.shift();
        if (script !== undefined) return script(args);
        const r = execute(world, args);
        return { result: text({ id: r.id, entity: "refund", amount: r.amount }) };
      }
      const s = world.moneyScript.shift();
      return s === undefined ? { result: text({ id: "plink_ABCdefghij" }) } : s(name);
    },
  });
  const logs: string[] = [];
  const upstream = new Upstream({
    factory: up.factory,
    logger: (l) => logs.push(l),
    sleep: () => Promise.resolve(),
  });
  const store = opts.store ?? unwrap(openAuditStore({ path: ":memory:" }));
  const pipeline = createMoneyPipeline({
    policy: opts.policy ?? ALLOW,
    store,
    upstream,
    approvals: createInMemoryApprovalStub(),
    clock: systemClock,
    timer: systemTimer,
    logger: (l) => logs.push(l),
    lateResponses: {
      onLateResponse: (l: (e: LateResponse) => void) => {
        const off = upstream.onLateResponse(l);
        opts.injectLate?.add(l);
        return () => {
          off();
          opts.injectLate?.delete(l);
        };
      },
    },
    verifyWaitMs: opts.verifyWaitMs ?? 2_000,
    ...(opts.verifyTimer === undefined ? {} : { verifyTimer: opts.verifyTimer }),
    ...(opts.startReconciling === true ? { startReconciling: true } : {}),
    ...(opts.preCheck === undefined ? {} : { preCheck: opts.preCheck }),
  });
  const proxy = createProxyServer({
    upstream,
    interceptor: createFirewallInterceptor(pipeline, { logger: (l) => logs.push(l) }),
    advertise: advertiseTool,
    resultFilter: redactSensitiveResult,
    logger: (l) => logs.push(l),
    sessionId: "sess-t010",
    moneyCallTimeoutMs: opts.moneyTimeoutMs ?? 40,
  });
  await upstream.connect();
  const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);
  const agent = new Client({ name: "agent", version: "0" }, { capabilities: {} });
  await agent.connect(agentSide);
  const h: Harness = { agent, up, upstream, proxy, pipeline, store, logs, world };
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
    { method: "tools/call", params: { name, arguments: { reason: REASON, ...args } } },
    CallToolResultSchema,
    signal === undefined ? undefined : { signal },
  );
}
const refund = (h: Harness, args: Record<string, unknown>, signal?: AbortSignal) =>
  call(h, "create_refund", args, signal);
const sent = (h: Harness, name: string) => h.up.calls.filter((c) => c.name === name);

interface Rows {
  attempts: AuditAttemptRecord[];
  outcomes: AuditOutcomeRecord[];
  verifications: AuditVerificationRecord[];
}
function rows(s: AuditStore): Rows {
  const out: Rows = { attempts: [], outcomes: [], verifications: [] };
  for (const r of unwrap(s.readAll())) {
    if ("invalid" in r) throw new Error("invalid row");
    if (r.kind === "attempt") out.attempts.push(r);
    else if (r.kind === "outcome") out.outcomes.push(r);
    else if (r.kind === "verification") out.verifications.push(r);
  }
  return out;
}

const markerOf = (args: Record<string, unknown> | undefined): unknown =>
  (args?.["notes"] as Record<string, unknown> | undefined)?.[ATTEMPT_MARKER_KEY];

function expectDuplicate(
  r: CallToolResult,
  status: keyof typeof DUPLICATE_MESSAGES,
): Record<string, unknown> {
  expect(r.isError).toBe(true);
  const body = jsonOf(r);
  expect(body).toMatchObject({ decision: "deny", ruleId: "firewall.duplicate" });
  const dup = body["duplicateOf"] as Record<string, unknown>;
  expect(dup["status"]).toBe(status);
  return dup;
}

// ---------------------------------------------------------------------------------------------------------------

describe("timeout ⇒ verify before anything else", () => {
  it("refund exists (marker found) ⇒ verifiedAfterTimeout success; the next identical call is denied executed", async () => {
    const h = await setup();
    h.world.refundScript.push(executesNoAnswer(h.world));
    const r = await refund(h, A1);
    const { attempts, outcomes, verifications } = rows(h.store);
    const id = attempts[0]?.id;
    expect(r.isError).toBe(false);
    const ref = h.world.refunds[0]?.id;
    // Exact firewall body, passed through the agent-facing redaction untouched.
    expect(jsonOf(r)).toEqual({
      outcome: "success",
      verifiedAfterTimeout: true,
      attemptId: id,
      upstreamRef: ref,
      message: VERIFIED_AFTER_TIMEOUT_MESSAGE,
    });
    expect(markerOf(sent(h, "create_refund")[0]?.args)).toBe(id);
    expect(outcomes).toEqual([expect.objectContaining({ attemptId: id, outcome: "timeout" })]);
    expect(verifications).toEqual([
      expect.objectContaining({
        attemptId: id,
        trigger: "timeout",
        result: "happened",
        method: "refund_notes_marker",
        needsHuman: false,
        upstreamRef: ref,
      }),
    ]);
    const dup = expectDuplicate(await refund(h, A1), "executed");
    expect(dup).toEqual({ attemptId: id, status: "executed", upstreamRef: ref });
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("late FAILURE + complete list without marker ⇒ exactly one retry; original not counted; velocity counts once", async () => {
    const h = await setup();
    h.world.refundScript.push(failsLate(80));
    const r = await refund(h, A1);
    expect(r.isError).not.toBe(true);
    const calls = sent(h, "create_refund");
    expect(calls).toHaveLength(2);
    const { attempts, outcomes, verifications } = rows(h.store);
    const [orig, retry] = attempts;
    expect(markerOf(calls[0]?.args)).toBe(orig?.id);
    expect(markerOf(calls[1]?.args)).toBe(retry?.id);
    expect(retry).toMatchObject({
      retryOf: orig?.id,
      decision: "allow",
      idempotencyKey: unwrap(idempotencyKey("create_refund", A1)),
    });
    expect(outcomes.map((o) => [o.attemptId, o.outcome])).toEqual([
      [orig?.id, "timeout"],
      [retry?.id, "success"],
    ]);
    expect(verifications).toEqual([
      expect.objectContaining({ attemptId: orig?.id, result: "not_happened", trigger: "timeout" }),
    ]);
    expect(jsonOf(r)).toMatchObject({ entity: "refund", amount: 5_000 });
    const stats = createStatsPort({
      store: h.store,
      upstream: h.upstream,
      clock: systemClock,
    });
    expect(unwrap(await stats.sumLast({ tools: ["create_refund"], windowMs: 3_600_000 }))).toEqual({
      amountPaise: 5_000,
      count: 1,
    });
    expect(expectDuplicate(await refund(h, A1), "executed")["attemptId"]).toBe(retry?.id);
    expect(sent(h, "create_refund")).toHaveLength(2);
  });

  it("the retry times out too ⇒ verified once ⇒ unknown + flagged; never a second retry", async () => {
    const h = await setup({ verifyWaitMs: 300 });
    h.world.refundScript.push(failsLate(80), hangs);
    const r = await refund(h, A1);
    const { attempts, verifications } = rows(h.store);
    const retry = attempts[1];
    expect(retry?.retryOf).toBe(attempts[0]?.id);
    expect(jsonOf(r)).toEqual({
      outcome: "unknown",
      attemptId: retry?.id,
      flaggedForHuman: true,
      message: UNKNOWN_OUTCOME_MESSAGE,
    });
    expect(r.isError).toBe(true);
    expect(verifications.map((v) => [v.attemptId, v.result, v.needsHuman])).toEqual([
      [attempts[0]?.id, "not_happened", false],
      [retry?.id, "unknown", true],
    ]);
    await new Promise((res) => setTimeout(res, 120));
    expect(sent(h, "create_refund")).toHaveLength(2);
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([retry?.id]);
  });

  it("the refund lookup fails ⇒ unknown + flagged for a human (stderr line, no payload); no retry", async () => {
    const h = await setup();
    h.world.listFails = true;
    h.world.refundScript.push(failsLate(80));
    const r = await refund(h, A1);
    const id = rows(h.store).attempts[0]?.id ?? "";
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", attemptId: id, flaggedForHuman: true });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({
        result: "unknown",
        needsHuman: true,
        errorCode: "verify.unavailable",
      }),
    ]);
    expect(h.logs.join("\n")).toContain(`NEEDS A HUMAN: create_refund attempt ${id}`);
    expect(h.logs.join("\n")).not.toContain(PAY);
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([id]);
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("no late answer within the wait ⇒ unknown, no retry", async () => {
    const h = await setup({ verifyTimer: immediateTimer });
    h.world.refundScript.push(hangs);
    const r = await refund(h, A1);
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", flaggedForHuman: true });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({ result: "unknown", errorCode: "verify.not_found" }),
    ]);
    expect(sent(h, "create_refund")).toHaveLength(1);
    // Identical call: blocked (unknown never ages out).
    expectDuplicate(await refund(h, A1), "may_have_executed");
  });

  it("a late FAILURE after the flag ⇒ settled not_happened in the background; an identical call is then allowed", async () => {
    const h = await setup({ verifyTimer: immediateTimer });
    h.world.refundScript.push(failsLate(150));
    const r = await refund(h, A1);
    const id = rows(h.store).attempts[0]?.id;
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", attemptId: id });
    await vi.waitFor(() => {
      expect(rows(h.store).verifications.map((v) => [v.trigger, v.result])).toEqual([
        ["timeout", "unknown"],
        ["late_response", "not_happened"],
      ]);
    });
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([]);
    expect(h.logs.join("\n")).toContain(`late answer settled attempt ${String(id)}`);
    const again = await refund(h, A1);
    expect(again.isError).not.toBe(true);
    expect(sent(h, "create_refund")).toHaveLength(2);
    // A fresh call, not a retry.
    expect(rows(h.store).attempts[1]?.retryOf).toBeUndefined();
  });

  it("a late SUCCESS after the flag ⇒ settled happened (marker now visible)", async () => {
    const h = await setup({ verifyTimer: immediateTimer });
    h.world.refundScript.push(executesLate(h.world, 150));
    expect(jsonOf(await refund(h, A1))).toMatchObject({ outcome: "unknown" });
    await vi.waitFor(() => {
      expect(rows(h.store).verifications.at(-1)).toMatchObject({
        trigger: "late_response",
        result: "happened",
        upstreamRef: h.world.refunds[0]?.id,
      });
    });
    expect(expectDuplicate(await refund(h, A1), "executed")["upstreamRef"]).toBe(
      h.world.refunds[0]?.id,
    );
  });

  it("the agent cancels after the send ⇒ verified, never retried", async () => {
    const h = await setup({ moneyTimeoutMs: 5_000 });
    h.world.refundScript.push(failsLate(80), () => ({ result: text({ id: "rfnd_NOPEabcdef" }) }));
    const ac = new AbortController();
    const p = refund(h, A1, ac.signal);
    await vi.waitFor(() => {
      expect(sent(h, "create_refund")).toHaveLength(1);
    });
    ac.abort();
    await expect(p).rejects.toThrow();
    // Not retry-eligible (cancelled) ⇒ no wait ⇒ unknown at once; the late failure then settles it in the background.
    await vi.waitFor(() => {
      expect(rows(h.store).verifications.map((v) => [v.trigger, v.result])).toEqual([
        ["timeout", "unknown"],
        ["late_response", "not_happened"],
      ]);
    });
    expect(rows(h.store).outcomes[0]).toMatchObject({
      outcome: "timeout",
      errorCode: "upstream.cancelled",
    });
    await new Promise((res) => setTimeout(res, 50));
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("a tool error (isError) with no marker in a complete list ⇒ settled not_happened; upstream error returned; no retry", async () => {
    const h = await setup();
    h.world.refundScript.push(() => ({
      result: { isError: true, content: [{ type: "text", text: REJECTION_TEXT }] },
    }));
    const r = await refund(h, A1);
    expect(r.isError).toBe(true);
    expect(r.content[0]).toMatchObject({ type: "text", text: REJECTION_TEXT });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({
        trigger: "upstream_error",
        result: "not_happened",
        needsHuman: false,
      }),
    ]);
    expect(sent(h, "create_refund")).toHaveLength(1);
    expect((await refund(h, A1)).isError).not.toBe(true);
    expect(sent(h, "create_refund")).toHaveLength(2);
  });

  it("a late failure but the request is not a refund (non-verifiable tool) ⇒ unknown, no lookup", async () => {
    const h = await setup();
    h.world.moneyScript.push(() => ({ never: true }));
    const r = await call(h, "create_payment_link", {
      amount: 10_000,
      currency: "INR",
      description: "x",
    });
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", flaggedForHuman: true });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({
        method: "none",
        result: "unknown",
        errorCode: "verify.unsupported_tool",
      }),
    ]);
    expect(sent(h, REFUND_LIST_TOOL)).toHaveLength(0);
  });

  it("capture_payment times out but the payment is captured ⇒ verifiedAfterTimeout (payment status)", async () => {
    const h = await setup();
    h.world.moneyScript.push(() => ({ never: true }));
    const r = await call(h, "capture_payment", { payment_id: PAY, amount: 5_000, currency: "INR" });
    expect(jsonOf(r)).toMatchObject({
      outcome: "success",
      verifiedAfterTimeout: true,
      upstreamRef: PAY,
    });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({ method: "payment_status", result: "happened" }),
    ]);
  });
});

describe("only a DEFINITE Razorpay rejection proves non-execution (security review)", () => {
  const lateToolError = (delayMs: number, text: string) => (): ScriptedReply => ({
    delayMs,
    result: { isError: true, content: [{ type: "text", text }] },
  });

  it.each([
    [
      "an isError 'context canceled' (MCP server's own HTTP timeout)",
      lateToolError(80, "context canceled"),
    ],
    [
      "a JSON-RPC error",
      (): ScriptedReply => ({ delayMs: 80, error: { code: -32603, message: "BAD_REQUEST_ERROR" } }),
    ],
    [
      "BAD_REQUEST_ERROR next to SERVER_ERROR",
      lateToolError(80, "BAD_REQUEST_ERROR / SERVER_ERROR"),
    ],
  ])(
    "timeout + late %s + marker absent ⇒ unknown + flagged, NO retry, identical call blocked",
    async (_label, script) => {
      const h = await setup();
      h.world.refundScript.push(script);
      const r = await refund(h, A1);
      const id = rows(h.store).attempts[0]?.id;
      expect(r.isError).toBe(true);
      expect(jsonOf(r)).toMatchObject({ outcome: "unknown", attemptId: id, flaggedForHuman: true });
      expect(rows(h.store).verifications).toEqual([
        expect.objectContaining({
          trigger: "timeout",
          result: "unknown",
          needsHuman: true,
          errorCode: "verify.ambiguous_failure",
        }),
      ]);
      expect(sent(h, "create_refund")).toHaveLength(1);
      expectDuplicate(await refund(h, A1), "may_have_executed");
      expect(sent(h, "create_refund")).toHaveLength(1);
    },
  );

  it("late BAD_REQUEST_ERROR + marker absent ⇒ exactly one retry", async () => {
    const h = await setup();
    h.world.refundScript.push(
      lateToolError(
        80,
        '{"error":{"code":"BAD_REQUEST_ERROR","description":"The id provided does not exist"}}',
      ),
    );
    const r = await refund(h, A1);
    expect(r.isError).not.toBe(true);
    expect(sent(h, "create_refund")).toHaveLength(2);
    expect(rows(h.store).attempts[1]?.retryOf).toBe(rows(h.store).attempts[0]?.id);
  });

  it("an ambiguous late answer after the flag (settleLate) does not settle it; it stays blocked", async () => {
    const h = await setup({ verifyTimer: immediateTimer });
    h.world.refundScript.push(lateToolError(150, "context deadline exceeded"));
    const r = await refund(h, A1);
    const id = rows(h.store).attempts[0]?.id ?? "";
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", attemptId: id });
    await vi.waitFor(() => {
      expect(h.logs.join("\n")).toContain(`late answer for attempt ${id} did not settle it`);
    });
    expect(rows(h.store).verifications.map((v) => [v.trigger, v.result])).toEqual([
      ["timeout", "unknown"],
    ]);
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([id]);
    expectDuplicate(await refund(h, A1), "may_have_executed");
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("a direct ambiguous tool error + marker absent ⇒ unknown + flagged; identical re-send denied duplicate", async () => {
    const h = await setup();
    h.world.refundScript.push(() => ({
      result: {
        isError: true,
        content: [{ type: "text", text: 'Post "https://api.razorpay.com": EOF' }],
      },
    }));
    const r = await refund(h, A1);
    const id = rows(h.store).attempts[0]?.id;
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", attemptId: id, flaggedForHuman: true });
    expect(rows(h.store).outcomes[0]).toMatchObject({ errorCode: "upstream.tool_error" });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({ trigger: "upstream_error", result: "unknown", needsHuman: true }),
    ]);
    expectDuplicate(await refund(h, A1), "may_have_executed");
    expect(sent(h, "create_refund")).toHaveLength(1);
  });

  it("a direct tool error is never re-settled by a 'late' answer (no late listener for direct answers)", async () => {
    const injectLate = new Set<(e: LateResponse) => void>();
    const h = await setup({ injectLate });
    h.world.refundScript.push(() => ({
      result: { isError: true, content: [{ type: "text", text: "context canceled" }] },
    }));
    await refund(h, A1);
    const id = rows(h.store).attempts[0]?.id;
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([id]);
    // Forged definite rejections for every plausible request id of this connection.
    for (let requestId = 0; requestId < 50; requestId++) {
      for (const l of [...injectLate]) {
        l({
          requestId,
          tool: "create_refund",
          generation: h.upstream.generation,
          sentAt: 1,
          receivedAt: 2,
          responseType: "result",
          isError: true,
          failure: "definite_rejection",
        });
      }
    }
    await new Promise((res) => setTimeout(res, 50));
    expect(rows(h.store).verifications.map((v) => v.result)).toEqual(["unknown"]);
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([id]);
  });

  it("an agent string containing a rejection code (any case, any depth) ⇒ firewall.invalid_args, not sent", async () => {
    const h = await setup();
    for (const args of [
      { ...A1, notes: { memo: "bad_request_error" } },
      { ...A1, receipt: "x BAD_REQUEST_ERROR y" },
      { ...A1, notes: { BAD_REQUEST_ERROR: "v" } },
    ]) {
      const r = await refund(h, args);
      expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.invalid_args" });
    }
    expect(sent(h, "create_refund")).toHaveLength(0);
  });

  it("an upstream error echoing the code outside a structured position ⇒ ambiguous ⇒ unknown + flagged", async () => {
    const h = await setup();
    h.world.refundScript.push(() => ({
      result: {
        isError: true,
        content: [{ type: "text", text: 'refund failed; notes: {"memo":"BAD_REQUEST_ERROR"}' }],
      },
    }));
    const r = await refund(h, A1);
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", flaggedForHuman: true });
    expect(rows(h.store).outcomes[0]).toMatchObject({ errorCode: "upstream.tool_error" });
    expectDuplicate(await refund(h, A1), "may_have_executed");
  });

  it("a direct BAD_REQUEST_ERROR + marker absent ⇒ not_happened, recorded upstream.rejected; re-send allowed", async () => {
    const h = await setup();
    h.world.refundScript.push(() => ({
      result: {
        isError: true,
        content: [{ type: "text", text: REJECTION_TEXT }],
      },
    }));
    const r = await refund(h, A1);
    expect(r.isError).toBe(true);
    expect(rows(h.store).outcomes[0]).toMatchObject({ errorCode: "upstream.rejected" });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({ result: "not_happened", needsHuman: false }),
    ]);
    expect((await refund(h, A1)).isError).not.toBe(true);
    expect(sent(h, "create_refund")).toHaveLength(2);
  });

  it("startup: a recorded upstream.rejected settles not_happened; an upstream.tool_error stays unknown and blocks", async () => {
    const store = unwrap(openAuditStore({ path: ":memory:" }));
    const ids = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"];
    for (const [id, errorCode, amount] of [
      [ids[0] ?? "", "upstream.rejected", 5_000],
      [ids[1] ?? "", "upstream.tool_error", 6_000],
    ] as const) {
      unwrap(
        store.recordAttempt({
          id,
          sessionId: "old",
          tool: "create_refund",
          args: { payment_id: PAY, amount, notes: { [ATTEMPT_MARKER_KEY]: id } },
          reason: REASON,
          decision: "allow",
          matchedRules: ["r"],
          idempotencyKey: unwrap(idempotencyKey("create_refund", { payment_id: PAY, amount })),
        }),
      );
      unwrap(
        store.recordOutcome({ attemptId: id, outcome: "upstream_error", errorCode, latencyMs: 1 }),
      );
    }
    const h = await setup({ store, startReconciling: true });
    unwrap(await h.pipeline.reconcile());
    expect(rows(store).verifications.map((v) => [v.attemptId, v.result])).toEqual([
      [ids[0], "not_happened"],
      [ids[1], "unknown"],
    ]);
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([ids[1]]);
    expect((await refund(h, { payment_id: PAY, amount: 5_000 })).isError).not.toBe(true);
    expectDuplicate(await refund(h, { payment_id: PAY, amount: 6_000 }), "may_have_executed");
  });

  it("timeout + refund found with status pending ⇒ verifiedAfterTimeout with the pending message", async () => {
    const h = await setup();
    h.world.refundScript.push((args) => {
      execute(h.world, args).status = "pending";
      return { never: true };
    });
    const r = await refund(h, A1);
    expect(r.isError).toBe(false);
    expect(jsonOf(r)).toMatchObject({
      outcome: "success",
      verifiedAfterTimeout: true,
      message: VERIFIED_AFTER_TIMEOUT_PENDING_MESSAGE,
    });
  });

  it("timeout + refund found with status failed ⇒ unknown + flagged (verify.refund_failed), no retry", async () => {
    const h = await setup();
    h.world.refundScript.push((args) => {
      execute(h.world, args).status = "failed";
      return { never: true };
    });
    const r = await refund(h, A1);
    expect(jsonOf(r)).toMatchObject({ outcome: "unknown", flaggedForHuman: true });
    expect(rows(h.store).verifications).toEqual([
      expect.objectContaining({
        result: "unknown",
        errorCode: "verify.refund_failed",
        needsHuman: true,
      }),
    ]);
    expect(sent(h, "create_refund")).toHaveLength(1);
  });
});

describe("notes marker invariants", () => {
  it("agent-supplied notes.asf_* (any case) or more than 14 notes ⇒ firewall.invalid_args (audited), not sent", async () => {
    const h = await setup();
    for (const notes of [
      { asf_attempt: "1b4e28ba-2fa1-41d2-883f-0016d3cca427" },
      { ASF_other: "x" },
      Object.fromEntries(Array.from({ length: 15 }, (_, i) => [`k${String(i)}`, "v"])),
      "not an object",
    ]) {
      const r = await refund(h, { ...A1, notes });
      expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.invalid_args" });
    }
    expect(sent(h, "create_refund")).toHaveLength(0);
    expect(rows(h.store).attempts.every((a) => a.decision === "deny")).toBe(true);
    expect(rows(h.store).attempts).toHaveLength(4);
  });

  it("a policy transform adding an asf_ note ⇒ firewall.invalid_args", async () => {
    const policy = compiled(
      definePolicy({
        default: "deny",
        rules: [
          rule("refund.tag")
            .on("create_refund")
            .transform((ctx) => ({ ...ctx.args, notes: { asf_attempt: "forged" } })),
          rule("refund.ok").on("create_refund").allow(),
        ],
      }),
    );
    const h = await setup({ policy });
    const r = await refund(h, A1);
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.invalid_args" });
    expect(sent(h, "create_refund")).toHaveLength(0);
  });

  it("agent notes are kept next to the marker (14 allowed)", async () => {
    const h = await setup();
    const notes = Object.fromEntries(Array.from({ length: 14 }, (_, i) => [`k${String(i)}`, "v"]));
    expect((await refund(h, { ...A1, notes })).isError).not.toBe(true);
    const fwd = sent(h, "create_refund")[0]?.args?.["notes"] as Record<string, unknown>;
    expect(Object.keys(fwd)).toHaveLength(15);
    expect(fwd[ATTEMPT_MARKER_KEY]).toBe(rows(h.store).attempts[0]?.id);
  });
});

describe("startup reconciliation", () => {
  const OLD = "0e8a7a3c-6a43-4f7c-9a1b-2c3d4e5f6a7b";

  function seedOldUnknown(): AuditStore {
    const s = unwrap(openAuditStore({ path: ":memory:" }));
    const ts = new Date(Date.now() - 25 * 3_600_000).toISOString();
    unwrap(
      s.recordAttempt({
        id: OLD,
        ts,
        sessionId: "old",
        tool: "create_refund",
        args: { ...A1, notes: { [ATTEMPT_MARKER_KEY]: OLD } },
        reason: REASON,
        decision: "allow",
        matchedRules: ["money.allow"],
        idempotencyKey: unwrap(idempotencyKey("create_refund", A1)),
      }),
    );
    unwrap(
      s.recordOutcome({
        attemptId: OLD,
        ts,
        outcome: "timeout",
        errorCode: "upstream.timeout",
        latencyMs: 10,
      }),
    );
    unwrap(
      s.recordVerification({
        attemptId: OLD,
        ts,
        trigger: "timeout",
        result: "unknown",
        method: "refund_notes_marker",
        needsHuman: true,
        errorCode: "verify.not_found",
      }),
    );
    return s;
  }

  it("money calls are denied firewall.reconciling (audited) until reconciliation ends; a 25 h old unknown still blocks", async () => {
    const store = seedOldUnknown();
    const h = await setup({ store, startReconciling: true });
    expect(h.pipeline.isReconciling()).toBe(true);
    const denied = await refund(h, { payment_id: "pay_OTHERabcdef", amount: 100 });
    expect(jsonOf(denied)).toEqual({
      decision: "deny",
      ruleId: "firewall.reconciling",
      message: RECONCILING_MESSAGE,
    });
    expect(rows(store).attempts.at(-1)).toMatchObject({
      decision: "deny",
      matchedRules: ["firewall.reconciling"],
    });
    // Reads keep working.
    expect((await call(h, "fetch_payment", { payment_id: PAY })).isError).not.toBe(true);
    const summary = unwrap(await h.pipeline.reconcile());
    expect(summary.unresolved.map((a) => a.attempt.id)).toEqual([OLD]);
    expect(h.pipeline.isReconciling()).toBe(false);
    // Still unknown: no new verification row for it.
    expect(rows(store).verifications).toHaveLength(1);
    // Older than the 24 h scan, still blocks (in-memory unresolved set).
    const dup = expectDuplicate(await refund(h, A1), "may_have_executed");
    expect(dup["attemptId"]).toBe(OLD);
    expect(sent(h, "create_refund")).toHaveLength(0);
  });

  it("an old unknown whose refund now shows up ⇒ settled happened at startup", async () => {
    const store = seedOldUnknown();
    const h = await setup({ store, startReconciling: true });
    h.world.refunds.push({
      id: "rfnd_OLDabcdefg",
      amount: 5_000,
      payment_id: PAY,
      status: "processed",
      notes: { [ATTEMPT_MARKER_KEY]: OLD },
    });
    unwrap(await h.pipeline.reconcile());
    expect(rows(store).verifications.at(-1)).toMatchObject({
      trigger: "startup",
      result: "happened",
    });
    expect(h.pipeline.unresolvedAttemptIds()).toEqual([]);
  });

  it("reconciliation failure (scan cap) ⇒ pipeline degraded, money calls denied audit_unavailable", async () => {
    const store = unwrap(openAuditStore({ path: ":memory:", maxScanRows: 1 }));
    unwrap(
      store.recordAttempt({
        sessionId: "s",
        tool: "create_refund",
        args: A1,
        reason: REASON,
        decision: "deny",
        matchedRules: ["x"],
      }),
    );
    unwrap(
      store.recordAttempt({
        sessionId: "s",
        tool: "create_refund",
        args: A1,
        reason: REASON,
        decision: "deny",
        matchedRules: ["x"],
      }),
    );
    const h = await setup({ store, startReconciling: true });
    expect((await h.pipeline.reconcile()).ok).toBe(false);
    expect(h.pipeline.isDegraded()).toBe(true);
    expect(h.pipeline.isReconciling()).toBe(false);
    expect(jsonOf(await refund(h, A1))).toMatchObject({ ruleId: "audit_unavailable" });
  });
});

describe("not retried", () => {
  it("the agent cancels DURING the wait ⇒ settled not_happened on the late failure, but not retried", async () => {
    const h = await setup();
    h.world.refundScript.push(failsLate(150));
    const ac = new AbortController();
    const p = refund(h, A1, ac.signal);
    await vi.waitFor(() => {
      expect(rows(h.store).outcomes[0]).toMatchObject({ outcome: "timeout" });
    });
    ac.abort();
    await expect(p).rejects.toThrow();
    await vi.waitFor(() => {
      expect(rows(h.store).verifications).toEqual([
        expect.objectContaining({ result: "not_happened", trigger: "timeout" }),
      ]);
    });
    await new Promise((res) => setTimeout(res, 50));
    expect(sent(h, "create_refund")).toHaveLength(1);
    expect(h.logs.join("\n")).toContain("not retried: the request was cancelled");
    expect(NOT_RETRIED_MESSAGE).toMatch(/NOT executed/);
  });
});

describe("T012 modes and verify-before-retry", () => {
  it("shadow mode: a timed-out refund is still verified and retried once; both attempts are shadow attempts", async () => {
    const store = unwrap(openAuditStore({ path: ":memory:" }));
    const modes = createModeStore(store);
    unwrap(modes.set({ shadow: true, actor: "cli:ops" }));
    const SHADOW_DENY = compiled(
      definePolicy({ default: "deny", rules: [rule("refund.no").on("create_refund").deny("no")] }),
    );
    const h = await setup({ store, policy: SHADOW_DENY, preCheck: createModePreCheck(modes) });
    h.world.refundScript.push(failsLate(80));
    const r = await refund(h, A1);
    expect(r.isError).not.toBe(true);
    expect(sent(h, "create_refund")).toHaveLength(2);
    const { attempts, verifications } = rows(h.store);
    const [orig, retry] = attempts;
    expect(orig).toMatchObject({ decision: "allow", shadow: true, wouldDecision: "deny" });
    expect(retry).toMatchObject({
      retryOf: orig?.id,
      decision: "allow",
      shadow: true,
      wouldDecision: "deny",
    });
    expect(verifications).toEqual([
      expect.objectContaining({ attemptId: orig?.id, result: "not_happened" }),
    ]);
    // Duplicates of the executed retry are still blocked in shadow mode.
    expect(expectDuplicate(await refund(h, A1), "executed")["attemptId"]).toBe(retry?.id);
  });

  it("kill switch turned ON after the send ⇒ the original is verified, the retry is NOT sent", async () => {
    const store = unwrap(openAuditStore({ path: ":memory:" }));
    const modes = createModeStore(store);
    const h = await setup({ store, preCheck: createModePreCheck(modes) });
    h.world.refundScript.push(() => {
      unwrap(modes.set({ killSwitch: true, actor: "cli:ops" }));
      return failsLate(80)();
    });
    const r = await refund(h, A1);
    expect(sent(h, "create_refund")).toHaveLength(1);
    expect(jsonOf(r)).toMatchObject({ error: "upstream_timeout", message: NOT_RETRIED_MESSAGE });
    const { attempts, verifications } = rows(h.store);
    expect(attempts).toHaveLength(1);
    expect(verifications).toEqual([
      expect.objectContaining({ attemptId: attempts[0]?.id, result: "not_happened" }),
    ]);
    expect(h.logs.join("\n")).toContain(`not retried: ${KILL_SWITCH_RULE}`);
    // And new money calls are frozen.
    expect(jsonOf(await refund(h, { payment_id: PAY, amount: 6_000 }))).toMatchObject({
      decision: "deny",
      ruleId: KILL_SWITCH_RULE,
    });
  });

  it("shadow mode turned OFF after the send ⇒ a would-deny refund is NOT retried (M1)", async () => {
    const store = unwrap(openAuditStore({ path: ":memory:" }));
    const modes = createModeStore(store);
    unwrap(modes.set({ shadow: true, actor: "cli:ops" }));
    const DENY = compiled(
      definePolicy({ default: "deny", rules: [rule("refund.no").on("create_refund").deny("no")] }),
    );
    const h = await setup({ store, policy: DENY, preCheck: createModePreCheck(modes) });
    h.world.refundScript.push(() => {
      unwrap(modes.set({ shadow: false, actor: "cli:ops" }));
      return failsLate(80)();
    });
    const r = await refund(h, A1);
    expect(sent(h, "create_refund")).toHaveLength(1);
    expect(jsonOf(r)).toMatchObject({ error: "upstream_timeout", message: NOT_RETRIED_MESSAGE });
    expect(rows(h.store).attempts).toHaveLength(1);
    expect(h.logs.join("\n")).toContain("not retried: firewall.shadow_ended");
  });
});
