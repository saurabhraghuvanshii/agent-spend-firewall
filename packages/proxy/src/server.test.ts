import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  ToolListChangedNotificationSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  createProxyServer,
  CREDENTIAL_LEAK_RESULT,
  denyResult,
  passThroughInterceptor,
  screenResult,
  stableStringify,
  type CallContext,
  type CallInterceptor,
  type ProxyServer,
} from "./server.js";
import {
  FAKE_TOOLS,
  fakeUpstream,
  hang,
  jsonOf,
  textOf,
  type FakeUpstream,
} from "./test-support/fake-upstream.js";
import { redactSecrets, type DiscoveredTool } from "./tool-discovery.js";
import { noRedact, Upstream, type Redactor } from "./upstream.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const redact: Redactor = (s) => redactSecrets(s, KEYS);

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  logs: string[];
  sleeps: number[];
  seen: CallContext[];
}

const open: Harness[] = [];

afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.agent.close();
    await h.proxy.close();
    await h.upstream.close();
  }
});

async function setup(
  opts: {
    fake?: FakeUpstream;
    interceptor?: CallInterceptor;
    cachedTools?: readonly DiscoveredTool[];
    callTimeoutMs?: number;
    connectFirst?: boolean;
  } = {},
): Promise<Harness> {
  const fake = opts.fake ?? fakeUpstream();
  const logs: string[] = [];
  const sleeps: number[] = [];
  const seen: CallContext[] = [];
  const upstream = new Upstream({
    factory: fake.factory,
    logger: (l) => logs.push(l),
    redact,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
  });
  const inner = opts.interceptor ?? passThroughInterceptor;
  const recording: CallInterceptor = {
    intercept: (ctx, forward) => {
      seen.push(ctx);
      return inner.intercept(ctx, forward);
    },
  };
  const proxy = createProxyServer({
    upstream,
    interceptor: recording,
    logger: (l) => logs.push(l),
    redact,
    sessionId: "session-test",
    ...(opts.cachedTools === undefined ? {} : { cachedTools: opts.cachedTools }),
    ...(opts.callTimeoutMs === undefined ? {} : { callTimeoutMs: opts.callTimeoutMs }),
  });
  if (opts.connectFirst !== false) await upstream.connect();
  const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);
  const agent = new Client({ name: "test-agent", version: "0.0.0" }, { capabilities: {} });
  await agent.connect(agentSide);
  const h = { agent, fake, upstream, proxy, logs, sleeps, seen };
  open.push(h);
  return h;
}

async function call(
  agent: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  return agent.request(
    { method: "tools/call", params: { name, arguments: args } },
    CallToolResultSchema,
  );
}

describe("tools/list mirroring", () => {
  it("advertises upstream tools unchanged (names, descriptions, schemas, annotations)", async () => {
    const h = await setup();
    const listed = await h.agent.listTools();
    // Same tools, sorted by name (deterministic, like discovery).
    const byName = [...FAKE_TOOLS].sort((a, b) => (a.name < b.name ? -1 : 1));
    expect(listed.tools).toEqual(byName);
  });

  it("collects every page of a paginated upstream list", async () => {
    const fake = fakeUpstream();
    fake.setPageSize(1);
    const h = await setup({ fake });
    const listed = await h.agent.listTools();
    expect(listed.tools.map((t) => t.name)).toEqual(FAKE_TOOLS.map((t) => t.name).sort());
  });

  it("re-lists and notifies the agent when upstream sends tools/list_changed", async () => {
    const h = await setup();
    await h.agent.listTools();
    const notified = new Promise<void>((resolve) => {
      h.agent.setNotificationHandler(ToolListChangedNotificationSchema, () => {
        resolve();
      });
    });
    const extra: Tool = { name: "fetch_order", inputSchema: { type: "object" } };
    h.fake.setTools([...FAKE_TOOLS, extra]);
    await h.fake.notifyListChanged();
    await notified;
    const listed = await h.agent.listTools();
    expect(listed.tools.map((t) => t.name)).toContain("fetch_order");
    // The new tool is callable once listed.
    const r = await call(h.agent, "fetch_order", { order_id: "order_1" });
    expect(r.isError).toBeUndefined();
  });
});

describe("tools/call forwarding", () => {
  it("forwards a read call with the same args and returns the upstream result", async () => {
    const h = await setup();
    const args = { payment_id: "pay_123" };
    const r = await call(h.agent, "fetch_payment", args);
    expect(r.isError).toBeUndefined();
    expect(jsonOf(r)).toEqual({ tool: "fetch_payment", args });
    expect(h.fake.calls).toEqual([{ name: "fetch_payment", args }]);
    expect(h.seen[0]).toMatchObject({
      tool: "fetch_payment",
      toolClass: "read",
      sessionId: "session-test",
    });
  });

  it("passes a money call through unchanged; the interceptor sees toolClass money", async () => {
    const h = await setup();
    const args = { payment_id: "pay_123", amount: 5000, notes: { why: "duplicate" } };
    const r = await call(h.agent, "create_refund", args);
    expect(jsonOf(r)).toEqual({ tool: "create_refund", args });
    expect(h.fake.calls).toEqual([{ name: "create_refund", args }]);
    expect(h.seen).toHaveLength(1);
    expect(h.seen[0]?.toolClass).toBe("money");
    expect(h.seen[0]?.args).toEqual(args);
  });

  it("returns upstream isError results as-is", async () => {
    const fake = fakeUpstream({
      handler: () =>
        Promise.resolve({ isError: true, content: [{ type: "text", text: "BAD_REQUEST_ERROR" }] }),
    });
    const h = await setup({ fake });
    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_x" });
    expect(r).toEqual({ isError: true, content: [{ type: "text", text: "BAD_REQUEST_ERROR" }] });
  });

  it("forwards what the interceptor passes to forward(), and can short-circuit", async () => {
    const interceptor: CallInterceptor = {
      intercept: (ctx, forward) =>
        ctx.toolClass === "money"
          ? Promise.resolve(denyResult("test.rule", "nope"))
          : forward({ ...ctx.args, extra: 1 }),
    };
    const h = await setup({ interceptor });
    const denied = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(denied.isError).toBe(true);
    expect(jsonOf(denied)).toEqual({ decision: "deny", ruleId: "test.rule", message: "nope" });
    await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(h.fake.calls).toEqual([
      { name: "fetch_payment", args: { payment_id: "pay_1", extra: 1 } },
    ]);
  });

  it("denies (fail closed) when the interceptor throws, without calling upstream", async () => {
    const interceptor: CallInterceptor = {
      intercept: () => Promise.reject(new Error(`engine exploded ${KEYS.keySecret}`)),
    };
    const h = await setup({ interceptor });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.interceptor_error" });
    expect(h.fake.calls).toEqual([]);
    expect(h.logs.join("\n")).not.toContain(KEYS.keySecret);
  });
});

describe("unknown tools", () => {
  it("denies a tool upstream does not list and never forwards it", async () => {
    const h = await setup();
    const r = await call(h.agent, "drain_account", { amount: 1 });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });
    expect(h.fake.calls).toEqual([]);
    expect(h.seen).toEqual([]);
  });

  it.each(["Create_Refund", "create_refund ", "CREATE_REFUND", "constructor", "__proto__", ""])(
    "treats %j as unknown (exact match only)",
    async (name) => {
      const h = await setup();
      const r = await call(h.agent, name, {});
      expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });
      expect(h.fake.calls).toEqual([]);
    },
  );
});

describe("upstream failures", () => {
  it("upstream protocol error ⇒ isError upstream_error; server keeps serving", async () => {
    let n = 0;
    const fake = fakeUpstream({
      handler: (name, args) => {
        n++;
        if (n === 1) return Promise.reject(new Error("internal failure"));
        return Promise.resolve({
          content: [{ type: "text", text: JSON.stringify({ name, args }) }],
        });
      },
    });
    const h = await setup({ fake });
    const r1 = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(r1.isError).toBe(true);
    expect(jsonOf(r1)).toMatchObject({ error: "upstream_error", forwarded: true });
    const r2 = await call(h.agent, "fetch_payment", { payment_id: "pay_2" });
    expect(r2.isError).toBeUndefined();
  });

  it("redacts every form of the keys from upstream error messages", async () => {
    const basic = Buffer.from(`${KEYS.keyId}:${KEYS.keySecret}`).toString("base64");
    const fake = fakeUpstream({
      handler: () =>
        Promise.reject(
          new Error(
            `auth ${KEYS.keyId} ${KEYS.keySecret} Basic ${basic} ${encodeURIComponent(KEYS.keySecret)}`,
          ),
        ),
    });
    const h = await setup({ fake });
    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    const text = textOf(r);
    expect(text).toContain("[REDACTED]");
    for (const s of [KEYS.keyId, KEYS.keySecret, basic]) expect(text).not.toContain(s);
  });

  it("replaces a successful upstream result that echoes a key with an upstream_error (never patched)", async () => {
    const fake = fakeUpstream({
      handler: () =>
        Promise.resolve({
          content: [
            { type: "text", text: `key=${KEYS.keySecret}` },
            { type: "text", text: "pay_1" },
          ],
        }),
    });
    const h = await setup({ fake });
    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(r.isError).toBe(true);
    expect(r.content).toHaveLength(1);
    expect(jsonOf(r)).toEqual({
      error: "upstream_error",
      message: "upstream response contained credential material",
      forwarded: true,
    });
    expect(JSON.stringify(r)).not.toContain(KEYS.keySecret);
    expect(h.logs.join("\n")).toMatch(/fetch_payment contained credential material/);
    expect(h.logs.join("\n")).not.toContain(KEYS.keySecret);
  });

  it("call timeout ⇒ upstream_timeout (forwarded, outcome unknown)", async () => {
    const fake = fakeUpstream({ handler: (_n, _a, signal) => hang(signal) });
    const h = await setup({ fake, callTimeoutMs: 50 });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(r.isError).toBe(true);
    const body = jsonOf(r);
    expect(body).toMatchObject({ error: "upstream_timeout", forwarded: true });
    expect(String(body["message"])).toMatch(/check the resource status before retrying/);
    expect(h.fake.calls).toHaveLength(1); // never retried
  });

  it("connection lost mid-call ⇒ upstream_error, forwarded, not retried", async () => {
    const fake = fakeUpstream();
    fake.setHandler(async (_n, _a, signal) => {
      await fake.dropConnection();
      return hang(signal);
    });
    const h = await setup({ fake });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_error", forwarded: true });
    expect(h.fake.calls).toHaveLength(1);
  });

  it("upstream transport closed between calls ⇒ reconnects, then succeeds", async () => {
    const h = await setup();
    await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    await h.fake.dropConnection();
    expect(h.upstream.isConnected()).toBe(false);
    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_2" });
    expect(r.isError).toBeUndefined();
    expect(h.fake.attempts()).toBe(2);
    expect(h.upstream.generation).toBe(2);
    expect(h.fake.disposed()).toBeGreaterThanOrEqual(1);
  });

  it("reconnect exhausted ⇒ upstream_unavailable (not forwarded) with bounded backoff", async () => {
    const h = await setup();
    await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    h.fake.setFailing(true);
    await h.fake.dropConnection();
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ error: "upstream_unavailable", forwarded: false });
    expect(h.sleeps).toEqual([250, 1000]);
    expect(h.fake.calls).toHaveLength(1);
    // Recovers once upstream is back.
    h.fake.setFailing(false);
    const r2 = await call(h.agent, "fetch_payment", { payment_id: "pay_3" });
    expect(r2.isError).toBeUndefined();
  });
});

describe("forwarding is bound to the CURRENT upstream generation", () => {
  const cachedTools: DiscoveredTool[] = FAKE_TOOLS.map((t) => ({
    name: t.name,
    description: t.description ?? "",
    inputSchema: t.inputSchema,
  }));

  it("regression: container dies, reconnect ok, re-list fails ⇒ previous list is NOT an allowlist", async () => {
    const fake = fakeUpstream();
    const h = await setup({ fake, cachedTools });
    expect((await h.agent.listTools()).tools.map((t) => t.name)).toContain("create_refund");
    // New container no longer offers create_refund, and its tools/list fails.
    fake.setTools(FAKE_TOOLS.filter((t) => t.name !== "create_refund"));
    fake.setListFailing(true);
    await fake.dropConnection();
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toEqual({
      error: "upstream_unavailable",
      message: "the upstream Razorpay MCP server is unavailable; the call was not sent",
      forwarded: false,
    });
    expect(h.upstream.generation).toBe(2); // reconnect succeeded
    expect(fake.calls).toEqual([]);
    expect(h.seen).toEqual([]);
    // Once the list works again, the name is checked against the NEW list: unknown.
    fake.setListFailing(false);
    const r2 = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(jsonOf(r2)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });
    expect(fake.calls).toEqual([]);
  });

  it("same scenario without a cache ⇒ unknown_tool, never forwarded", async () => {
    const fake = fakeUpstream();
    const h = await setup({ fake });
    await h.agent.listTools();
    fake.setListFailing(true);
    await fake.dropConnection();
    // The previous generation's list is gone: even a name it contained is unknown now, never forwarded.
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 1 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });
    expect(fake.calls).toEqual([]);
  });

  it("reconnect between the name check and forward() ⇒ re-checked; not sent if the new list is unavailable", async () => {
    const fake = fakeUpstream();
    const interceptor: CallInterceptor = {
      intercept: async (ctx, forward) => {
        fake.setListFailing(true);
        await fake.dropConnection();
        return forward({ ...ctx.args });
      },
    };
    const h = await setup({ fake, interceptor, cachedTools });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_unavailable", forwarded: false });
    expect(fake.calls).toEqual([]);
    expect(h.upstream.generation).toBe(2);
  });

  it("reconnect between check and forward() where the new list drops the tool ⇒ unknown_tool", async () => {
    const fake = fakeUpstream();
    const interceptor: CallInterceptor = {
      intercept: async (ctx, forward) => {
        fake.setTools(FAKE_TOOLS.filter((t) => t.name !== "create_refund"));
        await fake.dropConnection();
        return forward({ ...ctx.args });
      },
    };
    const h = await setup({ fake, interceptor });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });
    expect(fake.calls).toEqual([]);
  });

  it("tool schema changes between interceptor and forward() ⇒ upstream_unavailable, not sent", async () => {
    const fake = fakeUpstream();
    const interceptor: CallInterceptor = {
      intercept: async (ctx, forward) => {
        fake.setTools(
          FAKE_TOOLS.map((t) =>
            t.name === "create_refund"
              ? {
                  ...t,
                  inputSchema: {
                    type: "object",
                    properties: { payment_id: { type: "string" }, amount: { type: "string" } },
                  },
                }
              : t,
          ),
        );
        await fake.dropConnection();
        return forward({ ...ctx.args });
      },
    };
    const h = await setup({ fake, interceptor });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toEqual({
      error: "upstream_unavailable",
      message: "tool schema changed; retry",
      forwarded: false,
    });
    expect(fake.calls).toEqual([]);
    expect(h.upstream.generation).toBe(2);
  });

  it("re-list with the same schema (keys reordered) between interceptor and forward() ⇒ forwarded", async () => {
    const fake = fakeUpstream();
    const reorder = (v: unknown): unknown => {
      if (Array.isArray(v)) return v.map(reorder);
      if (v !== null && typeof v === "object") {
        return Object.fromEntries(
          Object.entries(v)
            .reverse()
            .map(([k, x]) => [k, reorder(x)]),
        );
      }
      return v;
    };
    const interceptor: CallInterceptor = {
      intercept: async (ctx, forward) => {
        fake.setTools(
          FAKE_TOOLS.map((t) => ({
            ...t,
            inputSchema: reorder(t.inputSchema) as Tool["inputSchema"],
          })),
        );
        await fake.dropConnection();
        return forward({ ...ctx.args });
      },
    };
    const h = await setup({ fake, interceptor });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(r.isError).toBeUndefined();
    expect(fake.calls).toHaveLength(1);
  });

  it("stableStringify sorts object keys at every depth", () => {
    expect(stableStringify({ b: 1, a: { d: [1, { y: 2, x: 1 }], c: null } })).toBe(
      '{"a":{"c":null,"d":[1,{"x":1,"y":2}]},"b":1}',
    );
  });

  it("list_changed then a failing re-list (same generation) ⇒ upstream_unavailable until re-listed", async () => {
    const fake = fakeUpstream();
    const h = await setup({ fake });
    await h.agent.listTools();
    fake.setListFailing(true);
    await fake.notifyListChanged();
    await vi.waitFor(() => {
      expect(h.logs.some((l) => l.includes("upstream tools/list unavailable"))).toBe(true);
    });
    expect(h.upstream.generation).toBe(1);
    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_unavailable", forwarded: false });
    expect(fake.calls).toEqual([]);
    fake.setListFailing(false);
    const r2 = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(r2.isError).toBeUndefined();
    expect(fake.calls).toHaveLength(1);
  });
});

describe("forward() contract", () => {
  it("is call-once: a second forward is denied firewall.forward_twice and not sent", async () => {
    const results: CallToolResult[] = [];
    const interceptor: CallInterceptor = {
      intercept: async (ctx, forward) => {
        results.push(await forward({ ...ctx.args }));
        const second = await forward({ ...ctx.args });
        results.push(second);
        return second;
      },
    };
    const h = await setup({ interceptor });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.forward_twice" });
    expect(results[0]?.isError).toBeUndefined();
    expect(h.fake.calls).toHaveLength(1);
  });

  it("forward after intercept settled ⇒ firewall.forward_after_settle, not sent", async () => {
    let stash: ((a: Record<string, unknown>) => Promise<CallToolResult>) | undefined;
    const interceptor: CallInterceptor = {
      intercept: (_ctx, forward) => {
        stash = forward;
        return Promise.resolve(denyResult("test.rule", "denied"));
      },
    };
    const h = await setup({ interceptor });
    await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(stash).toBeDefined();
    const late = await stash?.({ payment_id: "pay_1", amount: 100 });
    expect(jsonOf(late)).toMatchObject({
      decision: "deny",
      ruleId: "firewall.forward_after_settle",
    });
    expect(h.fake.calls).toEqual([]);
  });

  it("forward after the interceptor THREW is also refused", async () => {
    let stash: ((a: Record<string, unknown>) => Promise<CallToolResult>) | undefined;
    const interceptor: CallInterceptor = {
      intercept: (_ctx, forward) => {
        stash = forward;
        return Promise.reject(new Error("boom"));
      },
    };
    const h = await setup({ interceptor });
    await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 100 });
    const late = await stash?.({ payment_id: "pay_1", amount: 100 });
    expect(jsonOf(late)).toMatchObject({ ruleId: "firewall.forward_after_settle" });
    expect(h.fake.calls).toEqual([]);
  });

  it("ctx.args is a deep-frozen copy; upstream receives exactly what forward() was given", async () => {
    let frozen = false;
    let threw = false;
    const interceptor: CallInterceptor = {
      intercept: (ctx, forward) => {
        frozen = Object.isFrozen(ctx.args) && Object.isFrozen(ctx.args["notes"]);
        try {
          (ctx.args as Record<string, unknown>)["amount"] = 1;
        } catch {
          threw = true;
        }
        // T004-style: strip `reason` before forwarding.
        const sent: Record<string, unknown> = { ...ctx.args };
        delete sent["reason"];
        const p = forward(sent);
        sent["amount"] = 999_999; // mutation after the call must not change what is sent
        return p;
      },
    };
    const h = await setup({ interceptor });
    await call(h.agent, "create_refund", {
      payment_id: "pay_1",
      amount: 100,
      notes: { k: "v" },
      reason: "customer was double charged",
    });
    expect(frozen).toBe(true);
    expect(threw).toBe(true);
    expect(h.fake.calls).toEqual([
      { name: "create_refund", args: { payment_id: "pay_1", amount: 100, notes: { k: "v" } } },
    ]);
  });

  class Money {
    paise = 100;
  }
  it.each<[string, () => Record<string, unknown>]>([
    ["a function", () => ({ f: () => 1 })],
    ["a Date", () => ({ d: new Date(0) })],
    ["NaN", () => ({ amount: Number.NaN })],
    ["Infinity", () => ({ amount: Number.POSITIVE_INFINITY })],
    ["a class instance", () => ({ m: new Money() })],
    ["a Map", () => ({ m: new Map([["a", 1]]) })],
    ["undefined value", () => ({ u: undefined })],
    [
      "too deep",
      () => {
        let o: Record<string, unknown> = {};
        const root = o;
        for (let i = 0; i < 40; i++) {
          const n: Record<string, unknown> = {};
          o["n"] = n;
          o = n;
        }
        return root;
      },
    ],
  ])("forward() with %s ⇒ firewall.invalid_forward_args, not sent", async (_l, make) => {
    const interceptor: CallInterceptor = { intercept: (_ctx, forward) => forward(make()) };
    const h = await setup({ interceptor });
    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.invalid_forward_args" });
    expect(h.fake.calls).toEqual([]);
  });
});

describe("cancellation", () => {
  it("agent cancels mid-call ⇒ the forward outcome is cancelled (forwarded), not upstream_timeout", async () => {
    const outcomes: CallToolResult[] = [];
    const fake = fakeUpstream({ handler: (_n, _a, signal) => hang(signal) });
    const interceptor: CallInterceptor = {
      intercept: async (ctx, forward) => {
        const r = await forward({ ...ctx.args });
        outcomes.push(r);
        return r;
      },
    };
    const h = await setup({ fake, interceptor });
    const c = new AbortController();
    const p = h.agent.request(
      {
        method: "tools/call",
        params: { name: "create_refund", arguments: { payment_id: "pay_1", amount: 1 } },
      },
      CallToolResultSchema,
      { signal: c.signal },
    );
    await vi.waitFor(() => {
      expect(fake.calls).toHaveLength(1);
    });
    c.abort("user cancelled");
    await expect(p).rejects.toThrow();
    await vi.waitFor(() => {
      expect(outcomes).toHaveLength(1);
    });
    expect(jsonOf(outcomes[0])).toMatchObject({ error: "cancelled", forwarded: true });
    expect(fake.calls).toHaveLength(1);
  });
});

describe("startup with upstream down", () => {
  const cachedTools: DiscoveredTool[] = FAKE_TOOLS.slice(0, 2).map((t) => ({
    name: t.name,
    description: t.description ?? "",
    inputSchema: t.inputSchema,
  }));

  it("serves the cached list; calls fail upstream_unavailable; recovers and notifies list_changed", async () => {
    const fake = fakeUpstream();
    fake.setFailing(true);
    const h = await setup({ fake, cachedTools, connectFirst: false });
    let notified = 0;
    h.agent.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      notified++;
    });

    const listed = await h.agent.listTools();
    expect(listed.tools.map((t) => t.name)).toEqual(["fetch_payment", "create_refund"]);

    const r = await call(h.agent, "fetch_payment", { payment_id: "pay_1" });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_unavailable", forwarded: false });

    // Not in the cache and no live list: unknown, never forwarded.
    const u = await call(h.agent, "fetch_all_payments", { count: 1 });
    expect(jsonOf(u)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });

    fake.setFailing(false);
    const ok = await call(h.agent, "fetch_all_payments", { count: 1 });
    expect(ok.isError).toBeUndefined();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(notified).toBe(1);
    expect(fake.calls).toEqual([{ name: "fetch_all_payments", args: { count: 1 } }]);
  });

  it("the cache is never an allowlist: a cached name upstream no longer lists is denied", async () => {
    const fake = fakeUpstream({ tools: FAKE_TOOLS.slice(0, 1) });
    const h = await setup({ fake, cachedTools, connectFirst: false });
    const r = await call(h.agent, "create_refund", { payment_id: "pay_1", amount: 1 });
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.unknown_tool" });
    expect(fake.calls).toEqual([]);
  });

  it("no cache and upstream down ⇒ tools/list fails with a clear error; process keeps serving", async () => {
    const fake = fakeUpstream();
    fake.setFailing(true);
    const h = await setup({ fake, connectFirst: false });
    await expect(h.agent.listTools()).rejects.toThrow(
      /upstream Razorpay MCP server is unavailable/,
    );
    fake.setFailing(false);
    const listed = await h.agent.listTools();
    expect(listed.tools).toHaveLength(FAKE_TOOLS.length);
  });
});

describe("screenResult", () => {
  it("returns the same object when there is no credential material", () => {
    const r: CallToolResult = { content: [{ type: "text", text: "fine" }] };
    expect(screenResult(r, redact)).toBe(r);
    expect(screenResult(r, noRedact)).toBe(r);
  });

  const basic = Buffer.from(`${KEYS.keyId}:${KEYS.keySecret}`).toString("base64");
  it.each<[string, CallToolResult]>([
    ["secret in a text value", { content: [{ type: "text", text: `x ${KEYS.keySecret}` }] }],
    [
      "key id as an object KEY",
      { content: [{ type: "text", text: "ok" }], structuredContent: { [KEYS.keyId]: 1 } },
    ],
    [
      "secret deep in structuredContent",
      { content: [], structuredContent: { a: { deep: [KEYS.keySecret] } } },
    ],
    ["HTTP Basic form", { content: [{ type: "text", text: `Authorization: Basic ${basic}` }] }],
    [
      "URI-encoded secret",
      { content: [{ type: "text", text: `?s=${encodeURIComponent(KEYS.keySecret)}` }] },
    ],
  ])("%s ⇒ whole result replaced", (_label, r) => {
    const out = screenResult(r, redact);
    expect(out).toBe(CREDENTIAL_LEAK_RESULT);
    expect(JSON.stringify(out)).not.toMatch(/rzp_test_Key123|TopSecretValue987/);
    expect(out.isError).toBe(true);
  });
});
