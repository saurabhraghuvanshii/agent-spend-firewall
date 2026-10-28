/** T011 server seams: firewall-implemented local tools and `openDirectCall` (forwarding for approved actions). */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  createProxyServer,
  forwardReportOf,
  retryForwardOf,
  type CallInterceptor,
  type LocalTool,
  type ProxyServer,
} from "./server.js";
import {
  FAKE_TOOLS,
  fakeUpstream,
  hang,
  jsonOf,
  type FakeUpstream,
} from "./test-support/fake-upstream.js";
import { redactSecrets } from "./tool-discovery.js";
import { Upstream, type Redactor } from "./upstream.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const redact: Redactor = (s) => redactSecrets(s, KEYS);

interface H {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
  logs: string[];
  localCalls: Array<{ args: unknown; sessionId: string }>;
  intercepted: string[];
}
const open: H[] = [];
afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.agent.close();
    await h.proxy.close();
    await h.upstream.close();
  }
});

const LOCAL_TOOL: Tool = {
  name: "firewall_check_approval",
  description: "local",
  inputSchema: { type: "object", properties: { approvalId: { type: "string" } } },
};

async function setup(
  o: { local?: Partial<LocalTool>; tools?: Tool[]; callTimeoutMs?: number; connect?: boolean } = {},
): Promise<H> {
  const fake = fakeUpstream(o.tools === undefined ? {} : { tools: o.tools });
  const logs: string[] = [];
  const localCalls: H["localCalls"] = [];
  const intercepted: string[] = [];
  const upstream = new Upstream({
    factory: fake.factory,
    logger: (l) => logs.push(l),
    redact,
    sleep: () => Promise.resolve(),
  });
  const interceptor: CallInterceptor = {
    intercept: (ctx, forward) => {
      intercepted.push(ctx.tool);
      return forward({ ...ctx.args });
    },
  };
  const local: LocalTool = {
    tool: LOCAL_TOOL,
    call: (args, ctx) => {
      localCalls.push({ args, sessionId: ctx.sessionId });
      return Promise.resolve({ content: [{ type: "text", text: JSON.stringify({ ok: true }) }] });
    },
    ...o.local,
  };
  const proxy = createProxyServer({
    upstream,
    interceptor,
    advertise: (t) => ({ ...t, description: `${t.description ?? ""} [advertised]` }),
    resultFilter: () => ({ content: [{ type: "text", text: "filtered" }] }),
    logger: (l) => logs.push(l),
    redact,
    sessionId: "sess-local",
    localTools: [local],
    ...(o.callTimeoutMs === undefined ? {} : { callTimeoutMs: o.callTimeoutMs }),
  });
  if (o.connect !== false) await upstream.connect();
  const [a, b] = InMemoryTransport.createLinkedPair();
  await proxy.connect(b);
  const agent = new Client({ name: "a", version: "0" }, { capabilities: {} });
  await agent.connect(a);
  const h = { agent, fake, upstream, proxy, logs, localCalls, intercepted };
  open.push(h);
  return h;
}

const call = (h: H, name: string, args: unknown): Promise<CallToolResult> =>
  h.agent.request(
    { method: "tools/call", params: { name, arguments: args as Record<string, unknown> } },
    CallToolResultSchema,
  );

describe("local tools", () => {
  it("are advertised unchanged next to the upstream tools", async () => {
    const h = await setup();
    const listed = await h.agent.listTools();
    expect(listed.tools.at(-1)).toEqual(LOCAL_TOOL);
    expect(listed.tools.find((t) => t.name === "create_refund")?.description).toContain(
      "[advertised]",
    );
  });

  it("are handled locally: no interceptor, no upstream, no result filter; works while upstream is down", async () => {
    const h = await setup({ connect: false });
    const r = await call(h, LOCAL_TOOL.name, { approvalId: "apr_1" });
    expect(jsonOf(r)).toEqual({ ok: true });
    expect(h.localCalls).toEqual([{ args: { approvalId: "apr_1" }, sessionId: "sess-local" }]);
    expect(h.intercepted).toEqual([]);
    expect(h.fake.calls).toEqual([]);
  });

  it("shadow an upstream tool with the same name (never forwarded)", async () => {
    const h = await setup({ tools: [...FAKE_TOOLS, { ...LOCAL_TOOL, description: "upstream" }] });
    const listed = await h.agent.listTools();
    expect(listed.tools.filter((t) => t.name === LOCAL_TOOL.name)).toEqual([LOCAL_TOOL]);
    await call(h, LOCAL_TOOL.name, {});
    expect(h.fake.calls).toEqual([]);
  });

  it("a throwing handler ⇒ deny firewall.internal_error", async () => {
    const h = await setup({ local: { call: () => Promise.reject(new Error("boom")) } });
    expect(jsonOf(await call(h, LOCAL_TOOL.name, { a: 1 }))).toMatchObject({
      ruleId: "firewall.internal_error",
    });
    expect(h.logs.join("\n")).toContain("firewall_check_approval failed: Error");
  });

  it("refuses duplicate local tool names (configuration error)", () => {
    const fake = fakeUpstream();
    const upstream = new Upstream({ factory: fake.factory, redact });
    const t: LocalTool = { tool: LOCAL_TOOL, call: () => Promise.resolve({ content: [] }) };
    expect(() => createProxyServer({ upstream, localTools: [t, t] })).toThrow();
  });
});

describe("openDirectCall", () => {
  it("forwards once with the current schema and tags a ForwardReport", async () => {
    const h = await setup();
    const opened = await h.proxy.openDirectCall("create_refund", new AbortController().signal);
    if (!opened.ok) throw new Error(opened.error.code);
    expect(opened.value.toolClass).toBe("money");
    expect(opened.value.inputSchema).toEqual(FAKE_TOOLS[1]?.inputSchema);
    expect(Object.isFrozen(opened.value.inputSchema)).toBe(true);
    const r = await opened.value.forward({ payment_id: "pay_1", amount: 100 });
    expect(forwardReportOf(r)).toMatchObject({ sent: true, kind: "ok" });
    const twice = await opened.value.forward({ payment_id: "pay_1", amount: 100 });
    expect(jsonOf(twice)).toMatchObject({ ruleId: "firewall.forward_twice" });
    expect(h.fake.calls.filter((c) => c.name === "create_refund")).toHaveLength(1);
  });

  it("refuses after settle, for unknown / local tools, and when upstream is down", async () => {
    const h = await setup();
    const opened = await h.proxy.openDirectCall("create_refund", new AbortController().signal);
    if (!opened.ok) throw new Error(opened.error.code);
    opened.value.settle();
    expect(jsonOf(await opened.value.forward({}))).toMatchObject({
      ruleId: "firewall.forward_after_settle",
    });
    const unknown = await h.proxy.openDirectCall("nope", new AbortController().signal);
    expect(!unknown.ok && unknown.error.code).toBe("firewall.unknown_tool");
    const local = await h.proxy.openDirectCall(LOCAL_TOOL.name, new AbortController().signal);
    expect(!local.ok && local.error.code).toBe("firewall.unknown_tool");
    h.fake.setFailing(true);
    await h.fake.dropConnection();
    await h.upstream.close();
    const down = await h.proxy.openDirectCall("create_refund", new AbortController().signal);
    expect(!down.ok && down.error.code).toBe("upstream_unavailable");
    expect(h.fake.calls).toEqual([]);
  });

  it("refuses to send when the tool's schema changed after opening", async () => {
    const h = await setup();
    const opened = await h.proxy.openDirectCall("create_refund", new AbortController().signal);
    if (!opened.ok) throw new Error(opened.error.code);
    h.fake.setTools(
      FAKE_TOOLS.map((t) =>
        t.name === "create_refund"
          ? { ...t, inputSchema: { type: "object", properties: { evil: { type: "string" } } } }
          : t,
      ),
    );
    await h.fake.notifyListChanged();
    await new Promise((r) => setTimeout(r, 20));
    const r = await opened.value.forward({ payment_id: "pay_1", amount: 1 });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_unavailable", forwarded: false });
    expect(h.fake.calls.filter((c) => c.name === "create_refund")).toEqual([]);
  });

  it("a sent timeout carries a one-use RetryForward (T010)", async () => {
    const h = await setup({ callTimeoutMs: 30 });
    h.fake.setHandler((_n, _a, signal) => hang(signal));
    const opened = await h.proxy.openDirectCall("create_refund", new AbortController().signal);
    if (!opened.ok) throw new Error(opened.error.code);
    const r = await opened.value.forward({ payment_id: "pay_1", amount: 1 });
    expect(forwardReportOf(r)).toMatchObject({ kind: "upstream_timeout", sent: true });
    expect(retryForwardOf(r)).toBeTypeOf("function");
  });
});
