/**
 * T010 server seams: the one-extra-send `RetryForward` capability and the separate money-call timeout.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  createProxyServer,
  forwardReportOf,
  retryForwardOf,
  type CallInterceptor,
  type ProxyServer,
  type RetryForward,
} from "./server.js";
import { fakeUpstream, hang, jsonOf, type FakeUpstream } from "./test-support/fake-upstream.js";
import { Upstream } from "./upstream.js";

interface Harness {
  agent: Client;
  fake: FakeUpstream;
  upstream: Upstream;
  proxy: ProxyServer;
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
  interceptor: CallInterceptor,
  opts: { callTimeoutMs?: number; moneyCallTimeoutMs?: number } = {},
): Promise<Harness> {
  const fake = fakeUpstream();
  const upstream = new Upstream({ factory: fake.factory, sleep: () => Promise.resolve() });
  const proxy = createProxyServer({
    upstream,
    interceptor,
    sessionId: "s",
    ...(opts.callTimeoutMs === undefined ? {} : { callTimeoutMs: opts.callTimeoutMs }),
    ...(opts.moneyCallTimeoutMs === undefined
      ? {}
      : { moneyCallTimeoutMs: opts.moneyCallTimeoutMs }),
  });
  await upstream.connect();
  const [a, p] = InMemoryTransport.createLinkedPair();
  await proxy.connect(p);
  const agent = new Client({ name: "a", version: "0" }, { capabilities: {} });
  await agent.connect(a);
  const h = { agent, fake, upstream, proxy };
  open.push(h);
  return h;
}

const call = (h: Harness, name: string, args: Record<string, unknown>): Promise<CallToolResult> =>
  h.agent.request(
    { method: "tools/call", params: { name, arguments: args } },
    CallToolResultSchema,
  );

describe("RetryForward (T010)", () => {
  it("issued on a timeout: one extra send; a second use is refused; the retry's result has no token", async () => {
    let n = 0;
    const seen: { first?: CallToolResult; second?: CallToolResult; third?: CallToolResult } = {};
    const h = await setup(
      {
        intercept: async (ctx, forward) => {
          const r1 = await forward({ ...ctx.args, n: 1 });
          seen.first = r1;
          const retry = retryForwardOf(r1);
          if (retry === undefined) return r1;
          const r2 = await retry({ ...ctx.args, n: 2 });
          seen.second = r2;
          seen.third = await retry({ ...ctx.args, n: 3 });
          expect(retryForwardOf(r2)).toBeUndefined();
          return r2;
        },
      },
      { moneyCallTimeoutMs: 30 },
    );
    h.fake.setHandler((_name, args, signal) => {
      n++;
      return args?.["n"] === 1
        ? hang(signal)
        : Promise.resolve({ content: [{ type: "text", text: '{"id":"rfnd_ok"}' }] });
    });
    const r = await call(h, "create_refund", { payment_id: "pay_1", amount: 100 });
    expect(jsonOf(r)).toEqual({ id: "rfnd_ok" });
    expect(n).toBe(2);
    expect(forwardReportOf(seen.first ?? r)).toMatchObject({
      kind: "upstream_timeout",
      sent: true,
    });
    expect(forwardReportOf(seen.second ?? r)).toMatchObject({ kind: "ok", sent: true });
    expect(jsonOf(seen.third)).toMatchObject({ ruleId: "firewall.forward_twice" });
    expect(h.fake.calls.map((c) => c.args?.["n"])).toEqual([1, 2]);
  });

  it("not issued for a success, a tool error, or a call that was never sent", async () => {
    const tokens: Array<RetryForward | undefined> = [];
    const h = await setup({
      intercept: async (ctx, forward) => {
        const r = await forward(
          ctx.args["unsendable"] === true ? { v: Number.NaN } : { ...ctx.args },
        );
        tokens.push(retryForwardOf(r));
        return r;
      },
    });
    h.fake.setHandler((_n, args) =>
      Promise.resolve(
        args?.["fail"] === true
          ? { isError: true, content: [{ type: "text", text: "bad" }] }
          : { content: [{ type: "text", text: "{}" }] },
      ),
    );
    await call(h, "create_refund", { amount: 1 });
    await call(h, "create_refund", { amount: 1, fail: true });
    // Refused by forward (not plain JSON) ⇒ never sent ⇒ no token.
    await call(h, "create_refund", { amount: 1, unsendable: true });
    expect(tokens).toEqual([undefined, undefined, undefined]);
  });

  it("issued when the connection drops mid-call (sent upstream_error); refused after the call settled", async () => {
    let kept: RetryForward | undefined;
    const h = await setup({
      intercept: async (ctx, forward) => {
        const r = await forward({ ...ctx.args });
        kept = retryForwardOf(r);
        return r;
      },
    });
    h.fake.setHandler((_n, _a, signal) => {
      void h.fake.dropConnection();
      return hang(signal);
    });
    const r = await call(h, "create_refund", { amount: 1 });
    expect(jsonOf(r)).toMatchObject({ error: "upstream_error", forwarded: true });
    expect(kept).toBeDefined();
    const late = await kept?.({ amount: 1 });
    expect(jsonOf(late)).toMatchObject({ ruleId: "firewall.forward_after_settle" });
  });
});

describe("money-call timeout (T010)", () => {
  it("applies to money tools only; reads keep the general timeout", async () => {
    const h = await setup(
      { intercept: (ctx, forward) => forward({ ...ctx.args }) },
      { moneyCallTimeoutMs: 30, callTimeoutMs: 5_000 },
    );
    h.fake.setHandler(
      () =>
        new Promise((res) => {
          setTimeout(() => {
            res({ content: [{ type: "text", text: "{}" }] });
          }, 80);
        }),
    );
    expect(jsonOf(await call(h, "create_refund", { amount: 1 }))).toMatchObject({
      error: "upstream_timeout",
    });
    expect((await call(h, "fetch_all_payments", { count: 1 })).isError).not.toBe(true);
  });
});
