import { describe, expect, it } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { composeInterceptors, firewallChain, type Stage } from "./interceptor-chain.js";
import { moneyArgsStage } from "./money-args.js";
import type { CallContext, Forward } from "./server.js";
import { jsonOf } from "./test-support/fake-upstream.js";

const OK: CallToolResult = { content: [{ type: "text", text: '{"ok":true}' }] };

function ctx(args: Record<string, unknown> = { a: 1 }): CallContext {
  return {
    tool: "create_refund",
    toolClass: "money",
    args: Object.freeze({ ...args }),
    inputSchema: { type: "object" },
    sessionId: "s",
    signal: new AbortController().signal,
  };
}

function recordingForward(): { forward: Forward; sent: Record<string, unknown>[] } {
  const sent: Record<string, unknown>[] = [];
  return {
    sent,
    forward: (args) => {
      sent.push(args);
      return Promise.resolve(OK);
    },
  };
}

describe("composeInterceptors", () => {
  it("runs stages in order and forwards the last context's args (fresh object)", async () => {
    const order: string[] = [];
    const a: Stage = (c, next) => {
      order.push("a");
      return next({ ...c, args: { ...c.args, a: 2 } });
    };
    const b: Stage = (c, next) => {
      order.push("b");
      return next(c);
    };
    const { forward, sent } = recordingForward();
    const original = ctx();
    const r = await composeInterceptors([a, b]).intercept(original, forward);
    expect(r).toBe(OK);
    expect(order).toEqual(["a", "b"]);
    expect(sent).toEqual([{ a: 2 }]);
    expect(sent[0]).not.toBe(original.args);
  });

  it("no stages ⇒ plain forward", async () => {
    const { forward, sent } = recordingForward();
    await composeInterceptors([]).intercept(ctx(), forward);
    expect(sent).toEqual([{ a: 1 }]);
  });

  it("a stage returning early never reaches later stages or upstream", async () => {
    const deny: CallToolResult = { isError: true, content: [{ type: "text", text: "{}" }] };
    let reached = false;
    const { forward, sent } = recordingForward();
    const r = await composeInterceptors([
      () => Promise.resolve(deny),
      (c, next) => {
        reached = true;
        return next(c);
      },
    ]).intercept(ctx(), forward);
    expect(r).toBe(deny);
    expect(reached).toBe(false);
    expect(sent).toEqual([]);
  });

  it("forwards at most once even if a stage calls next twice", async () => {
    const { forward, sent } = recordingForward();
    let second: CallToolResult | undefined;
    await composeInterceptors([
      async (c, next) => {
        const first = await next(c);
        second = await next(c);
        return first;
      },
    ]).intercept(ctx(), forward);
    expect(sent).toHaveLength(1);
    expect(second?.isError).toBe(true);
    expect(jsonOf(second)).toMatchObject({ decision: "deny", ruleId: "firewall.forward_twice" });
  });

  it("a throwing stage ⇒ structured deny, no forward, logs the error class only", async () => {
    const logs: string[] = [];
    const { forward, sent } = recordingForward();
    const r = await composeInterceptors(
      [
        () => {
          throw new TypeError("contains agent input SECRET");
        },
      ],
      { logger: (l) => logs.push(l) },
    ).intercept(ctx(), forward);
    expect(r.isError).toBe(true);
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.interceptor_error" });
    expect(String(jsonOf(r)["message"])).toContain("not");
    expect(sent).toEqual([]);
    expect(logs.join("\n")).toContain("TypeError");
    expect(logs.join("\n")).not.toContain("SECRET");
  });

  it("a stage that throws after forwarding says the call may have been sent", async () => {
    const { forward, sent } = recordingForward();
    const r = await composeInterceptors([
      async (c, next) => {
        await next(c);
        throw new Error("post-forward failure");
      },
    ]).intercept(ctx(), forward);
    expect(sent).toHaveLength(1);
    expect(jsonOf(r)).toMatchObject({ ruleId: "firewall.interceptor_error" });
    expect(String(jsonOf(r)["message"])).toContain("sent upstream");
  });
});

describe("firewallChain", () => {
  const REASON = "Customer cust_123 was double charged for order_456; refunding the duplicate.";
  const refundCtx = (args: Record<string, unknown>): CallContext => ({
    tool: "create_refund",
    toolClass: "money",
    args: Object.freeze({ ...args }),
    inputSchema: {
      type: "object",
      properties: { payment_id: { type: "string" }, amount: { type: "number" } },
    },
    sessionId: "s",
    signal: new AbortController().signal,
  });

  it("always puts moneyArgsStage first, then the later stages in order", () => {
    const a: Stage = (c, next) => next(c);
    const b: Stage = (c, next) => next(c);
    expect(firewallChain()).toEqual([moneyArgsStage]);
    expect(firewallChain(a, b)).toEqual([moneyArgsStage, a, b]);
    expect(Object.isFrozen(firewallChain(a))).toBe(true);
  });

  it("a later stage sees stripped args and untrustedReason", async () => {
    const seen: CallContext[] = [];
    const later: Stage = (c, next) => {
      seen.push(c);
      return next(c);
    };
    const { forward, sent } = recordingForward();
    const r = await composeInterceptors(firewallChain(later)).intercept(
      refundCtx({ payment_id: "pay_1", amount: 100, reason: REASON }),
      forward,
    );
    expect(r).toBe(OK);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.args).toEqual({ payment_id: "pay_1", amount: 100 });
    expect(seen[0]?.untrustedReason).toBe(REASON);
    expect(sent).toEqual([{ payment_id: "pay_1", amount: 100 }]);
  });

  it("a later stage is never reached when moneyArgsStage denies", async () => {
    let reached = false;
    const later: Stage = (c, next) => {
      reached = true;
      return next(c);
    };
    const { forward, sent } = recordingForward();
    const r = await composeInterceptors(firewallChain(later)).intercept(
      refundCtx({ payment_id: "pay_1", amount: 100 }),
      forward,
    );
    expect(jsonOf(r)).toMatchObject({ decision: "deny", ruleId: "firewall.reason_required" });
    expect(reached).toBe(false);
    expect(sent).toEqual([]);
  });
});
