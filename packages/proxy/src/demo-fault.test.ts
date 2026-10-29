/** T015 demo-only fault injection: the first create_refund response (and only it) arrives late. */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEMO_DELAY_ENV,
  demoFaultFactory,
  demoFaultWarnings,
  MAX_DEMO_DELAY_MS,
  MIN_DEMO_DELAY_MS,
  parseDemoDelayMs,
} from "./demo-fault.js";
import { fakeUpstream, textOf } from "./test-support/fake-upstream.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { Upstream, type LateResponse, type UpstreamTransportFactory } from "./upstream.js";

interface Scheduled {
  readonly fn: () => void;
  readonly ms: number;
  cancelled: boolean;
}

function manualSchedule(): {
  readonly schedule: (fn: () => void, ms: number) => () => void;
  readonly queue: Scheduled[];
  fire(): void;
} {
  const queue: Scheduled[] = [];
  return {
    queue,
    schedule: (fn, ms) => {
      const s: Scheduled = { fn, ms, cancelled: false };
      queue.push(s);
      return () => {
        s.cancelled = true;
      };
    },
    fire: () => {
      for (const s of queue.splice(0)) if (!s.cancelled) s.fn();
    },
  };
}

const open: Upstream[] = [];
afterEach(async () => {
  for (const u of open.splice(0)) await u.close();
});

const REFUND = { payment_id: "pay_DEMOabcdef", amount: 30_000 };

function setup(delayMs = 15_000) {
  const fake = fakeUpstream();
  const sched = manualSchedule();
  const delayed: number[] = [];
  const u = new Upstream({
    factory: demoFaultFactory(fake.factory, {
      delayMs,
      schedule: sched.schedule,
      onDelayed: () => delayed.push(1),
    }),
    callTimeoutMs: 2_000,
  });
  open.push(u);
  const late: LateResponse[] = [];
  u.onLateResponse((e) => late.push(e));
  return { fake, sched, u, late, delayed };
}

describe("parseDemoDelayMs", () => {
  it("unset / empty ⇒ disabled", () => {
    expect(parseDemoDelayMs(undefined)).toEqual({ ok: true, value: undefined });
    expect(parseDemoDelayMs("")).toEqual({ ok: true, value: undefined });
  });

  it("integers in range are accepted", () => {
    expect(parseDemoDelayMs(String(MIN_DEMO_DELAY_MS))).toEqual({ ok: true, value: 1_000 });
    expect(parseDemoDelayMs("15000")).toEqual({ ok: true, value: 15_000 });
    expect(parseDemoDelayMs(String(MAX_DEMO_DELAY_MS))).toEqual({ ok: true, value: 120_000 });
  });

  it.each(["999", "120001", "0", "-5", "abc", "1e4", "15000.5", " 15000", "0x3a98", "9999999999"])(
    "%j ⇒ refused",
    (raw) => {
      const r = parseDemoDelayMs(raw);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("proxy.bad_demo_delay");
        expect(r.error.message).toContain(DEMO_DELAY_ENV);
      }
    },
  );
});

describe("demoFaultWarnings", () => {
  it("always warns loudly; adds a note when the delay can't cause a timeout", () => {
    const lines = demoFaultWarnings(15_000, 10_000, 15_000);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^WARNING: DEMO FAULT INJECTION IS ON/);
    expect(demoFaultWarnings(5_000, 10_000, 15_000)).toHaveLength(2);
    expect(demoFaultWarnings(10_000, 10_000, 15_000)[1]).toMatch(/will NOT time out/);
  });

  it("warns that the late answer misses the verify window when delay > money timeout + verify wait", () => {
    // Exactly at the edge: still inside the window.
    expect(demoFaultWarnings(25_000, 10_000, 15_000)).toHaveLength(1);
    const late = demoFaultWarnings(25_001, 10_000, 15_000);
    expect(late).toHaveLength(2);
    expect(late[1]).toMatch(/^WARNING: /);
    expect(late[1]).toMatch(/MISS THE VERIFY WINDOW/);
    expect(late[1]).toMatch(/UNKNOWN/);
    expect(late[1]).toContain("10000 + 15000");
  });
});

describe("demoFaultFactory", () => {
  it("rejects an out-of-range delay", () => {
    const fake = fakeUpstream();
    expect(() => demoFaultFactory(fake.factory, { delayMs: 10 })).toThrow(/out of range/);
    expect(() => demoFaultFactory(fake.factory, { delayMs: 1.5e3 + 0.5 })).toThrow();
  });

  it("delays only the FIRST create_refund response: the call is sent, times out, and the answer arrives late", async () => {
    const { fake, sched, u, late, delayed } = setup();
    const first = await u.callTool("create_refund", REFUND, { timeoutMs: 30 });
    // The request reached upstream at once; only the response was held back.
    expect(fake.calls.map((c) => c.name)).toEqual(["create_refund"]);
    expect(first).toMatchObject({ kind: "error", error: "upstream_timeout", forwarded: true });
    expect(delayed).toHaveLength(1);
    expect(sched.queue.map((s) => s.ms)).toEqual([15_000]);
    sched.fire();
    await vi.waitFor(() => {
      expect(late).toHaveLength(1);
    });
    expect(late[0]).toMatchObject({ tool: "create_refund", isError: false, failure: "none" });

    // Second refund: not delayed.
    const second = await u.callTool("create_refund", REFUND, { timeoutMs: 1_000 });
    expect(second.kind).toBe("ok");
    expect(sched.queue).toHaveLength(0);
    expect(delayed).toHaveLength(1);
  });

  it("other tools are never delayed, before or after the fault fired", async () => {
    const { sched, u } = setup();
    const read = await u.callTool("fetch_payment", { payment_id: "pay_X" }, { timeoutMs: 1_000 });
    expect(read.kind).toBe("ok");
    if (read.kind === "ok") expect(textOf(read.result)).toContain("fetch_payment");
    expect(sched.queue).toHaveLength(0);
    // Still armed for the first refund.
    await u.callTool("create_refund", REFUND, { timeoutMs: 30 });
    expect(sched.queue).toHaveLength(1);
    sched.fire();
    const after = await u.callTool("fetch_all_payments", {}, { timeoutMs: 1_000 });
    expect(after.kind).toBe("ok");
  });

  it("fires once per process, across reconnects", async () => {
    const { fake, sched, u } = setup();
    await u.callTool("create_refund", REFUND, { timeoutMs: 30 });
    expect(sched.queue).toHaveLength(1);
    await fake.dropConnection();
    await vi.waitFor(() => {
      expect(u.isConnected()).toBe(false);
    });
    // The held response belonged to the dropped connection: cancelled, never delivered.
    expect(sched.queue[0]?.cancelled).toBe(true);
    const again = await u.callTool("create_refund", REFUND, { timeoutMs: 1_000 });
    expect(again.kind).toBe("ok");
    expect(sched.queue).toHaveLength(1);
  });

  it("with a delay shorter than the call timeout the refund is just slow (ok)", async () => {
    const { sched, u } = setup(1_000);
    const pending = u.callTool("create_refund", REFUND, { timeoutMs: 5_000 });
    await vi.waitFor(() => {
      expect(sched.queue).toHaveLength(1);
    });
    sched.fire();
    const r = await pending;
    expect(r.kind).toBe("ok");
  });
});

describe("demoFaultFactory: a failed send re-arms the fault", () => {
  function failingOnce(): {
    readonly factory: UpstreamTransportFactory;
    readonly sent: JSONRPCMessage[];
    readonly delivered: JSONRPCMessage[];
    failNext: boolean;
    reply(m: JSONRPCMessage): void;
  } {
    const sent: JSONRPCMessage[] = [];
    const delivered: JSONRPCMessage[] = [];
    let current: Transport | undefined;
    const h = {
      sent,
      delivered,
      failNext: true,
      reply: (m: JSONRPCMessage) => {
        current?.onmessage?.(m);
      },
      factory: (): ReturnType<UpstreamTransportFactory> => {
        const inner: Transport = {
          start: () => Promise.resolve(),
          close: () => Promise.resolve(),
          send: (m) => {
            if (h.failNext) {
              h.failNext = false;
              return Promise.reject(new Error("send failed"));
            }
            sent.push(m);
            return Promise.resolve();
          },
        };
        current = inner;
        return { transport: inner, dispose: () => Promise.resolve() };
      },
    };
    return h;
  }

  const refundReq = (id: number): JSONRPCMessage => ({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: "create_refund", arguments: REFUND },
  });
  const resultFor = (id: number): JSONRPCMessage => ({
    jsonrpc: "2.0",
    id,
    result: { content: [] },
  });

  it("the first refund's send rejects ⇒ not delayed later; the next refund is the one delayed", async () => {
    const h = failingOnce();
    const sched = manualSchedule();
    const conn = demoFaultFactory(h.factory, { delayMs: 15_000, schedule: sched.schedule })();
    conn.transport.onmessage = (m) => h.delivered.push(m);
    await expect(conn.transport.send(refundReq(1))).rejects.toThrow(/send failed/);
    // A stray answer for the failed id is not held back.
    h.reply(resultFor(1));
    expect(h.delivered).toHaveLength(1);
    expect(sched.queue).toHaveLength(0);
    // Re-armed: the next refund's answer is the delayed one.
    await conn.transport.send(refundReq(2));
    h.reply(resultFor(2));
    expect(h.delivered).toHaveLength(1);
    expect(sched.queue).toHaveLength(1);
    sched.fire();
    expect(h.delivered).toHaveLength(2);
    // Fired once: a third refund passes straight through.
    await conn.transport.send(refundReq(3));
    h.reply(resultFor(3));
    expect(h.delivered).toHaveLength(3);
  });
});
