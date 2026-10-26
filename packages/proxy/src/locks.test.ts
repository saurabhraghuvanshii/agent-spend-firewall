import type { Result } from "@asf/core";
import { describe, expect, it } from "vitest";
import { createKeyedMutex, createMutex, MAX_LOCK_WAIT_MS, type Release } from "./locks.js";

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

const W = { timeoutMs: 1000 };

describe("createMutex", () => {
  it("grants immediately when free and serialises holders in FIFO order", async () => {
    const m = createMutex();
    const first = unwrap(await m.acquire(W));
    expect(m.isLocked()).toBe(true);
    const order: number[] = [];
    const waits = [1, 2, 3].map((n) =>
      m.acquire(W).then((r) => {
        order.push(n);
        return unwrap(r);
      }),
    );
    expect(m.waiting()).toBe(3);
    first();
    const r1 = await waits[0];
    expect(order).toEqual([1]);
    r1?.();
    const r2 = await waits[1];
    r2?.();
    const r3 = await waits[2];
    expect(order).toEqual([1, 2, 3]);
    r3?.();
    expect(m.isLocked()).toBe(false);
  });

  it("times out with firewall.busy and the waiter never acquires later", async () => {
    const m = createMutex();
    const hold = unwrap(await m.acquire(W));
    const r = await m.acquire({ timeoutMs: 10 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("firewall.busy");
    expect(m.waiting()).toBe(0);
    hold();
    expect(m.isLocked()).toBe(false);
  });

  it("timeoutMs 0 only succeeds when free; invalid timeouts fail closed", async () => {
    const m = createMutex();
    const hold = unwrap(await m.acquire({ timeoutMs: 0 }));
    expect((await m.acquire({ timeoutMs: 0 })).ok).toBe(false);
    hold();
    for (const t of [-1, 1.5, Number.NaN, MAX_LOCK_WAIT_MS + 1]) {
      const r = await m.acquire({ timeoutMs: t });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("firewall.busy");
    }
    expect(m.isLocked()).toBe(false);
  });

  it("abort while waiting ⇒ firewall.cancelled; already aborted ⇒ cancelled without queueing", async () => {
    const m = createMutex();
    const hold = unwrap(await m.acquire(W));
    const ac = new AbortController();
    const p = m.acquire({ timeoutMs: 1000, signal: ac.signal });
    ac.abort();
    const r = await p;
    expect(!r.ok && r.error.code).toBe("firewall.cancelled");
    expect(m.waiting()).toBe(0);
    const pre = await m.acquire({ timeoutMs: 1000, signal: ac.signal });
    expect(!pre.ok && pre.error.code).toBe("firewall.cancelled");
    hold();
    expect(m.isLocked()).toBe(false);
  });

  it("release is idempotent (a double release never frees another holder's lock)", async () => {
    const m = createMutex();
    const a = unwrap(await m.acquire(W));
    const pb = m.acquire(W);
    a();
    const b = unwrap(await pb);
    a(); // stale double release
    expect(m.isLocked()).toBe(true);
    const r = await m.acquire({ timeoutMs: 5 });
    expect(r.ok).toBe(false);
    b();
    expect(m.isLocked()).toBe(false);
  });

  it("released in finally when the critical section throws", async () => {
    const m = createMutex();
    const section = async (): Promise<void> => {
      const release = unwrap(await m.acquire(W));
      try {
        await Promise.resolve();
        throw new Error("boom");
      } finally {
        release();
      }
    };
    await expect(section()).rejects.toThrow("boom");
    expect(m.isLocked()).toBe(false);
    unwrap(await m.acquire({ timeoutMs: 0 }))();
  });
});

describe("createKeyedMutex", () => {
  it("keys are independent; same key serialises; idle keys are dropped", async () => {
    const k = createKeyedMutex();
    const a = unwrap(await k.acquire("pay_A", W));
    const b = unwrap(await k.acquire("pay_B", { timeoutMs: 0 }));
    expect(k.size()).toBe(2);
    const sameKey = await k.acquire("pay_A", { timeoutMs: 10 });
    expect(!sameKey.ok && sameKey.error.code).toBe("firewall.busy");
    let got: Release | undefined;
    const waiting = k.acquire("pay_A", W).then((r) => {
      got = unwrap(r);
    });
    a();
    await waiting;
    expect(got).toBeDefined();
    got?.();
    got?.();
    b();
    expect(k.size()).toBe(0);
  });

  it("a cancelled waiter does not leak its key", async () => {
    const k = createKeyedMutex();
    const a = unwrap(await k.acquire("x", W));
    const ac = new AbortController();
    const p = k.acquire("x", { timeoutMs: 1000, signal: ac.signal });
    ac.abort();
    expect((await p).ok).toBe(false);
    a();
    expect(k.size()).toBe(0);
  });
});
