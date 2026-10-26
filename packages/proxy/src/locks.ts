/**
 * In-process async mutexes for the money path (T008).
 *
 * - FIFO: waiters are granted in arrival order.
 * - Bounded wait: every `acquire` carries `timeoutMs`; a waiter not granted in time gets `err("firewall.busy")` and
 *   leaves the queue (it never acquires later).
 * - Cancellable: an aborted `signal` (before or while waiting) ⇒ `err("firewall.cancelled")`.
 * - `release` is idempotent: calling it twice never releases a lock held by someone else.
 * - `acquire` never rejects.
 *
 * These serialise calls inside ONE proxy process only (one stdio agent per process). They are not a distributed lock.
 */
import { err, ok, type Result } from "@asf/core";

export type Release = () => void;

export interface AcquireOptions {
  /** Max integer ms to wait (0 = only if free right now). Invalid ⇒ `err("firewall.busy")` (fail closed). */
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface Mutex {
  acquire(opts: AcquireOptions): Promise<Result<Release>>;
  /** True while held. */
  isLocked(): boolean;
  /** Number of queued waiters. */
  waiting(): number;
}

export interface KeyedMutex {
  /** Independent mutex per `key`; idle keys are dropped (no unbounded growth). */
  acquire(key: string, opts: AcquireOptions): Promise<Result<Release>>;
  /** Number of keys currently held or waited on. */
  size(): number;
}

/** Upper bound for a lock wait (10 minutes). */
export const MAX_LOCK_WAIT_MS = 600_000;

interface Waiter {
  grant(): void;
}

const busy = (): Result<Release> =>
  err("firewall.busy", "another money action is in progress; try again shortly");
const cancelled = (): Result<Release> =>
  err("firewall.cancelled", "the request was cancelled while waiting for a lock");

export function createMutex(): Mutex {
  let held = false;
  const queue: Waiter[] = [];

  /** A release function for the current holder; idempotent. */
  const makeRelease = (): Release => {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      const next = queue.shift();
      if (next === undefined) held = false;
      else next.grant(); // ownership passes directly: `held` stays true
    };
  };

  return {
    isLocked: () => held,
    waiting: () => queue.length,
    acquire(opts: AcquireOptions): Promise<Result<Release>> {
      const { timeoutMs, signal } = opts;
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > MAX_LOCK_WAIT_MS) {
        return Promise.resolve(busy());
      }
      if (signal?.aborted === true) return Promise.resolve(cancelled());
      if (!held && queue.length === 0) {
        held = true;
        return Promise.resolve(ok(makeRelease()));
      }
      if (timeoutMs === 0) return Promise.resolve(busy());
      return new Promise<Result<Release>>((resolve) => {
        // `timer` is assigned below before any callback can run (grant / abort / timeout are all async).
        const cleanup = (): void => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
        };
        const leave = (r: Result<Release>): void => {
          const i = queue.indexOf(waiter);
          if (i < 0) return; // already granted
          queue.splice(i, 1);
          cleanup();
          resolve(r);
        };
        const onAbort = (): void => {
          leave(cancelled());
        };
        const waiter: Waiter = {
          grant: () => {
            cleanup();
            resolve(ok(makeRelease()));
          },
        };
        queue.push(waiter);
        const timer = setTimeout(() => {
          leave(busy());
        }, timeoutMs);
        signal?.addEventListener("abort", onAbort, { once: true });
      });
    },
  };
}

export function createKeyedMutex(): KeyedMutex {
  const locks = new Map<string, { mutex: Mutex; users: number }>();
  return {
    size: () => locks.size,
    async acquire(key: string, opts: AcquireOptions): Promise<Result<Release>> {
      let entry = locks.get(key);
      if (entry === undefined) {
        entry = { mutex: createMutex(), users: 0 };
        locks.set(key, entry);
      }
      const e = entry;
      e.users++;
      const drop = (): void => {
        e.users--;
        if (e.users === 0 && locks.get(key) === e) locks.delete(key);
      };
      const r = await e.mutex.acquire(opts);
      if (!r.ok) {
        drop();
        return r;
      }
      let done = false;
      const release = r.value;
      return ok(() => {
        if (done) return;
        done = true;
        release();
        drop();
      });
    },
  };
}
