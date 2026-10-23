/**
 * In-memory, deterministic implementations of the policy ports for tests, evals and demos.
 * Pure: no timers, no clock, no I/O.
 */
import { canonicalJson } from "../audit/canonical-json.js";
import type { JsonValue } from "../audit/types.js";
import { err, ok } from "../result.js";
import type {
  Args,
  Clock,
  HistoryPort,
  HistoryQuery,
  PaymentInfo,
  PolicyDeps,
  RazorpayLookupPort,
  StatsPort,
  StatsQuery,
  StatsSummary,
  Timer,
  TimerHandle,
} from "./types.js";

export interface FakeClock extends Clock {
  advance(ms: number): void;
  set(ms: number): void;
}

export function fakeClock(startMs = 1_700_000_000_000): FakeClock {
  let now = startMs;
  return {
    nowMs: () => now,
    advance(ms: number) {
      now += ms;
    },
    set(ms: number) {
      now = ms;
    },
  };
}

export interface FakeTimer extends Timer {
  /** Fire every armed, uncancelled timer. */
  fire(): void;
  /** Every `after()` call, in order. */
  readonly armed: readonly { ms: number; cancelled: boolean; fired: boolean }[];
}

/** Timer that only fires when the test calls `fire()`. Never fires on its own. */
export function fakeTimer(): FakeTimer {
  const armed: { ms: number; cancelled: boolean; fired: boolean }[] = [];
  const resolvers: (() => void)[] = [];
  return {
    armed,
    after(ms: number): TimerHandle {
      let resolve: () => void = () => undefined;
      const promise = new Promise<void>((res) => {
        resolve = res;
      });
      const entry = { ms, cancelled: false, fired: false };
      armed.push(entry);
      resolvers.push(resolve);
      return {
        promise,
        cancel() {
          entry.cancelled = true;
        },
      };
    },
    fire() {
      armed.forEach((t, i) => {
        if (!t.cancelled && !t.fired) {
          t.fired = true;
          resolvers[i]?.();
        }
      });
    },
  };
}

export interface HistoryEntry {
  tool: string;
  args: Args;
  atMs: number;
}

export interface Recording<Q> {
  readonly calls: Q[];
}

/** `hasRecent` is true if an entry for `tool` within `withinMs` of `clock` matches every `match` key. */
export function fakeHistory(
  entries: readonly HistoryEntry[],
  clock: Clock,
): HistoryPort & Recording<HistoryQuery> {
  const calls: HistoryQuery[] = [];
  return {
    calls,
    hasRecent(q) {
      calls.push(q);
      const now = clock.nowMs();
      const hit = entries.some(
        (e) =>
          e.tool === q.tool &&
          e.atMs <= now &&
          e.atMs > now - q.withinMs &&
          Object.entries(q.match).every(([k, v]) => sameJson(e.args[k], v)),
      );
      return Promise.resolve(ok(hit));
    },
  };
}

export function fakeStats(
  source: StatsSummary | ((q: StatsQuery) => StatsSummary),
): StatsPort & Recording<StatsQuery> {
  const calls: StatsQuery[] = [];
  return {
    calls,
    sumLast(q) {
      calls.push(q);
      return Promise.resolve(ok(typeof source === "function" ? source(q) : source));
    },
  };
}

/** Lookup by id; unknown ids return `err("razorpay.not_found")`. */
export function fakeRazorpay(
  payments: readonly PaymentInfo[],
): RazorpayLookupPort & Recording<string> {
  const calls: string[] = [];
  return {
    calls,
    payment(id) {
      calls.push(id);
      const p = payments.find((x) => x.id === id);
      return Promise.resolve(
        p === undefined ? err("razorpay.not_found", "payment not found") : ok(p),
      );
    },
  };
}

/** Ports that always return `err(code)`. */
export const failingPorts = {
  history: (code = "history.unavailable"): HistoryPort => ({
    hasRecent: () => Promise.resolve(err(code, "history unavailable")),
  }),
  stats: (code = "stats.unavailable"): StatsPort => ({
    sumLast: () => Promise.resolve(err(code, "stats unavailable")),
  }),
  razorpay: (code = "razorpay.unavailable"): RazorpayLookupPort => ({
    payment: () => Promise.resolve(err(code, "razorpay unavailable")),
  }),
} as const;

/** Deps with empty history, zero stats, no payments, a fixed clock and a manual timer. */
export function fakeDeps(overrides: Partial<PolicyDeps> = {}): PolicyDeps {
  const clock = overrides.clock ?? fakeClock();
  return {
    history: overrides.history ?? fakeHistory([], clock),
    stats: overrides.stats ?? fakeStats({ amountPaise: 0, count: 0 }),
    razorpay: overrides.razorpay ?? fakeRazorpay([]),
    clock,
    timer: overrides.timer ?? fakeTimer(),
  };
}

function sameJson(a: JsonValue | undefined, b: JsonValue): boolean {
  if (a === undefined) return false;
  const ea = canonicalJson(a);
  const eb = canonicalJson(b);
  return ea.ok && eb.ok && ea.value === eb.value;
}
