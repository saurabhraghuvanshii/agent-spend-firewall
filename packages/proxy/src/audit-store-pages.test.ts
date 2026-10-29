/** T013: bounded audit reads for the dashboard API (`readPage`, `readSession`). */
import type { Result } from "@asf/core";
import { afterEach, describe, expect, it } from "vitest";
import {
  MAX_PAGE_ROWS,
  openAuditStore,
  type AuditStore,
  type RecordAttemptInput,
} from "./audit-store.js";

const opened: AuditStore[] = [];
afterEach(() => {
  for (const s of opened.splice(0)) s.close();
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

const attempt = (sessionId: string): RecordAttemptInput => ({
  sessionId,
  tool: "create_refund",
  args: { payment_id: "pay_1", amount: 1_000 },
  reason: "duplicate charge",
  decision: "allow",
  matchedRules: [],
});

function seeded(): AuditStore {
  const s = unwrap(openAuditStore({ path: ":memory:" }));
  opened.push(s);
  // seq 1 attempt A(s1), 2 attempt B(s2), 3 outcome A, 4 mode, 5 outcome B
  const a = unwrap(s.recordAttempt(attempt("s1")));
  const b = unwrap(s.recordAttempt(attempt("s2")));
  unwrap(s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 1 }));
  unwrap(s.changeMode({ killSwitch: true, actor: "dashboard:admin" }));
  unwrap(s.recordOutcome({ attemptId: b.id, outcome: "success", latencyMs: 1 }));
  return s;
}

const seqs = (r: Result<Array<{ seq: number }>>): number[] => unwrap(r).map((x) => x.seq);

describe("readPage", () => {
  it("newest first, cursor below beforeSeq, tail above afterSeq", () => {
    const s = seeded();
    expect(seqs(s.readPage({ limit: 2 }))).toEqual([5, 4]);
    expect(seqs(s.readPage({ limit: 2, beforeSeq: 4 }))).toEqual([3, 2]);
    expect(seqs(s.readPage({ limit: 10, beforeSeq: 1 }))).toEqual([]);
    expect(seqs(s.readPage({ limit: 2, afterSeq: 2 }))).toEqual([3, 4]);
    expect(seqs(s.readPage({ limit: 10, afterSeq: 5 }))).toEqual([]);
  });

  it.each([
    [{ limit: 0 }],
    [{ limit: MAX_PAGE_ROWS + 1 }],
    [{ limit: 1.5 }],
    [{ limit: 1, beforeSeq: -1 }],
    [{ limit: 1, beforeSeq: 2, afterSeq: 1 }],
    [{ limit: 1, extra: 1 } as unknown as { limit: number }],
  ])("bad query %o ⇒ err", (q) => {
    const s = seeded();
    const r = s.readPage(q);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_input");
  });

  it("closed store ⇒ err", () => {
    const s = seeded();
    s.close();
    expect(s.readPage({ limit: 1 }).ok).toBe(false);
    expect(s.readSession("s1", 1).ok).toBe(false);
  });
});

describe("readSession", () => {
  it("a session's attempts and the records referencing them, oldest first", () => {
    const s = seeded();
    const rows = unwrap(s.readSession("s1", 100));
    expect(rows.map((r) => r.seq)).toEqual([1, 3]);
    expect(seqs(s.readSession("s2", 100))).toEqual([2, 5]);
    expect(seqs(s.readSession("s2", 1))).toEqual([2]);
    expect(seqs(s.readSession("nope", 100))).toEqual([]);
  });

  it("bad input ⇒ err", () => {
    const s = seeded();
    expect(s.readSession("", 1).ok).toBe(false);
    expect(s.readSession("s1", 0).ok).toBe(false);
    expect(s.readSession("x".repeat(257), 1).ok).toBe(false);
  });
});
