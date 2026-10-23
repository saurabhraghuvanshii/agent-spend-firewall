import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalJson, type Result } from "@asf/core";
import { openAuditStore, type AuditStore, type RecordAttemptInput } from "./audit-store.js";

let dir: string;
let dbPath: string;
let nowMs: number;
const T0 = Date.parse("2026-10-23T10:00:00.000Z");
const MIN = 60_000;
const opened: AuditStore[] = [];
const rawOpened: Database.Database[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-activity-"));
  dbPath = join(dir, "audit.db");
  nowMs = T0;
});

afterEach(() => {
  for (const s of opened.splice(0)) s.close();
  for (const d of rawOpened.splice(0)) if (d.open) d.close();
  rmSync(dir, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r.value;
}

function open(extra: Partial<Parameters<typeof openAuditStore>[0]> = {}): AuditStore {
  let n = 0;
  const s = unwrap(
    openAuditStore({
      path: dbPath,
      clock: () => new Date(nowMs),
      idGen: () => `gen-${String(++n)}`,
      ...extra,
    }),
  );
  opened.push(s);
  return s;
}

function raw(): Database.Database {
  const d = new Database(dbPath);
  rawOpened.push(d);
  return d;
}

const attempt = (id: string, over: Partial<RecordAttemptInput> = {}): RecordAttemptInput => ({
  sessionId: "sess-1",
  tool: "create_refund",
  args: { payment_id: "pay_123", amount: 50_000 },
  reason: "customer reported a duplicate charge",
  decision: "allow",
  matchedRules: ["refund.allow"],
  id,
  ...over,
});

/** Insert a row directly (INSERT is not blocked by the append-only triggers). */
function rawInsert(seq: number, id: string, kind: string, body: string, salt: string): void {
  const h = (c: string): string => c.repeat(64);
  raw()
    .prepare(
      "INSERT INTO audit_log (seq, id, kind, body_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .run(seq, id, kind, body, h(salt), h(salt === "e" ? "f" : "e"));
}

function canon(v: unknown): string {
  const c = canonicalJson(v);
  if (!c.ok) throw new Error("not canonical");
  return c.value;
}

describe("readActivitySince", () => {
  it("returns attempts at or after the cutoff, oldest first, and stops scanning at the cutoff", () => {
    // 20 old rows, then 2 recent ones; a 3-row scan cap proves the scan stops at the first old row.
    const s = open({ maxActivityRows: 3 });
    for (let i = 0; i < 20; i++) unwrap(s.recordAttempt(attempt(`old-${String(i)}`)));
    nowMs = T0 + 30 * MIN;
    unwrap(s.recordAttempt(attempt("new-1")));
    nowMs = T0 + 31 * MIN;
    unwrap(s.recordAttempt(attempt("new-2")));
    const rows = unwrap(s.readActivitySince(T0 + 15 * MIN));
    expect(rows.map((r) => r.attempt.id)).toEqual(["new-1", "new-2"]);
    expect(rows.every((r) => r.outcome === undefined)).toBe(true);
  });

  it("includes a record exactly at the cutoff and excludes one 1 ms earlier", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("a")));
    expect(unwrap(s.readActivitySince(T0)).map((r) => r.attempt.id)).toEqual(["a"]);
    expect(unwrap(s.readActivitySince(T0 + 1))).toEqual([]);
  });

  it("pairs an in-window attempt with its outcome", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("a")));
    nowMs = T0 + MIN;
    unwrap(s.recordOutcome({ attemptId: "a", outcome: "success", latencyMs: 5 }));
    const rows = unwrap(s.readActivitySince(T0));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.outcome?.outcome).toBe("success");
    expect(rows[0]?.attempt.argsRedacted).toEqual({ payment_id: "pay_123", amount: 50_000 });
  });

  it("includes an attempt older than the cutoff whose outcome is in the window", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("old", { decision: "require_approval" })));
    unwrap(s.recordAttempt(attempt("old-pending", { decision: "require_approval" })));
    nowMs = T0 + 40 * MIN;
    unwrap(s.recordOutcome({ attemptId: "old", outcome: "success", latencyMs: 1 }));
    const rows = unwrap(s.readActivitySince(T0 + 30 * MIN));
    expect(rows.map((r) => [r.attempt.id, r.outcome?.outcome])).toEqual([["old", "success"]]);
  });

  it("compares parsed instants, not strings (offset timestamps)", () => {
    const s = open();
    // 15:30+05:30 is 10:00Z; as a string it sorts after "2026-10-23T10:00:00.001Z".
    unwrap(s.recordAttempt(attempt("ist", { ts: "2026-10-23T15:30:00.000+05:30" })));
    expect(unwrap(s.readActivitySince(T0)).map((r) => r.attempt.id)).toEqual(["ist"]);
    expect(unwrap(s.readActivitySince(T0 + 1))).toEqual([]);
  });

  it("returns an empty list for an empty store", () => {
    expect(unwrap(open().readActivitySince(0))).toEqual([]);
  });

  it("works on a read-only store", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("a")));
    const ro = open({ readonly: true });
    expect(unwrap(ro.readActivitySince(T0)).map((r) => r.attempt.id)).toEqual(["a"]);
  });

  it("fails closed on an unreadable row in the window", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("a")));
    rawInsert(2, "junk", "attempt", "{not json", "a");
    const r = s.readActivitySince(T0);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("audit.activity_invalid");
      expect(JSON.stringify(r.error)).not.toContain("pay_123");
    }
  });

  it("fails closed on a non-canonical (edited) row in the window", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("a")));
    const body = canon({
      kind: "attempt",
      id: "b",
      ts: new Date(T0).toISOString(),
      sessionId: "s",
      tool: "create_refund",
      argsRedacted: { amount: 1 },
      reason: "r",
      decision: "allow",
      matchedRules: [],
    });
    rawInsert(2, "b", "attempt", ` ${body}`, "b");
    expect(s.readActivitySince(T0).ok).toBe(false);
  });

  it("fails closed when an in-window outcome's attempt is missing", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt("a")));
    const body = canon({
      kind: "outcome",
      id: "o-orphan",
      attemptId: "ghost",
      ts: new Date(T0).toISOString(),
      outcome: "success",
      latencyMs: 1,
    });
    rawInsert(2, "o-orphan", "outcome", body, "c");
    const r = s.readActivitySince(T0);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.activity_invalid");
  });

  it("fails closed when an outcome precedes its attempt", () => {
    const s = open();
    const body = canon({
      kind: "outcome",
      id: "o-early",
      attemptId: "later",
      ts: new Date(T0).toISOString(),
      outcome: "success",
      latencyMs: 1,
    });
    rawInsert(1, "o-early", "outcome", body, "d");
    unwrap(s.recordAttempt(attempt("later")));
    expect(s.readActivitySince(T0).ok).toBe(false);
  });

  it("fails closed when the window holds more rows than the cap", () => {
    const s = open({ maxActivityRows: 2 });
    for (const id of ["a", "b", "c"]) unwrap(s.recordAttempt(attempt(id)));
    const r = s.readActivitySince(T0);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.activity_too_large");
    // A window that fits is fine.
    nowMs = T0 + MIN;
    unwrap(s.recordAttempt(attempt("d")));
    expect(unwrap(s.readActivitySince(T0 + MIN)).map((x) => x.attempt.id)).toEqual(["d"]);
  });

  it("rejects a non-finite cutoff and a closed store", () => {
    const s = open();
    expect(s.readActivitySince(Number.NaN).ok).toBe(false);
    expect(s.readActivitySince(Number.POSITIVE_INFINITY).ok).toBe(false);
    s.close();
    const r = s.readActivitySince(0);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.read_failed");
  });

  it("rejects an invalid maxActivityRows at open", () => {
    const r = openAuditStore({ path: dbPath, maxActivityRows: 0 });
    expect(r.ok).toBe(false);
  });
});
