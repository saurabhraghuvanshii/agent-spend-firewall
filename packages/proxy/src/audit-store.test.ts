import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  GENESIS_PREV_HASH,
  buildRecord,
  canonicalJson,
  type AuditAttemptBody,
  type AuditRecord,
  type Hasher,
  type Result,
} from "@asf/core";
import {
  MAX_FUTURE_SKEW_MS,
  openAuditStore,
  type AuditStore,
  type RecordAttemptInput,
} from "./audit-store.js";
import { nodeHasher } from "./node-hasher.js";

let dir: string;
let dbPath: string;
const opened: AuditStore[] = [];
const rawOpened: Database.Database[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-audit-"));
  dbPath = join(dir, "nested", "audit.db");
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
      clock: () => new Date("2026-10-23T10:00:00.000Z"),
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

const attempt = (over: Partial<RecordAttemptInput> = {}): RecordAttemptInput => ({
  sessionId: "sess-1",
  tool: "create_refund",
  args: { payment_id: "pay_123", amount: 50_000 },
  reason: "customer reported a duplicate charge",
  decision: "allow",
  matchedRules: ["refund.max_amount"],
  ...over,
});

function seedPairs(s: AuditStore, n: number): AuditRecord[] {
  const out: AuditRecord[] = [];
  for (let i = 0; i < n; i++) {
    const a = unwrap(s.recordAttempt(attempt({ id: `att-${String(i)}` })));
    out.push(a);
    out.push(
      unwrap(
        s.recordOutcome({
          attemptId: a.id,
          outcome: "success",
          latencyMs: 10 + i,
          id: `out-${String(i)}`,
        }),
      ),
    );
  }
  return out;
}

function verifyOk(s: AuditStore) {
  const v = unwrap(s.verify());
  if (!v.ok) throw new Error(`chain broken at seq ${String(v.brokenAt.seq)}: ${v.brokenAt.reason}`);
  return v;
}

describe("openAuditStore", () => {
  it("creates the parent dir, schema and WAL mode", () => {
    open();
    const d = raw();
    expect(d.pragma("journal_mode", { simple: true })).toBe("wal");
    const names = d
      .prepare("SELECT name FROM sqlite_master WHERE type IN ('table','trigger') ORDER BY name")
      .all() as Array<{ name: string }>;
    expect(names.map((n) => n.name)).toEqual([
      "audit_log",
      "audit_log_no_delete",
      "audit_log_no_update",
    ]);
  });

  it("readonly open of a missing file fails", () => {
    const r = openAuditStore({ path: join(dir, "missing.db"), readonly: true });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.open_failed");
  });

  it("readonly open of a non-audit database fails", () => {
    const p = join(dir, "other.db");
    const d = new Database(p);
    d.exec("CREATE TABLE t (x)");
    d.close();
    const r = openAuditStore({ path: p, readonly: true });
    expect(r.ok).toBe(false);
  });

  it.each([false, true])(
    "an existing audit_log missing the hash column fails to open (readonly=%s)",
    (readonly) => {
      const p = join(dir, "legacy.db");
      const d = new Database(p);
      d.exec(
        "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, id TEXT, kind TEXT, body_json TEXT, prev_hash TEXT)",
      );
      d.close();
      const r = openAuditStore({ path: p, readonly });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("audit.open_failed");
        expect(r.error.details?.["missingColumns"]).toBe("hash");
      }
      // Writable open must not have modified the foreign table (no triggers added).
      const check = new Database(p, { readonly: true });
      const triggers = check
        .prepare("SELECT count(*) AS n FROM sqlite_master WHERE type = 'trigger'")
        .get();
      check.close();
      expect(triggers).toEqual({ n: 0 });
    },
  );

  it("an existing audit_log missing body_json fails to open writable (no throw)", () => {
    const p = join(dir, "legacy2.db");
    const d = new Database(p);
    d.exec("CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, id TEXT)");
    d.close();
    const r = openAuditStore({ path: p });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.open_failed");
  });

  it("a pristine store has no trigger warnings (writable and readonly)", () => {
    expect(open().warnings).toEqual([]);
    const ro = unwrap(openAuditStore({ path: dbPath, readonly: true }));
    opened.push(ro);
    expect(ro.warnings).toEqual([]);
  });

  describe("trigger integrity", () => {
    const NOOP_UPDATE =
      "DROP TRIGGER audit_log_no_update; " +
      "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log BEGIN SELECT 1; END;";

    it("writable open fails when a trigger was replaced by a same-named no-op", () => {
      seedPairs(open(), 1);
      raw().exec(NOOP_UPDATE);
      const r = openAuditStore({ path: dbPath });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("audit.open_failed");
        expect(r.error.details?.["triggers"]).toContain("audit_log_no_update");
      }
    });

    it("writable open fails when an extra trigger is attached to audit_log", () => {
      open();
      raw().exec(
        "CREATE TRIGGER audit_log_swallow BEFORE INSERT ON audit_log BEGIN SELECT RAISE(IGNORE); END;",
      );
      const r = openAuditStore({ path: dbPath });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("audit.open_failed");
        expect(r.error.details?.["triggers"]).toContain("unexpected trigger audit_log_swallow");
      }
    });

    it("whitespace-only differences in trigger SQL are accepted", () => {
      open();
      raw().exec(
        "DROP TRIGGER audit_log_no_delete; CREATE TRIGGER   audit_log_no_delete\n  BEFORE DELETE ON audit_log\n" +
          "BEGIN\n  SELECT RAISE(ABORT, 'audit_log is append-only');\nEND;",
      );
      const s = unwrap(openAuditStore({ path: dbPath }));
      opened.push(s);
      expect(s.warnings).toEqual([]);
    });

    it("writable open re-creates a dropped trigger", () => {
      open();
      raw().exec("DROP TRIGGER audit_log_no_delete");
      const s = unwrap(openAuditStore({ path: dbPath }));
      opened.push(s);
      seedPairs(s, 1);
      expect(() => raw().prepare("DELETE FROM audit_log WHERE seq = 1").run()).toThrow(
        /append-only/,
      );
    });

    it("readonly open reports mismatched / missing triggers as warnings, chain still verifies", () => {
      seedPairs(open(), 1);
      raw().exec(NOOP_UPDATE + " DROP TRIGGER audit_log_no_delete;");
      const ro = unwrap(openAuditStore({ path: dbPath, readonly: true }));
      opened.push(ro);
      expect(ro.warnings).toEqual([
        "trigger audit_log_no_update does not match the expected definition",
        "trigger audit_log_no_delete is missing",
      ]);
      expect(unwrap(ro.verify()).ok).toBe(true);
    });
  });

  it("verifies an empty log", () => {
    const v = verifyOk(open());
    expect(v.count).toBe(0);
    expect(v.headHash).toBe(GENESIS_PREV_HASH);
  });
});

describe("append + verify", () => {
  it("appends an attempt and its outcome as two chained records", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    expect(a).toMatchObject({ seq: 1, kind: "attempt", id: "gen-1", prevHash: GENESIS_PREV_HASH });
    expect(a.ts).toBe("2026-10-23T10:00:00.000Z");
    const o = unwrap(
      s.recordOutcome({
        attemptId: a.id,
        outcome: "success",
        latencyMs: 42,
        upstreamRef: "rfnd_1",
      }),
    );
    expect(o).toMatchObject({ seq: 2, kind: "outcome", attemptId: a.id, prevHash: a.hash });

    const v = verifyOk(s);
    expect(v).toEqual({ ok: true, count: 2, headHash: o.hash, danglingAttempts: [] });
    expect(unwrap(s.readAll())).toEqual([a, o]);
  });

  it.each([
    ["success", undefined],
    ["upstream_error", "bad_request_error"],
    ["timeout", "upstream.timeout"],
  ] as const)("records %s outcomes", (outcome, errorCode) => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    const o = unwrap(
      s.recordOutcome({
        attemptId: a.id,
        outcome,
        latencyMs: 1500,
        ...(errorCode === undefined ? {} : { errorCode }),
      }),
    );
    expect(o.kind === "outcome" && o.outcome).toBe(outcome);
    if (errorCode !== undefined) expect(o.kind === "outcome" && o.errorCode).toBe(errorCode);
    verifyOk(s);
  });

  it("persists across reopen and keeps chaining", () => {
    const s1 = open();
    seedPairs(s1, 2);
    s1.close();
    const s2 = open({ idGen: () => "after-reopen" });
    const a = unwrap(s2.recordAttempt(attempt()));
    expect(a.seq).toBe(5);
    const v = verifyOk(s2);
    expect(v.count).toBe(5);
    expect(v.danglingAttempts).toEqual(["after-reopen"]);
  });

  it("reports dangling attempts", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt({ id: "a1" })));
    unwrap(s.recordAttempt(attempt({ id: "a2" })));
    unwrap(s.recordOutcome({ attemptId: "a1", outcome: "success", latencyMs: 1 }));
    expect(verifyOk(s).danglingAttempts).toEqual(["a2"]);
  });

  it("keeps optional approver", () => {
    const s = open();
    const a = unwrap(
      s.recordAttempt(attempt({ decision: "require_approval", approver: "dashboard:ops-lead" })),
    );
    expect(a.kind === "attempt" && a.approver).toBe("dashboard:ops-lead");
    expect(unwrap(s.readAll())[0]).toEqual(a);
    verifyOk(s);
  });

  it("stores the canonical body without chain fields", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt({ id: "x1" })));
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 1").get() as {
      body_json: string;
    };
    const body = JSON.parse(row.body_json) as Record<string, unknown>;
    expect(Object.keys(body)).not.toContain("seq");
    expect(Object.keys(body)).not.toContain("prevHash");
    expect(Object.keys(body)).not.toContain("hash");
    expect(Object.keys(body)).toEqual([...Object.keys(body)].sort());
  });
});

describe("outcome constraints", () => {
  it("rejects an outcome for an unknown attempt", () => {
    const s = open();
    const r = s.recordOutcome({ attemptId: "nope", outcome: "success", latencyMs: 1 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.unknown_attempt");
    expect(unwrap(s.readAll())).toHaveLength(0);
  });

  it("rejects an outcome whose attemptId is another outcome", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    const o = unwrap(s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 1 }));
    const r = s.recordOutcome({ attemptId: o.id, outcome: "success", latencyMs: 1 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.unknown_attempt");
  });

  it("rejects a duplicate outcome for the same attempt", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordOutcome({ attemptId: a.id, outcome: "timeout", latencyMs: 30_000 }));
    const r = s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 31_000 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.duplicate_outcome");
    expect(unwrap(s.readAll())).toHaveLength(2);
  });

  it("the DB itself rejects a second outcome row for an attempt (unique index)", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 1 }));
    const body = JSON.stringify({ kind: "outcome", id: "o-dup", attemptId: a.id });
    expect(() =>
      raw()
        .prepare("INSERT INTO audit_log VALUES (3, 'o-dup', 'outcome', ?, ?, ?)")
        .run(body, "a".repeat(64), "b".repeat(64)),
    ).toThrow(/UNIQUE/);
  });

  it("a deny attempt only accepts denied / not_forwarded outcomes", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt({ id: "d1", decision: "deny" })));
    for (const outcome of ["success", "upstream_error", "timeout"] as const) {
      const r = s.recordOutcome({ attemptId: a.id, outcome, latencyMs: 1 });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("audit.inconsistent_outcome");
    }
    unwrap(s.recordOutcome({ attemptId: a.id, outcome: "denied", latencyMs: 1 }));
    unwrap(s.recordAttempt(attempt({ id: "d2", decision: "deny" })));
    unwrap(s.recordOutcome({ attemptId: "d2", outcome: "not_forwarded", latencyMs: 1 }));
    expect(unwrap(s.readAll())).toHaveLength(4);
    verifyOk(s);
  });

  it("require_approval attempts accept any outcome", () => {
    const s = open();
    for (const [i, outcome] of (
      ["success", "upstream_error", "timeout", "denied", "not_forwarded"] as const
    ).entries()) {
      const a = unwrap(
        s.recordAttempt(attempt({ id: `ra-${String(i)}`, decision: "require_approval" })),
      );
      unwrap(s.recordOutcome({ attemptId: a.id, outcome, latencyMs: 1 }));
    }
    verifyOk(s);
  });

  it("rejects a non-integer latency", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    const r = s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 1.5 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_input");
  });
});

describe("fail closed", () => {
  it("recordAttempt on a closed store returns err", () => {
    const s = open();
    s.close();
    const r = s.recordAttempt(attempt());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.write_failed");
    const ro = s.recordOutcome({ attemptId: "x", outcome: "success", latencyMs: 1 });
    expect(ro.ok).toBe(false);
    expect(s.readAll().ok).toBe(false);
    expect(s.verify().ok).toBe(false);
  });

  it("readonly store refuses writes", () => {
    open().close();
    const s = open({ readonly: true });
    const r = s.recordAttempt(attempt());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.write_failed");
    verifyOk(s);
  });

  it("returns err (does not throw) when the DB is locked by another writer", () => {
    const s = open({ busyTimeoutMs: 0 });
    const other = raw();
    other.exec("BEGIN IMMEDIATE");
    const r = s.recordAttempt(attempt());
    other.exec("ROLLBACK");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("audit.write_failed");
      expect(r.error.details?.["sqliteCode"]).toBe("SQLITE_BUSY");
    }
  });

  it("returns err and writes nothing when the hasher throws", () => {
    const bad: Hasher = {
      sha256Hex: () => {
        throw new Error("boom");
      },
    };
    const s = open({ hasher: bad });
    const r = s.recordAttempt(attempt());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.write_failed");
    expect(raw().prepare("SELECT count(*) AS n FROM audit_log").get()).toEqual({ n: 0 });
  });

  it("returns err when the hasher returns garbage", () => {
    const s = open({ hasher: { sha256Hex: () => "not-hex" } });
    expect(s.recordAttempt(attempt()).ok).toBe(false);
  });

  it("returns err when the clock throws", () => {
    const s = open({
      clock: () => {
        throw new Error("clock down");
      },
    });
    expect(s.recordAttempt(attempt()).ok).toBe(false);
  });

  it.each([
    ["float amount (unit confusion)", { amount: 500.5 }],
    ["NaN", { amount: Number.NaN }],
    ["bigint", { amount: 10n }],
    ["Date", { at: new Date(0) }],
    ["function", { f: () => 1 }],
  ])("rejects non-JSON args but records a deny attempt: %s", (_label, args) => {
    const s = open();
    const r = s.recordAttempt(attempt({ args, decision: "allow" }));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.code).toBe("audit.invalid_args");
    expect(r.error.details?.["recorded"]).toBe(true);
    expect(r.error.details?.["attemptId"]).toBe("gen-1");
    const rows = unwrap(s.readAll());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      kind: "attempt",
      id: "gen-1",
      decision: "deny",
      matchedRules: ["audit.invalid_args"],
      reason: "customer reported a duplicate charge",
    });
    const row = rows[0];
    if (row === undefined || "invalid" in row || row.kind !== "attempt") throw new Error("bad row");
    expect(row.argsRedacted).toEqual({
      _invalid: expect.stringMatching(/^canonical_json\./) as unknown,
      _path: expect.stringMatching(/^\$\./) as unknown,
    });
    verifyOk(s);
  });

  it("float amount: deny row carries the core error code and path", () => {
    const s = open();
    const r = s.recordAttempt(attempt({ args: { payment_id: "pay_1", amount: 500.5 } }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("audit.invalid_args");
      expect(r.error.details?.["path"]).toBe("$.amount");
    }
    const row = unwrap(s.readAll())[0];
    expect(row).toMatchObject({
      decision: "deny",
      argsRedacted: { _invalid: "canonical_json.non_integer", _path: "$.amount" },
    });
    // The deny attempt can be closed with a not-forwarded outcome.
    unwrap(s.recordOutcome({ attemptId: "gen-1", outcome: "not_forwarded", latencyMs: 0 }));
    expect(verifyOk(s).danglingAttempts).toEqual([]);
  });

  it("invalid args never leak the offending value into the log", () => {
    const s = open();
    const r = s.recordAttempt(attempt({ args: { amount: 123.456, vpa: "x@okaxis" } }));
    expect(r.ok).toBe(false);
    const text = JSON.stringify(unwrap(s.readAll()));
    expect(text).not.toContain("123.456");
    expect(text).not.toContain("okaxis");
  });

  it("invalid args + failing fallback append => audit.write_failed", () => {
    const bad: Hasher = {
      sha256Hex: () => {
        throw new Error("boom");
      },
    };
    const s = open({ hasher: bad });
    const r = s.recordAttempt(attempt({ args: { amount: 1.5 } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.write_failed");
    expect(raw().prepare("SELECT count(*) AS n FROM audit_log").get()).toEqual({ n: 0 });
  });

  it("rejects cyclic args (and records a deny attempt)", () => {
    const cyc: Record<string, unknown> = {};
    cyc["self"] = cyc;
    const s = open();
    const r = s.recordAttempt(attempt({ args: cyc }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_args");
    expect(unwrap(s.readAll())).toHaveLength(1);
  });

  it.each(["", "x\nOK: audit log forged", "\u001b[2J", "a b", "ñ", "x".repeat(129)])(
    "validates idGen output %j => err, nothing written",
    (bad) => {
      const s = open({ idGen: () => bad });
      const r = s.recordAttempt(attempt());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("audit.write_failed");
      expect(unwrap(s.readAll())).toHaveLength(0);
    },
  );

  it.each(["x\nOK: audit log forged\u001b[2J", "", "a/b", "ü", "x".repeat(129)])(
    "rejects caller id / attemptId %j (nothing written)",
    (bad) => {
      const s = open();
      const r = s.recordAttempt(attempt({ id: bad }));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("audit.invalid_input");
      const a = unwrap(s.recordAttempt(attempt({ id: "ok-1" })));
      const o1 = s.recordOutcome({ attemptId: bad, outcome: "success", latencyMs: 1 });
      expect(o1.ok).toBe(false);
      if (!o1.ok) expect(o1.error.code).toBe("audit.invalid_input");
      const o2 = s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 1, id: bad });
      expect(o2.ok).toBe(false);
      if (!o2.ok) expect(o2.error.code).toBe("audit.invalid_input");
      expect(unwrap(s.readAll())).toHaveLength(1);
    },
  );

  it.each(["3f2504e0-4f89-11d3-9a0c-0305e82c3301", "att_1.2:3-x", "x".repeat(128)])(
    "accepts id %s",
    (id) => {
      const s = open();
      expect(unwrap(s.recordAttempt(attempt({ id }))).id).toBe(id);
    },
  );

  it("validates clock output: invalid Date => err, nothing written", () => {
    const s = open({ clock: () => new Date(Number.NaN) });
    const r = s.recordAttempt(attempt());
    expect(r.ok).toBe(false);
    expect(unwrap(s.readAll())).toHaveLength(0);
    const s2 = open({ clock: () => "2026-01-01" as unknown as Date });
    expect(s2.recordAttempt(attempt()).ok).toBe(false);
    expect(unwrap(s2.readAll())).toHaveLength(0);
  });

  it("rejects a caller-supplied ts earlier than the head record", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt({ id: "a1", ts: "2026-10-23T10:00:00.000Z" })));
    const r = s.recordAttempt(attempt({ id: "a2", ts: "2026-10-23T09:59:59.999Z" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_input");
    // Equal or later is fine; offsets are compared as instants.
    unwrap(s.recordAttempt(attempt({ id: "a3", ts: "2026-10-23T15:30:00.000+05:30" })));
    unwrap(s.recordAttempt(attempt({ id: "a4", ts: "2026-10-23T10:00:01.000Z" })));
    const o = s.recordOutcome({
      attemptId: "a1",
      outcome: "success",
      latencyMs: 1,
      ts: "2026-01-01T00:00:00.000Z",
    });
    expect(o.ok).toBe(false);
    expect(unwrap(s.readAll())).toHaveLength(3);
  });

  it("clamps a clock-derived ts to the head ts when the clock goes backwards", () => {
    let now = new Date("2026-10-23T10:00:00.000Z");
    const s = open({ clock: () => now });
    const a1 = unwrap(s.recordAttempt(attempt({ id: "a1" })));
    expect(a1.ts).toBe("2026-10-23T10:00:00.000Z");
    now = new Date("2026-10-23T09:58:00.000Z"); // NTP step back
    const a2 = unwrap(s.recordAttempt(attempt({ id: "a2" })));
    expect(a2.ts).toBe("2026-10-23T10:00:00.000Z");
    const o = unwrap(s.recordOutcome({ attemptId: "a1", outcome: "success", latencyMs: 1 }));
    expect(o.ts).toBe("2026-10-23T10:00:00.000Z");
    now = new Date("2026-10-23T10:00:05.000Z");
    expect(unwrap(s.recordAttempt(attempt({ id: "a3" }))).ts).toBe("2026-10-23T10:00:05.000Z");
    verifyOk(s);
    expect(unwrap(s.readAll()).map((r) => ("ts" in r ? r.ts : null))).toEqual([
      "2026-10-23T10:00:00.000Z",
      "2026-10-23T10:00:00.000Z",
      "2026-10-23T10:00:00.000Z",
      "2026-10-23T10:00:05.000Z",
    ]);
  });

  it("clamps the clock ts to a (slightly future) caller ts at the head", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt({ id: "a1", ts: "2026-10-23T10:04:00.000Z" })));
    expect(unwrap(s.recordAttempt(attempt({ id: "a2" }))).ts).toBe("2026-10-23T10:04:00.000Z");
    verifyOk(s);
  });

  it("rejects a caller ts more than 5 minutes ahead of the clock (nothing written)", () => {
    const s = open();
    const clockMs = Date.parse("2026-10-23T10:00:00.000Z");
    const tooFar = new Date(clockMs + MAX_FUTURE_SKEW_MS + 1).toISOString();
    const r = s.recordAttempt(attempt({ id: "f1", ts: tooFar }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("audit.invalid_input");
      expect(r.error.details?.["issues"]).toBe("ts: future_dated");
    }
    expect(s.recordAttempt(attempt({ id: "f2", ts: "2027-01-01T00:00:00.000Z" })).ok).toBe(false);
    expect(unwrap(s.readAll())).toHaveLength(0);
    // Exactly at the limit is accepted.
    const edge = new Date(clockMs + MAX_FUTURE_SKEW_MS).toISOString();
    unwrap(s.recordAttempt(attempt({ id: "f3", ts: edge })));
    const o = s.recordOutcome({ attemptId: "f3", outcome: "success", latencyMs: 1, ts: tooFar });
    expect(o.ok).toBe(false);
    if (!o.ok) expect(o.error.code).toBe("audit.invalid_input");
    expect(unwrap(s.readAll())).toHaveLength(1);
  });

  it("rejects invalid input fields", () => {
    const s = open();
    expect(s.recordAttempt(attempt({ sessionId: "" })).ok).toBe(false);
    expect(s.recordAttempt(attempt({ ts: "yesterday" })).ok).toBe(false);
    const bad = { ...attempt(), decision: "maybe" } as unknown as RecordAttemptInput;
    expect(s.recordAttempt(bad).ok).toBe(false);
  });

  it("rejects a duplicate attempt id", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt({ id: "same" })));
    const r = s.recordAttempt(attempt({ id: "same" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.write_failed");
    verifyOk(s);
  });
});

describe("append-only triggers", () => {
  it("blocks UPDATE", () => {
    seedPairs(open(), 1);
    expect(() => raw().prepare("UPDATE audit_log SET kind = 'x' WHERE seq = 1").run()).toThrow(
      /append-only/,
    );
  });

  it("blocks DELETE", () => {
    seedPairs(open(), 1);
    expect(() => raw().prepare("DELETE FROM audit_log WHERE seq = 2").run()).toThrow(/append-only/);
  });
});

describe("tamper detection", () => {
  function tamper(sql: string, ...params: unknown[]): void {
    const d = raw();
    d.exec("DROP TRIGGER audit_log_no_update; DROP TRIGGER audit_log_no_delete;");
    d.prepare(sql).run(...params);
  }

  function broken(s: AuditStore) {
    const v = unwrap(s.verify());
    if (v.ok) throw new Error("expected broken chain");
    return v.brokenAt;
  }

  it("editing a body field of row N breaks at seq N (hash_mismatch)", () => {
    const s = open();
    const recs = seedPairs(s, 3);
    const target = recs[2]; // seq 3, an attempt
    if (target === undefined) throw new Error("seed failed");
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 3").get() as {
      body_json: string;
    };
    const body = JSON.parse(row.body_json) as Record<string, unknown>;
    body["reason"] = "totally legitimate reason";
    tamper("UPDATE audit_log SET body_json = ? WHERE seq = 3", JSON.stringify(body));
    expect(broken(s)).toMatchObject({ seq: 3, id: target.id, reason: "hash_mismatch" });
  });

  it("editing args amount of row N breaks at seq N", () => {
    const s = open();
    seedPairs(s, 2);
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 1").get() as {
      body_json: string;
    };
    tamper(
      "UPDATE audit_log SET body_json = ? WHERE seq = 1",
      row.body_json.replace('"amount":50000', '"amount":5000000'),
    );
    expect(broken(s)).toMatchObject({ seq: 1, reason: "hash_mismatch" });
  });

  it("corrupt JSON in row N is an invalid_row at seq N", () => {
    const s = open();
    seedPairs(s, 2);
    tamper("UPDATE audit_log SET body_json = '{not json' WHERE seq = 3");
    expect(broken(s)).toMatchObject({ seq: 3, reason: "invalid_row" });
  });

  it("an extra smuggled key in row N is an invalid_row", () => {
    const s = open();
    seedPairs(s, 2);
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 2").get() as {
      body_json: string;
    };
    const body = JSON.parse(row.body_json) as Record<string, unknown>;
    body["note"] = "x";
    tamper("UPDATE audit_log SET body_json = ? WHERE seq = 2", JSON.stringify(body));
    expect(broken(s)).toMatchObject({ seq: 2, reason: "invalid_row" });
  });

  it("a correctly hashed row whose id has control chars is an invalid_row", () => {
    const s = open();
    const evil = "x\nOK: audit log forged\u001b[2J";
    const body: AuditAttemptBody = {
      kind: "attempt",
      id: evil,
      ts: "2026-10-23T10:00:00.000Z",
      sessionId: "sess-1",
      tool: "create_refund",
      argsRedacted: { amount: 1 },
      reason: "a forged but well-hashed row",
      decision: "allow",
      matchedRules: [],
    };
    const rec = unwrap(buildRecord(nodeHasher, null, body));
    const json = unwrap(canonicalJson(body));
    raw()
      .prepare(
        "INSERT INTO audit_log (seq, id, kind, body_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(rec.seq, evil, "attempt", json, rec.prevHash, rec.hash);
    expect(broken(s)).toMatchObject({ seq: 1, reason: "invalid_row" });
  });

  it("a correctly hashed outcome whose attemptId has control chars is an invalid_row", () => {
    const s = open();
    const [a] = seedPairs(s, 1);
    if (a === undefined) throw new Error("seed failed");
    const head = unwrap(s.readAll())[1];
    if (head === undefined || "invalid" in head) throw new Error("seed failed");
    const body = {
      kind: "outcome" as const,
      id: "o-evil",
      attemptId: `${a.id}\n`,
      ts: "2026-10-23T10:00:00.000Z",
      outcome: "success" as const,
      latencyMs: 1,
    };
    const rec = unwrap(buildRecord(nodeHasher, { seq: head.seq, hash: head.hash }, body));
    raw()
      .prepare(
        "INSERT INTO audit_log (seq, id, kind, body_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(rec.seq, body.id, "outcome", unwrap(canonicalJson(body)), rec.prevHash, rec.hash);
    expect(broken(s)).toMatchObject({ seq: 3, reason: "invalid_row" });
  });

  it("id column disagreeing with body is an invalid_row", () => {
    const s = open();
    seedPairs(s, 2);
    tamper("UPDATE audit_log SET id = 'forged' WHERE seq = 2");
    expect(broken(s)).toMatchObject({ seq: 2, reason: "invalid_row" });
  });

  it("a duplicate key prepended inside the stored body is an invalid_row", () => {
    const s = open();
    seedPairs(s, 2);
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 3").get() as {
      body_json: string;
    };
    expect(row.body_json.startsWith("{")).toBe(true);
    const forged = `{"decision":"deny",${row.body_json.slice(1)}`;
    tamper("UPDATE audit_log SET body_json = ? WHERE seq = 3", forged);
    // SQLite sees the forged first key; JSON.parse would see the original last one.
    expect(
      raw()
        .prepare("SELECT json_extract(body_json, '$.decision') AS d FROM audit_log WHERE seq = 3")
        .get(),
    ).toEqual({ d: "deny" });
    expect(broken(s)).toMatchObject({ seq: 3, reason: "invalid_row" });
  });

  it("a whitespace-only edit of the stored body is an invalid_row", () => {
    const s = open();
    seedPairs(s, 2);
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 2").get() as {
      body_json: string;
    };
    tamper("UPDATE audit_log SET body_json = ? WHERE seq = 2", ` ${row.body_json}`);
    expect(broken(s)).toMatchObject({ seq: 2, reason: "invalid_row" });
  });

  it("tampering the hash column breaks the chain at that row", () => {
    const s = open();
    seedPairs(s, 2);
    tamper("UPDATE audit_log SET hash = ? WHERE seq = 2", "f".repeat(64));
    expect(broken(s)).toMatchObject({ seq: 2, reason: "hash_mismatch" });
  });

  it("deleting a middle row breaks the chain", () => {
    const s = open();
    seedPairs(s, 2);
    tamper("DELETE FROM audit_log WHERE seq = 2");
    expect(broken(s)).toMatchObject({ seq: 3, reason: "seq_gap" });
  });

  it("deleting an attempt row is detected", () => {
    const s = open();
    seedPairs(s, 2);
    tamper("DELETE FROM audit_log WHERE seq = 1");
    expect(broken(s).seq).toBe(2);
  });
});

describe("redaction", () => {
  const card = "4111 1111 1111 1111";
  const cardCompact = "4111111111111111";
  const vpa = "victim@okaxis";
  const email = "jane.doe@example.com";
  const key = "rzp_test_AbCdEf123456";
  const phone = "9876543210";

  it("never stores plaintext secrets from args or reason", () => {
    const s = open();
    unwrap(
      s.recordAttempt(
        attempt({
          args: {
            payment_id: "pay_123",
            amount: 50_000,
            card: { number: cardCompact, cvv: "123", expiry_month: "12" },
            vpa,
            email,
            contact: phone,
            notes: { comment: `card ${card} key ${key} mail ${email}`, upi: vpa },
            key_id: key,
          },
          reason: `refund to ${vpa} for card ${card}, email ${email}, key ${key}, call ${phone}`,
        }),
      ),
    );
    s.close();

    const d = raw();
    const rows = d.prepare("SELECT body_json FROM audit_log").all() as Array<{ body_json: string }>;
    const text = rows.map((r) => r.body_json).join("\n");
    for (const secret of [card, cardCompact, vpa, email, key, phone, "okaxis"]) {
      expect(text).not.toContain(secret);
    }
    expect(text).toContain("pay_123");
    expect(text).toContain("50000");
    d.pragma("wal_checkpoint(TRUNCATE)");
    d.close();

    // Nothing in any on-disk file either (db, wal, shm).
    const parent = join(dir, "nested");
    for (const f of readdirSync(parent)) {
      const bytes = readFileSync(join(parent, f)).toString("latin1");
      for (const secret of [cardCompact, vpa, email, key]) expect(bytes).not.toContain(secret);
    }
  });

  it("rejects free text in outcome errorCode / upstreamRef (nothing written)", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    for (const extra of [
      { errorCode: `bad key ${key}` },
      { errorCode: "BAD_REQUEST_ERROR" },
      { upstreamRef: `vpa ${vpa}` },
      { upstreamRef: "" },
      { upstreamRef: "x".repeat(129) },
    ]) {
      const r = s.recordOutcome({
        attemptId: a.id,
        outcome: "upstream_error",
        latencyMs: 5,
        ...extra,
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("audit.invalid_input");
    }
    expect(unwrap(s.readAll())).toHaveLength(1);
  });

  it.each(["telegram:7123456789", "telegram:1", "dashboard:admin", "dashboard:ops_lead-2"])(
    "stores approver %s verbatim",
    (approver) => {
      const s = open();
      const a = unwrap(s.recordAttempt(attempt({ decision: "require_approval", approver })));
      expect(a.kind === "attempt" && a.approver).toBe(approver);
      expect(unwrap(s.readAll())[0]).toEqual(a);
    },
  );

  it.each([
    "ops-lead",
    "Telegram:1",
    "telegram:",
    `telegram:${"1".repeat(21)}`,
    "telegram:@ravi",
    "telegram:has space",
    "dashboard:Admin",
    `dashboard:${"a".repeat(33)}`,
    "dashboard:ravi.kumar@gmail.com",
    "email:ravi.kumar@gmail.com",
    "sms:9876543210",
    "whatsapp:9876543210",
    `x:${key} leaked`,
  ])("rejects malformed / PII approver %s", (approver) => {
    const s = open();
    const r = s.recordAttempt(attempt({ approver }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_input");
    expect(unwrap(s.readAll())).toHaveLength(0);
  });

  it.each(["rfnd_ABC123xyz", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", "pout_9876543210123456"])(
    "stores upstreamRef %s verbatim",
    (upstreamRef) => {
      const s = open();
      const a = unwrap(s.recordAttempt(attempt()));
      const o = unwrap(
        s.recordOutcome({
          attemptId: a.id,
          outcome: "success",
          latencyMs: 5,
          upstreamRef,
          errorCode: "upstream.partial",
        }),
      );
      expect(o.kind === "outcome" && o.upstreamRef).toBe(upstreamRef);
      expect(unwrap(s.readAll())[1]).toEqual(o);
      verifyOk(s);
    },
  );

  it("does not mutate the caller's args", () => {
    const args = { vpa, amount: 100 };
    unwrap(open().recordAttempt(attempt({ args })));
    expect(args).toEqual({ vpa, amount: 100 });
  });
});

describe("concurrency", () => {
  it("two connections interleaving 100 appends each produce one valid chain", () => {
    let i1 = 0;
    let i2 = 0;
    const s1 = open({ idGen: () => `c1-${String(++i1)}` });
    const s2 = open({ idGen: () => `c2-${String(++i2)}` });
    for (let i = 0; i < 100; i++) {
      unwrap(s1.recordAttempt(attempt({ sessionId: "s1" })));
      unwrap(s2.recordAttempt(attempt({ sessionId: "s2" })));
    }
    for (const s of [s1, s2]) {
      const v = verifyOk(s);
      expect(v.count).toBe(200);
    }
    const seqs = unwrap(s1.readAll()).map((r) => r.seq);
    expect(seqs).toEqual(Array.from({ length: 200 }, (_, k) => k + 1));
  });

  it("uses the injected hasher (node sha256 by default)", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(nodeHasher.sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("originalArgs (transform audit, T008)", () => {
  it("stores originalArgsRedacted redacted like args; round-trips and verifies", () => {
    const s = open();
    const a = unwrap(
      s.recordAttempt(
        attempt({
          decision: "transform",
          args: { payment_id: "pay_123", amount: 10_000 },
          originalArgs: { payment_id: "pay_123", amount: 50_000, notes: { email: "a@b.co" } },
        }),
      ),
    );
    expect(a).toMatchObject({
      argsRedacted: { payment_id: "pay_123", amount: 10_000 },
      originalArgsRedacted: {
        payment_id: "pay_123",
        amount: 50_000,
        notes: { email: "[REDACTED]" },
      },
    });
    expect(unwrap(s.readAll())[0]).toEqual(a);
    expect(JSON.stringify(unwrap(s.readAll()))).not.toContain("a@b.co");
    unwrap(s.readActivitySince(0));
    verifyOk(s);
  });

  it("omits the key when originalArgs is absent (older rows still verify)", () => {
    const s = open();
    const a = unwrap(s.recordAttempt(attempt()));
    expect(Object.keys(a)).not.toContain("originalArgsRedacted");
    const row = raw().prepare("SELECT body_json FROM audit_log WHERE seq = 1").get() as {
      body_json: string;
    };
    expect(row.body_json).not.toContain("originalArgsRedacted");
    verifyOk(s);
  });

  it("invalid originalArgs ⇒ audit.invalid_args deny trail without either args", () => {
    const s = open();
    const r = s.recordAttempt(
      attempt({ decision: "transform", originalArgs: { amount: 1.5, vpa: "x@okaxis" } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_args");
    const row = unwrap(s.readAll())[0];
    expect(row).toMatchObject({ decision: "deny", matchedRules: ["audit.invalid_args"] });
    expect(Object.keys(row ?? {})).not.toContain("originalArgsRedacted");
    expect(JSON.stringify(row)).not.toContain("okaxis");
    verifyOk(s);
  });
});
