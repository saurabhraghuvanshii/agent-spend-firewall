import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Result } from "@asf/core";
import { openAuditStore, type AuditStore, type RecordAttemptInput } from "./audit-store.js";

let dir: string;
let dbPath: string;
const opened: AuditStore[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-audit-modes-"));
  dbPath = join(dir, "audit.db");
});

afterEach(() => {
  for (const s of opened.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r.value;
}

function codeOf(r: Result<unknown>): string | undefined {
  return r.ok ? undefined : r.error.code;
}

let n = 0;
function open(readonly = false): AuditStore {
  const s = unwrap(
    openAuditStore({
      path: dbPath,
      readonly,
      clock: () => new Date("2026-10-29T10:00:00.000Z"),
      idGen: () => `gen-${String(++n)}`,
    }),
  );
  opened.push(s);
  return s;
}

const attempt = (over: Partial<RecordAttemptInput> = {}): RecordAttemptInput => ({
  sessionId: "sess-1",
  tool: "create_refund",
  args: { payment_id: "pay_123", amount: 300_000 },
  reason: "customer reported a duplicate charge",
  decision: "allow",
  matchedRules: ["refund.max"],
  ...over,
});

function verifyOk(s: AuditStore): void {
  const v = unwrap(s.verify());
  if (!v.ok) throw new Error(`chain broken at seq ${String(v.brokenAt.seq)}: ${v.brokenAt.reason}`);
}

describe("readMode / changeMode (T012)", () => {
  it("has no mode record on a fresh log", () => {
    expect(unwrap(open().readMode())).toBeUndefined();
  });

  it("writes a chained mode record with who / when and merges partial changes", () => {
    const s = open();
    const on = unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    expect(on.changed).toBe(true);
    expect(on.record).toMatchObject({
      kind: "mode",
      killSwitch: true,
      shadow: false,
      actor: "cli:ops",
      ts: "2026-10-29T10:00:00.000Z",
    });
    const shadow = unwrap(s.changeMode({ shadow: true, actor: "dashboard:alice" }));
    expect(shadow.record).toMatchObject({
      killSwitch: true,
      shadow: true,
      actor: "dashboard:alice",
    });
    expect(unwrap(s.readMode())).toMatchObject({ killSwitch: true, shadow: true });
    verifyOk(s);
  });

  it("does not write when the requested state is already in force", () => {
    const s = open();
    expect(unwrap(s.changeMode({ killSwitch: false, actor: "cli:ops" }))).toEqual({
      changed: false,
      record: undefined,
    });
    unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    const again = unwrap(s.changeMode({ killSwitch: true, actor: "cli:bob" }));
    expect(again.changed).toBe(false);
    expect(again.record?.actor).toBe("cli:ops");
    const rows = unwrap(s.readAll());
    expect(rows).toHaveLength(1);
  });

  it("persists across a restart (reopen)", () => {
    const s = open();
    unwrap(s.changeMode({ killSwitch: true, shadow: true, actor: "cli:ops" }));
    s.close();
    expect(unwrap(open().readMode())).toMatchObject({ killSwitch: true, shadow: true });
  });

  it("a change from another connection is seen on the next read (CLI while the proxy runs)", () => {
    const proxy = open();
    const cli = open();
    expect(unwrap(proxy.readMode())).toBeUndefined();
    unwrap(cli.changeMode({ killSwitch: true, actor: "cli:ops" }));
    expect(unwrap(proxy.readMode())?.killSwitch).toBe(true);
    // The proxy keeps appending to the same chain without forking it.
    unwrap(proxy.recordAttempt(attempt({ decision: "deny" })));
    unwrap(cli.changeMode({ killSwitch: false, actor: "cli:ops" }));
    expect(unwrap(proxy.readMode())?.killSwitch).toBe(false);
    verifyOk(proxy);
  });

  it("rejects an invalid actor or unknown field without writing", () => {
    const s = open();
    expect(codeOf(s.changeMode({ killSwitch: true, actor: "ops@example.com" }))).toBe(
      "audit.invalid_input",
    );
    expect(codeOf(s.changeMode({ killSwitch: true, actor: "cli:Ops" }))).toBe(
      "audit.invalid_input",
    );
    const extra = { killSwitch: true, actor: "cli:ops", note: "x" };
    expect(codeOf(s.changeMode(extra))).toBe("audit.invalid_input");
    expect(unwrap(s.readAll())).toHaveLength(0);
  });

  it("read-only stores can read but not change the mode", () => {
    unwrap(open().changeMode({ shadow: true, actor: "cli:ops" }));
    const ro = open(true);
    expect(unwrap(ro.readMode())?.shadow).toBe(true);
    expect(codeOf(ro.changeMode({ shadow: false, actor: "cli:ops" }))).toBe("audit.write_failed");
  });

  it("a closed store fails closed", () => {
    const s = open();
    s.close();
    expect(codeOf(s.readMode())).toBe("audit.read_failed");
    expect(codeOf(s.changeMode({ killSwitch: true, actor: "cli:ops" }))).toBe("audit.write_failed");
  });

  it("a tampered latest mode record is unreadable; a new change writes a fresh valid record", () => {
    const s = open();
    unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    const raw = new Database(dbPath);
    raw.exec("DROP TRIGGER audit_log_no_update");
    raw
      .prepare(
        "UPDATE audit_log SET body_json = replace(body_json, '\"killSwitch\":true', '\"killSwitch\":false') WHERE kind = 'mode'",
      )
      .run();
    raw.close();
    expect(codeOf(s.readMode())).toBe("audit.mode_invalid");
    // Unreadable ⇒ the effective state is kill ON, so even "kill on" writes a new record.
    const fresh = unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    expect(fresh.changed).toBe(true);
    expect(unwrap(s.readMode())).toMatchObject({ killSwitch: true, shadow: false });
  });

  it("a malformed mode row is unreadable", () => {
    const s = open();
    unwrap(s.changeMode({ killSwitch: false, shadow: true, actor: "cli:ops" }));
    const raw = new Database(dbPath);
    raw.exec("DROP TRIGGER audit_log_no_update");
    raw.prepare("UPDATE audit_log SET body_json = '{}' WHERE kind = 'mode'").run();
    raw.close();
    expect(codeOf(s.readMode())).toBe("audit.mode_invalid");
  });
});

describe("readMode never goes backwards (T012, L2)", () => {
  it("the latest mode record disappearing or moving back ⇒ unreadable (kill ON)", () => {
    const s = open();
    unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    unwrap(s.changeMode({ shadow: true, actor: "cli:ops" }));
    expect(unwrap(s.readMode())).toMatchObject({ killSwitch: true, shadow: true });
    const raw = new Database(dbPath);
    raw.exec("DROP TRIGGER audit_log_no_delete");
    raw.prepare("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)").run();
    expect(codeOf(s.readMode())).toBe("audit.mode_invalid");
    raw.prepare("DELETE FROM audit_log").run();
    raw.close();
    expect(codeOf(s.readMode())).toBe("audit.mode_invalid");
  });

  it("a fresh connection has no history to compare (startup verify covers it)", () => {
    const s = open();
    unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    expect(unwrap(open().readMode())?.killSwitch).toBe(true);
  });
});

describe("shadow attempts in the store (T012)", () => {
  it("refuses a shadow attempt after shadow mode was turned off again (L1)", () => {
    const s = open();
    unwrap(s.changeMode({ shadow: true, actor: "cli:ops" }));
    unwrap(s.recordAttempt(attempt({ shadow: { wouldDecision: "deny" } })));
    unwrap(s.changeMode({ shadow: false, actor: "cli:ops" }));
    expect(codeOf(s.recordAttempt(attempt({ shadow: { wouldDecision: "deny" } })))).toBe(
      "audit.invalid_shadow",
    );
    unwrap(s.changeMode({ killSwitch: true, shadow: true, actor: "cli:ops" }));
    expect(s.recordAttempt(attempt({ shadow: { wouldDecision: "deny" } })).ok).toBe(true);
    verifyOk(s);
  });

  it("refuses a shadow attempt before shadow mode was ever turned on", () => {
    const s = open();
    expect(codeOf(s.recordAttempt(attempt({ shadow: { wouldDecision: "deny" } })))).toBe(
      "audit.invalid_shadow",
    );
    unwrap(s.changeMode({ killSwitch: true, actor: "cli:ops" }));
    expect(codeOf(s.recordAttempt(attempt({ shadow: { wouldDecision: "deny" } })))).toBe(
      "audit.invalid_shadow",
    );
    expect(unwrap(s.readAll())).toHaveLength(1);
  });

  it("stores shadow + wouldDecision after shadow mode was on; activity counts it as an allow", () => {
    const s = open();
    unwrap(s.changeMode({ shadow: true, actor: "cli:ops" }));
    const a = unwrap(s.recordAttempt(attempt({ shadow: { wouldDecision: "require_approval" } })));
    expect(a).toMatchObject({
      kind: "attempt",
      decision: "allow",
      shadow: true,
      wouldDecision: "require_approval",
    });
    unwrap(s.recordOutcome({ attemptId: a.id, outcome: "success", latencyMs: 4 }));
    verifyOk(s);
    const act = unwrap(s.readActivitySince(0));
    expect(act).toHaveLength(1);
    expect(act[0]?.attempt).toMatchObject({ shadow: true, wouldDecision: "require_approval" });
    expect(act[0]?.outcome?.outcome).toBe("success");
    // Mode rows are not money activity in any scan.
    expect(unwrap(s.readUnsettled())).toEqual({ open: [], unsettled: [], staleApprovals: [] });
    expect(unwrap(s.listNeedsHuman())).toEqual([]);
    expect(unwrap(s.readAttempt(a.id))?.attempt.shadow).toBe(true);
  });

  it.each([
    ["a deny", { decision: "deny" as const }],
    ["a transform", { decision: "transform" as const }],
    ["original args", { originalArgs: { amount: 1 } }],
    ["an approver", { approver: "telegram:1" }],
  ])("refuses a shadow attempt with %s", (_label, over) => {
    const s = open();
    unwrap(s.changeMode({ shadow: true, actor: "cli:ops" }));
    expect(codeOf(s.recordAttempt(attempt({ shadow: { wouldDecision: "deny" }, ...over })))).toBe(
      "audit.invalid_input",
    );
  });

  it("an invalid-args trail row drops the shadow fields (it is a deny)", () => {
    const s = open();
    unwrap(s.changeMode({ shadow: true, actor: "cli:ops" }));
    const r = s.recordAttempt(
      attempt({ args: { amount: 1.5 }, shadow: { wouldDecision: "deny" } }),
    );
    expect(codeOf(r)).toBe("audit.invalid_args");
    const rows = unwrap(s.readAll());
    const trail = rows.at(-1);
    expect(trail).toMatchObject({ kind: "attempt", decision: "deny" });
    expect(trail).not.toHaveProperty("shadow");
    expect(trail).not.toHaveProperty("wouldDecision");
    verifyOk(s);
  });
});
