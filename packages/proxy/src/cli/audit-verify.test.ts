import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildRecord, canonicalJson, type AuditAttemptBody } from "@asf/core";
import { openAuditStore } from "../audit-store.js";
import { nodeHasher } from "../node-hasher.js";
import { DEFAULT_AUDIT_DB, escapeForTerminal, resolveDbPath, runVerify } from "./audit-verify.js";

const FORGE = "x\nOK: audit log forged\u001b[2J";

/** No raw control chars (other than our own line breaks) may reach the terminal. */
function expectNoControlChars(output: string): void {
  for (const line of output.split("\n")) {
    expect(line).toMatch(/^[\x20-\x7e]*$/);
  }
}

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-audit-cli-"));
  dbPath = join(dir, "audit.db");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Seed `pairs` attempt/outcome pairs plus `dangling` attempts without outcome. */
function seed(pairs: number, dangling = 0): void {
  const r = openAuditStore({ path: dbPath });
  if (!r.ok) throw new Error(r.error.message);
  const s = r.value;
  try {
    for (let i = 0; i < pairs + dangling; i++) {
      const a = s.recordAttempt({
        id: `att-${String(i)}`,
        sessionId: "sess",
        tool: "create_refund",
        args: { payment_id: "pay_1", amount: 100 },
        reason: "duplicate charge refund",
        decision: "allow",
        matchedRules: [],
      });
      if (!a.ok) throw new Error(a.error.message);
      if (i < pairs) {
        const o = s.recordOutcome({ attemptId: a.value.id, outcome: "success", latencyMs: 3 });
        if (!o.ok) throw new Error(o.error.message);
      }
    }
  } finally {
    s.close();
  }
}

function tamperBody(seq: number): void {
  const d = new Database(dbPath);
  try {
    d.exec("DROP TRIGGER audit_log_no_update");
    const row = d.prepare("SELECT body_json FROM audit_log WHERE seq = ?").get(seq) as {
      body_json: string;
    };
    d.prepare("UPDATE audit_log SET body_json = ? WHERE seq = ?").run(
      row.body_json.replace('"amount":100', '"amount":100000'),
      seq,
    );
  } finally {
    d.close();
  }
}

describe("runVerify", () => {
  it("exit 0 with count and head hash for an intact log", () => {
    seed(2);
    const r = runVerify(["--db", dbPath], {});
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("OK");
    expect(r.output).toContain("records: 4");
    expect(r.output).toMatch(/head: [0-9a-f]{64}/);
    expect(r.output).not.toContain("WARNING");
  });

  it("warns about dangling attempts but still exits 0", () => {
    seed(1, 1);
    const r = runVerify([`--db=${dbPath}`], {});
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("WARNING: 1 attempt(s) without an outcome: att-1");
  });

  it("exit 1 naming the first broken seq and id", () => {
    seed(3);
    tamperBody(3);
    const r = runVerify(["--db", dbPath], {});
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("seq 3");
    expect(r.output).toContain("id att-1");
    expect(r.output).toContain("hash_mismatch");
  });

  it("exit 2 when the file does not exist (and does not create it)", () => {
    const missing = join(dir, "nope.db");
    const r = runVerify(["--db", missing], {});
    expect(r.exitCode).toBe(2);
    expect(r.output).toContain("cannot open");
    const again = runVerify(["--db", missing], {});
    expect(again.exitCode).toBe(2);
  });

  it("exit 2 when the file is not an audit database", () => {
    writeFileSync(dbPath, "this is not sqlite");
    expect(runVerify(["--db", dbPath], {}).exitCode).toBe(2);
  });

  it("exit 2 when audit_log lacks the hash column", () => {
    const d = new Database(dbPath);
    d.exec(
      "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, id TEXT, kind TEXT, body_json TEXT, prev_hash TEXT)",
    );
    d.close();
    const r = runVerify(["--db", dbPath], {});
    expect(r.exitCode).toBe(2);
    expect(r.output).toContain("audit.open_failed");
  });

  it("exit 1 when a stored body has a duplicate key prepended", () => {
    seed(2);
    const d = new Database(dbPath);
    try {
      d.exec("DROP TRIGGER audit_log_no_update");
      const row = d.prepare("SELECT body_json FROM audit_log WHERE seq = 1").get() as {
        body_json: string;
      };
      d.prepare("UPDATE audit_log SET body_json = ? WHERE seq = 1").run(
        `{"decision":"deny",${row.body_json.slice(1)}`,
      );
    } finally {
      d.close();
    }
    const r = runVerify(["--db", dbPath], {});
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("seq 1");
    expect(r.output).toContain("invalid_row");
  });

  it("exit 2 on bad usage", () => {
    expect(runVerify(["--db"], {}).exitCode).toBe(2);
    expect(runVerify(["--wat"], {}).exitCode).toBe(2);
  });

  it("ignores a forwarded `--` separator", () => {
    seed(1);
    expect(runVerify(["--", "--db", dbPath], {}).exitCode).toBe(0);
  });

  it("falls back to ASF_AUDIT_DB", () => {
    seed(1);
    expect(runVerify([], { ASF_AUDIT_DB: dbPath }).exitCode).toBe(0);
  });

  it("--db wins over ASF_AUDIT_DB", () => {
    seed(1);
    expect(runVerify(["--db", dbPath], { ASF_AUDIT_DB: join(dir, "x.db") }).exitCode).toBe(0);
  });

  it("resolves relative paths against INIT_CWD, then cwd", () => {
    seed(1);
    expect(runVerify(["--db", "audit.db"], { INIT_CWD: dir }, "/somewhere/else").exitCode).toBe(0);
    expect(runVerify(["--db", "audit.db"], {}, dir).exitCode).toBe(0);
  });
});

describe("terminal escaping", () => {
  it("escapes control, non-ASCII and backslash characters JSON-style", () => {
    expect(escapeForTerminal("att-1_ok:2.x")).toBe("att-1_ok:2.x");
    expect(escapeForTerminal(FORGE)).toBe("x\\u000aOK: audit log forged\\u001b[2J");
    expect(escapeForTerminal("\r\t\u007f\u0085\u2028")).toBe("\\u000d\\u0009\\u007f\\u0085\\u2028");
    expect(escapeForTerminal("é😀")).toBe("\\u00e9\\ud83d\\ude00");
    expect(escapeForTerminal("a\\u000ab")).toBe("a\\\\u000ab");
  });

  it("escapes a db path containing a newline and ANSI escape", () => {
    const evilDir = join(dir, "evil\nOK: audit log forged\u001b[2J");
    mkdirSync(evilDir);
    const r = runVerify(["--db", join(evilDir, "missing.db")], {});
    expect(r.exitCode).toBe(2);
    expect(r.output.split("\n")).toHaveLength(1);
    expect(r.output).toContain("evil\\u000aOK: audit log forged\\u001b[2J");
    expectNoControlChars(r.output);
  });

  it("a well-hashed row with a forged id is reported as invalid_row, id not echoed", () => {
    seed(0);
    const body: AuditAttemptBody = {
      kind: "attempt",
      id: FORGE,
      ts: "2026-10-23T10:00:00.000Z",
      sessionId: "s",
      tool: "create_refund",
      argsRedacted: null,
      reason: "forged row with valid hash",
      decision: "allow",
      matchedRules: [],
    };
    const rec = buildRecord(nodeHasher, null, body);
    const json = canonicalJson(body);
    if (!rec.ok || !json.ok) throw new Error("build failed");
    const d = new Database(dbPath);
    try {
      d.prepare(
        "INSERT INTO audit_log (seq, id, kind, body_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
      ).run(rec.value.seq, FORGE, "attempt", json.value, rec.value.prevHash, rec.value.hash);
    } finally {
      d.close();
    }
    const r = runVerify(["--db", dbPath], {});
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("seq 1, id (unknown), reason invalid_row");
    expect(r.output).not.toContain("forged");
    expectNoControlChars(r.output);
  });

  it("prints trigger warnings (escaped) without failing verification", () => {
    seed(1);
    const d = new Database(dbPath);
    try {
      d.exec(
        "DROP TRIGGER audit_log_no_update; " +
          "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log BEGIN SELECT 1; END;",
      );
      d.exec(
        `CREATE TRIGGER "${FORGE}" BEFORE INSERT ON audit_log BEGIN SELECT RAISE(IGNORE); END;`,
      );
    } finally {
      d.close();
    }
    const r = runVerify(["--db", dbPath], {});
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("OK: audit log");
    expect(r.output).toContain(
      "WARNING: trigger audit_log_no_update does not match the expected definition",
    );
    expect(r.output).toContain(
      "WARNING: unexpected trigger x\\u000aOK: audit log forged\\u001b[2J on audit_log",
    );
    expect(r.output.split("\n").filter((l) => l.startsWith("OK:"))).toHaveLength(1);
    expectNoControlChars(r.output);
  });
});

describe("resolveDbPath", () => {
  it("defaults to data/audit.db under INIT_CWD", () => {
    expect(resolveDbPath(undefined, { INIT_CWD: "/repo" }, "/repo/packages/proxy")).toBe(
      join("/repo", DEFAULT_AUDIT_DB),
    );
  });

  it("keeps absolute paths and ignores an empty ASF_AUDIT_DB", () => {
    expect(resolveDbPath("/abs/a.db", { INIT_CWD: "/repo" }, "/x")).toBe("/abs/a.db");
    expect(resolveDbPath(undefined, { ASF_AUDIT_DB: "" }, "/x")).toBe(join("/x", DEFAULT_AUDIT_DB));
  });
});
