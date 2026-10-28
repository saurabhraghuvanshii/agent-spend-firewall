import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import type { Result } from "@asf/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openAuditStore } from "../audit-store.js";
import { createModePreCheck, createModeStore, KILL_SWITCH_RULE } from "../modes.js";
import type { CallContext } from "../server.js";
import {
  defaultActor,
  MODE_USAGE,
  parseModeArgs,
  runModeCommand,
  type ModeCliDeps,
} from "./mode.js";

let repo: string;

beforeEach(() => {
  repo = realpathSync(mkdtempSync(join(tmpdir(), "asf-mode-cli-")));
});
afterEach(() => {
  rmSync(repo, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

function deps(env: Record<string, string> = {}, user: string | undefined = "saurabh"): ModeCliDeps {
  return {
    env: { INIT_CWD: repo, ...env },
    cwd: repo,
    moduleDir: repo,
    isRepoRoot: (d) => d === repo,
    userName: () => user,
  };
}

const dbPath = (): string => join(repo, "data", "audit.db");
const run = (argv: string[], d: ModeCliDeps = deps()) => runModeCommand(argv, d);

describe("parseModeArgs", () => {
  it.each([
    [["status"], { ok: true, cmd: "status" }],
    [["--", "status"], { ok: true, cmd: "status" }],
    [["kill", "on"], { ok: true, cmd: "set", change: { killSwitch: true } }],
    [["kill", "off"], { ok: true, cmd: "set", change: { killSwitch: false } }],
    [
      ["shadow", "on", "--actor", "alice"],
      { ok: true, cmd: "set", change: { shadow: true }, actor: "cli:alice" },
    ],
    [
      ["--actor=bob", "shadow", "off"],
      { ok: true, cmd: "set", change: { shadow: false }, actor: "cli:bob" },
    ],
  ])("%j", (argv, expected) => {
    expect(parseModeArgs(argv)).toEqual(expected);
  });

  it.each([
    [[]],
    [["kill"]],
    [["kill", "maybe"]],
    [["kill", "on", "extra"]],
    [["freeze", "on"]],
    [["status", "--actor", "x"]],
    [["kill", "on", "--actor"]],
    [["kill", "on", "--actor", "Bad Name"]],
    [["kill", "on", "--actor=a\nb"]],
    [["kill", "on", "--force"]],
  ])("rejects %j", (argv) => {
    expect(parseModeArgs(argv).ok).toBe(false);
  });
});

describe("defaultActor", () => {
  it.each([
    ["saurabh", "cli:saurabh"],
    ["Saurabh.R", "cli:saurabh_r"],
    ["a".repeat(40), `cli:${"a".repeat(32)}`],
    ["", "cli:operator"],
    ["...", "cli:operator"],
    [undefined, "cli:operator"],
  ])("%s ⇒ %s", (user, expected) => {
    expect(defaultActor(user)).toBe(expected);
  });
});

describe("runModeCommand", () => {
  it("status without an audit DB ⇒ defaults; does not create the DB", () => {
    const r = run(["status"]);
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("kill switch off; shadow mode off; never changed");
    expect(existsSync(dbPath())).toBe(false);
  });

  it("kill on / status / kill on again / kill off", () => {
    const on = run(["kill", "on"]);
    expect(on.exitCode).toBe(0);
    expect(on.output).toMatch(
      /^mode changed: kill switch ON; shadow mode off; last changed .* by cli:saurabh$/,
    );
    const status = run(["status"]);
    expect(status).toMatchObject({ exitCode: 0 });
    expect(status.output).toContain("kill switch ON");
    const again = run(["kill", "on"]);
    expect(again.output).toMatch(/^mode unchanged \(already in force\)/);
    expect(run(["kill", "off"]).output).toContain("kill switch off");
    // Every change is a chained, verifiable mode record.
    const s = unwrap(openAuditStore({ path: dbPath(), readonly: true }));
    try {
      const rows = unwrap(s.readAll());
      expect(rows.map((r) => ("invalid" in r ? "invalid" : r.kind))).toEqual(["mode", "mode"]);
      expect(unwrap(s.verify()).ok).toBe(true);
    } finally {
      s.close();
    }
  });

  it("shadow on with --actor; kill wins note when both are on", () => {
    expect(run(["shadow", "on", "--actor", "alice"]).output).toContain("by cli:alice");
    const both = run(["kill", "on"]);
    expect(both.output).toContain("kill switch wins");
  });

  it("takes effect on a running proxy's next money call (shared DB, per-call read)", () => {
    mkdirSync(join(repo, "data"));
    const proxyStore = unwrap(openAuditStore({ path: dbPath() }));
    try {
      const pre = createModePreCheck(createModeStore(proxyStore));
      const ctx = {} as unknown as CallContext;
      expect(pre(ctx)).toBeUndefined();
      expect(run(["kill", "on"]).exitCode).toBe(0);
      expect(pre(ctx)).toMatchObject({ ruleId: KILL_SWITCH_RULE });
      expect(run(["kill", "off"]).exitCode).toBe(0);
      expect(run(["shadow", "on"]).exitCode).toBe(0);
      expect(pre(ctx)).toEqual({ shadow: true });
    } finally {
      proxyStore.close();
    }
  });

  it("uses shell ASF_AUDIT_DB inside data/; refuses one outside", () => {
    const inside = run(["kill", "on"], deps({ ASF_AUDIT_DB: "data/other.db" }));
    expect(inside.exitCode).toBe(0);
    expect(existsSync(join(repo, "data", "other.db"))).toBe(true);
    const outside = run(["kill", "on"], deps({ ASF_AUDIT_DB: join(repo, "elsewhere.db") }));
    expect(outside.exitCode).toBe(2);
    expect(outside.output).toContain("inside <repo>/data/");
    expect(run(["kill", "on"], deps({ ASF_AUDIT_DB: ":memory:" })).exitCode).toBe(2);
  });

  it("bad usage ⇒ exit 2 with usage", () => {
    const r = run(["kill", "sideways"]);
    expect(r.exitCode).toBe(2);
    expect(r.output).toContain(MODE_USAGE);
  });

  it("no repo root ⇒ exit 2", () => {
    const r = runModeCommand(["status"], { ...deps(), isRepoRoot: () => false });
    expect(r.exitCode).toBe(2);
    expect(r.output).toContain("repo root");
  });

  it("an unreadable mode ⇒ status exit 1 (treated as kill ON); kill on/off writes a fresh valid record", () => {
    expect(run(["shadow", "on"]).exitCode).toBe(0);
    const raw = new Database(dbPath());
    raw.exec("DROP TRIGGER audit_log_no_update");
    raw.prepare("UPDATE audit_log SET body_json = '{}' WHERE kind = 'mode'").run();
    raw.close();
    const status = run(["status"]);
    expect(status.exitCode).toBe(1);
    expect(status.output).toContain("UNREADABLE");
    expect(status.output).toContain("kill switch as ON");
    // The corrupt record is the chain head: nothing can be appended after it (fail closed, exit 2).
    const write = run(["kill", "on"]);
    expect(write.exitCode).toBe(2);
    expect(write.output).toContain("the mode was NOT changed");
  });

  it("a mode record that fails its hash ⇒ status exit 1; kill on writes a fresh valid record", () => {
    expect(run(["kill", "off", "--actor", "a"]).exitCode).toBe(0); // no-op: nothing written
    expect(run(["shadow", "on"]).exitCode).toBe(0);
    const raw = new Database(dbPath());
    raw.exec("DROP TRIGGER audit_log_no_update");
    raw
      .prepare(
        "UPDATE audit_log SET body_json = replace(body_json, '\"shadow\":true', '\"shadow\":false') WHERE kind = 'mode'",
      )
      .run();
    raw.close();
    expect(run(["status"]).exitCode).toBe(1);
    const write = run(["kill", "on"]);
    expect(write.exitCode).toBe(0);
    expect(write.output).toContain("mode changed: kill switch ON; shadow mode off");
    expect(run(["status"]).exitCode).toBe(0);
  });

  it("the output never contains raw control characters", () => {
    const r = run(["kill", "on"], deps({}, "evil\u001b[2J\nuser"));
    for (const line of r.output.split("\n")) expect(line).toMatch(/^[\x20-\x7e]*$/);
    expect(r.output).toContain("cli:evil__2j_user");
  });
});
