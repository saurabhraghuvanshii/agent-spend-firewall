import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { PassThrough } from "node:stream";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { fakeUpstream, jsonOf, lateUpstream } from "../test-support/fake-upstream.js";
import { compilePolicy } from "@asf/core";
import defaultPolicy from "@asf/policies";
import { openAuditStore } from "../audit-store.js";
import { DEFAULT_RAZORPAY_MCP_IMAGE } from "../tool-discovery.js";
import { DEFAULT_UPSTREAM_TIMEOUT_MS } from "../upstream.js";
import {
  AGENT_MAX_MESSAGE_BYTES,
  AUDIT_UNVERIFIED_MESSAGE,
  confineAuditDb,
  DEFAULT_AUDIT_DB,
  firewallReportLines,
  loadCachedTools,
  openFirewall,
  parseDuplicateWindowMs,
  parseLockWaitMs,
  parseTimeoutMs,
  resolveProxyConfig,
  startProxy,
  startupDegradation,
  stderrLogger,
  type ConfigDeps,
  type Firewall,
  type ProxyConfig,
} from "./proxy.js";

function memFirewall(): Firewall {
  const policy = compilePolicy(defaultPolicy);
  const store = openAuditStore({ path: ":memory:" });
  if (!policy.ok || !store.ok) throw new Error("firewall setup");
  return { policy: policy.value, store: store.value };
}

const KEY_ID = "rzp_test_Key123";
const KEY_SECRET = "TopSecretValue987";
const ROOT = "/repo";

function deps(files: Record<string, string> = {}, over: Partial<ConfigDeps> = {}): ConfigDeps {
  return {
    cwd: "/elsewhere",
    moduleDir: `${ROOT}/packages/proxy/src/cli`,
    isRepoRoot: (dir) => dir === ROOT,
    readFile: (p) => files[p],
    baseChildEnv: () => ({ PATH: "/usr/bin", HOME: "/home/u", RAZORPAY_KEY_ID: "inherited" }),
    ...over,
  };
}

const SHELL = { RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: KEY_SECRET };

describe("resolveProxyConfig (key guard & env)", () => {
  it("accepts test keys from the shell; real keys only in the child env", () => {
    const r = resolveProxyConfig(SHELL, deps());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const c = r.value;
    expect(c.repoRoot).toBe(ROOT);
    expect(c.image).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    expect(c.callTimeoutMs).toBe(DEFAULT_UPSTREAM_TIMEOUT_MS);
    expect(c.childEnv).toEqual({
      PATH: "/usr/bin",
      HOME: "/home/u",
      RAZORPAY_KEY_ID: KEY_ID,
      RAZORPAY_KEY_SECRET: KEY_SECRET,
    });
    expect(c.dockerEnv).toEqual({ PATH: "/usr/bin", HOME: "/home/u" });
  });

  it("reads keys from <repoRoot>/.env at runtime; non-empty shell values win", () => {
    const env = `RAZORPAY_KEY_ID=rzp_test_FromFile1\nRAZORPAY_KEY_SECRET=fileSecret0000000\nASF_UPSTREAM_TIMEOUT_MS=5000\n`;
    const r = resolveProxyConfig(
      { RAZORPAY_KEY_SECRET: "shellSecret000000", RAZORPAY_KEY_ID: "" },
      deps({ [`${ROOT}/.env`]: env }),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.keys).toEqual({ keyId: "rzp_test_FromFile1", keySecret: "shellSecret000000" });
    expect(r.value.callTimeoutMs).toBe(5000);
  });

  it.each([
    [{ RAZORPAY_KEY_ID: "rzp_live_abc", RAZORPAY_KEY_SECRET: "s" }, "discover.live_key"],
    [{ ...SHELL, OTHER: "x RZP_LIVE_y" }, "discover.live_key"],
    [{ RAZORPAY_KEY_ID: "key_abc", RAZORPAY_KEY_SECRET: "s" }, "discover.not_test_key"],
    [{ RAZORPAY_KEY_SECRET: "s" }, "discover.missing_key_id"],
    [{ RAZORPAY_KEY_ID: KEY_ID }, "discover.missing_key_secret"],
    [{ RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: "tooShort1" }, "discover.bad_key_secret"],
  ])("refuses %j (%s) without echoing values", (shell, code) => {
    const r = resolveProxyConfig(shell, deps());
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.code).toBe(code);
    expect(r.error.message).not.toMatch(/rzp_live_abc|key_abc|RZP_LIVE_y|tooShort1/);
  });

  it("refuses a live key that only appears in .env", () => {
    const r = resolveProxyConfig(
      {},
      deps({ [`${ROOT}/.env`]: "RAZORPAY_KEY_ID=rzp_live_X\nRAZORPAY_KEY_SECRET=s\n" }),
    );
    expect(r.ok).toBe(false);
  });

  it("image override from the shell only; .env value ignored with a note", () => {
    const fromFile = resolveProxyConfig(
      SHELL,
      deps({ [`${ROOT}/.env`]: "ASF_RAZORPAY_MCP_IMAGE=evil/image:latest\n" }),
    );
    expect(fromFile.ok && fromFile.value.image).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    expect(fromFile.ok && fromFile.value.notes.join(" ")).toMatch(/ignored/);
    const fromShell = resolveProxyConfig(
      { ...SHELL, ASF_RAZORPAY_MCP_IMAGE: "razorpay/mcp:v1" },
      deps(),
    );
    expect(fromShell.ok && fromShell.value.image).toBe("razorpay/mcp:v1");
    const bad = resolveProxyConfig({ ...SHELL, ASF_RAZORPAY_MCP_IMAGE: "--privileged" }, deps());
    expect(bad.ok).toBe(false);
  });

  it("docker client vars come from the shell, never .env", () => {
    const r = resolveProxyConfig(
      { ...SHELL, DOCKER_HOST: "unix:///shell.sock" },
      deps({ [`${ROOT}/.env`]: "DOCKER_CONTEXT=evil\n" }),
    );
    expect(r.ok && r.value.childEnv["DOCKER_HOST"]).toBe("unix:///shell.sock");
    expect(r.ok && r.value.childEnv["DOCKER_CONTEXT"]).toBe(undefined);
  });

  it("finds the repo root from the module dir when spawned elsewhere; errors if none", () => {
    expect(resolveProxyConfig(SHELL, deps()).ok).toBe(true);
    const none = resolveProxyConfig(SHELL, deps({}, { isRepoRoot: () => false }));
    expect(none.ok).toBe(false);
  });

  it("rejects a bad ASF_UPSTREAM_TIMEOUT_MS", () => {
    expect(resolveProxyConfig({ ...SHELL, ASF_UPSTREAM_TIMEOUT_MS: "abc" }, deps()).ok).toBe(false);
  });
});

describe("parseTimeoutMs", () => {
  it.each([
    [undefined, DEFAULT_UPSTREAM_TIMEOUT_MS],
    ["", DEFAULT_UPSTREAM_TIMEOUT_MS],
    ["1000", 1000],
    ["600000", 600000],
  ])("%j ⇒ %d", (raw, n) => {
    expect(parseTimeoutMs(raw)).toEqual({ ok: true, value: n });
  });
  it.each(["999", "600001", "1e4", "-5", "30000.5", " 30000"])("rejects %j", (raw) => {
    expect(parseTimeoutMs(raw).ok).toBe(false);
  });
});

describe("loadCachedTools", () => {
  it("loads the committed docs/razorpay-tools.json (41 tools)", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const content = readFileSync(resolve(here, "../../../../docs/razorpay-tools.json"), "utf8");
    const r = loadCachedTools(content);
    expect(r.note).toBeUndefined();
    expect(r.tools).toHaveLength(41);
    expect(r.tools.map((t) => t.name)).toContain("create_refund");
  });

  it.each([undefined, "not json", JSON.stringify({ schemaVersion: 2 })])(
    "falls back to no cache for %j",
    (c) => {
      const r = loadCachedTools(c);
      expect(r.tools).toEqual([]);
      expect(r.note).toBeDefined();
    },
  );
});

describe("stderrLogger", () => {
  it("prefixes and escapes every line", () => {
    const out: string[] = [];
    stderrLogger((s) => out.push(s))("a\nb \u001b[31m");
    expect(out).toEqual(["[asf-proxy] a\n", "[asf-proxy] b \\u001b[31m\n"]);
  });
});

describe("startProxy", () => {
  const writes = vi.spyOn(process.stdout, "write");
  afterEach(() => {
    writes.mockClear();
  });

  function config(): ProxyConfig {
    const r = resolveProxyConfig(SHELL, deps());
    if (!r.ok) throw new Error("config");
    return r.value;
  }

  it("serves the agent, logs only via the logger, never writes to stdout, and shuts down cleanly", async () => {
    const fake = fakeUpstream({
      handler: () => Promise.reject(new Error(`boom ${KEY_SECRET}`)),
    });
    const logs: string[] = [];
    const running = startProxy({
      config: config(),
      logger: (l) => logs.push(l),
      factory: fake.factory,
      firewall: memFirewall(),
    });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await running.proxy.connect(b);
    const agent = new Client({ name: "t", version: "0" }, { capabilities: {} });
    await agent.connect(a);

    expect((await agent.listTools()).tools).toHaveLength(3);
    const r = await agent.request(
      {
        method: "tools/call",
        params: { name: "fetch_payment", arguments: { payment_id: "pay_1" } },
      },
      CallToolResultSchema,
    );
    expect(jsonOf(r)).toMatchObject({ error: "upstream_error" });
    expect(JSON.stringify(r)).not.toContain(KEY_SECRET);
    const unknown = await agent.request(
      { method: "tools/call", params: { name: "nope", arguments: {} } },
      CallToolResultSchema,
    );
    expect(jsonOf(unknown)).toMatchObject({ ruleId: "firewall.unknown_tool" });

    // T004 wiring: money tools advertise a required reason and calls without one never reach upstream.
    const listed = await agent.listTools();
    const refund = listed.tools.find((t) => t.name === "create_refund");
    expect(refund?.inputSchema.required).toContain("reason");
    expect(listed.tools.find((t) => t.name === "fetch_payment")?.inputSchema.required).toEqual([
      "payment_id",
    ]);
    const before = fake.calls.length;
    const noReason = await agent.request(
      {
        method: "tools/call",
        params: { name: "create_refund", arguments: { payment_id: "pay_1", amount: 100 } },
      },
      CallToolResultSchema,
    );
    expect(jsonOf(noReason)).toMatchObject({ ruleId: "firewall.reason_required" });
    expect(fake.calls.length).toBe(before);

    await running.shutdown();
    await running.shutdown();
    expect(fake.disposed()).toBe(1);
    expect(writes).not.toHaveBeenCalled();
    expect(logs.join("\n")).not.toContain(KEY_SECRET);
    await agent.close();
  });

  it("starts even when upstream is down (serves the configured cache)", async () => {
    const fake = fakeUpstream();
    fake.setFailing(true);
    const cfg = config();
    const here = dirname(fileURLToPath(import.meta.url));
    const cache = loadCachedTools(
      readFileSync(join(here, "../../../../docs/razorpay-tools.json"), "utf8"),
    );
    const logs: string[] = [];
    const running = startProxy({
      config: { ...cfg, cachedTools: cache.tools },
      logger: (l) => logs.push(l),
      factory: fake.factory,
      firewall: memFirewall(),
    });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await running.proxy.connect(b);
    const agent = new Client({ name: "t", version: "0" }, { capabilities: {} });
    await agent.connect(a);
    const cachedList = (await agent.listTools()).tools;
    expect(cachedList).toHaveLength(41);
    // The cached snapshot is rewritten too: money tools require a reason.
    expect(cachedList.find((t) => t.name === "create_refund")?.inputSchema.required).toContain(
      "reason",
    );
    await running.shutdown();
    await agent.close();
    expect(writes).not.toHaveBeenCalled();
    expect(logs.some((l) => l.includes("upstream not available yet"))).toBe(true);
  }, 15_000);
});

describe("late upstream responses (startProxy)", () => {
  it("logs metadata only (id, tool, type) — never the response body", async () => {
    const late = lateUpstream({
      delayMs: 50,
      result: {
        content: [{ type: "text", text: '{"email":"bob@example.com","vpa":"bob@okbank"}' }],
      },
    });
    const r = resolveProxyConfig({ ...SHELL, ASF_UPSTREAM_TIMEOUT_MS: "1000" }, deps());
    if (!r.ok) throw new Error("config");
    const logs: string[] = [];
    const running = startProxy({
      config: r.value,
      logger: (l) => logs.push(l),
      factory: late.factory,
      firewall: memFirewall(),
    });
    const outcome = await running.upstream.callTool(
      "create_refund",
      { payment_id: "pay_1", amount: 100 },
      { timeoutMs: 10 },
    );
    expect(outcome).toMatchObject({ kind: "error", error: "upstream_timeout" });
    await vi.waitFor(() => {
      expect(logs.some((l) => l.startsWith("late upstream response:"))).toBe(true);
    });
    const line = logs.find((l) => l.startsWith("late upstream response:"));
    expect(line).toBe(
      `late upstream response: id ${String(late.callIds[0])}, tool create_refund, result, generation 1`,
    );
    const all = logs.join("\n");
    expect(all).not.toMatch(/bob@example\.com|bob@okbank|email/);
    await running.shutdown();
  });
});

describe("agent message size cap", () => {
  it("an oversized agent message closes the channel without logging its content", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const t = new StdioServerTransport(stdin, stdout, { maxBufferSize: AGENT_MAX_MESSAGE_BYTES });
    const errors: Error[] = [];
    let closed = false;
    t.onerror = (e) => errors.push(e);
    t.onclose = () => {
      closed = true;
    };
    await t.start();
    stdin.write(Buffer.alloc(AGENT_MAX_MESSAGE_BYTES + 1, "a"));
    await vi.waitFor(() => {
      expect(closed).toBe(true);
    });
    expect(errors).toHaveLength(1);
    expect(AGENT_MAX_MESSAGE_BYTES).toBe(1024 * 1024);
  });
});

describe("T008 config: ASF_POLICY / ASF_AUDIT_DB / ASF_LOCK_WAIT_MS", () => {
  it("defaults", () => {
    const r = resolveProxyConfig(SHELL, deps());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.policyPath).toBeUndefined();
    expect(r.value.auditDbPath).toBe(join(ROOT, DEFAULT_AUDIT_DB));
    expect(r.value.lockWaitMs).toBe(5000);
  });

  it("reads shell overrides; relative DB paths resolve against the repo root", () => {
    const r = resolveProxyConfig(
      {
        ...SHELL,
        ASF_POLICY: "policies/strict.ts",
        ASF_LOCK_WAIT_MS: "250",
        ASF_AUDIT_DB: "data/run/a.db",
      },
      deps(),
    );
    expect(r.ok && r.value.policyPath).toBe("policies/strict.ts");
    expect(r.ok && r.value.auditDbPath).toBe(join(ROOT, "data/run/a.db"));
    expect(r.ok && r.value.lockWaitMs).toBe(250);
    const abs = resolveProxyConfig({ ...SHELL, ASF_AUDIT_DB: `${ROOT}/data/b.db` }, deps());
    expect(abs.ok && abs.value.auditDbPath).toBe(`${ROOT}/data/b.db`);
  });

  it("ASF_POLICY / ASF_AUDIT_DB in .env only are ignored with a note (shell env only)", () => {
    const r = resolveProxyConfig(
      SHELL,
      deps({ [`${ROOT}/.env`]: "ASF_AUDIT_DB=data/evil.db\nASF_POLICY=policies/open.ts\n" }),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.policyPath).toBeUndefined();
    expect(r.value.auditDbPath).toBe(join(ROOT, DEFAULT_AUDIT_DB));
    expect(r.value.notes).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^ASF_POLICY from \.env is ignored/) as string,
        expect.stringMatching(/^ASF_AUDIT_DB from \.env is ignored/) as string,
      ]),
    );
    // the shell value wins without a note
    const shell = resolveProxyConfig(
      { ...SHELL, ASF_POLICY: "policies/x.ts" },
      deps({ [`${ROOT}/.env`]: "ASF_POLICY=policies/open.ts\n" }),
    );
    expect(shell.ok && shell.value.policyPath).toBe("policies/x.ts");
    expect(shell.ok && shell.value.notes.join(" ")).not.toMatch(/ASF_POLICY/);
  });

  it.each([
    "/tmp/x/a.db",
    "var/a.db",
    "data",
    "data/",
    "data/../a.db",
    "../data/a.db",
    "/repo/database/a.db",
  ])("refuses ASF_AUDIT_DB=%j outside <repo>/data/ (exit 2)", (db) => {
    const r = resolveProxyConfig({ ...SHELL, ASF_AUDIT_DB: db }, deps());
    expect(!r.ok && r.error.code).toBe("proxy.bad_audit_db");
  });

  it.each([
    [{ ASF_LOCK_WAIT_MS: "0" }, "proxy.bad_lock_wait"],
    [{ ASF_LOCK_WAIT_MS: "abc" }, "proxy.bad_lock_wait"],
    [{ ASF_LOCK_WAIT_MS: "60001" }, "proxy.bad_lock_wait"],
    [{ ASF_AUDIT_DB: ":memory:" }, "proxy.bad_audit_db"],
  ])("refuses %j", (extra, code) => {
    const r = resolveProxyConfig({ ...SHELL, ...extra }, deps());
    expect(!r.ok && r.error.code).toBe(code);
  });
});

describe("parseLockWaitMs", () => {
  it.each([
    [undefined, 5000],
    ["", 5000],
    ["1", 1],
    ["60000", 60000],
  ])("%j ⇒ %d", (raw, n) => {
    expect(parseLockWaitMs(raw)).toEqual({ ok: true, value: n });
  });
  it.each(["0", "60001", "1.5", "-1", " 5", "1e3"])("rejects %j", (raw) => {
    expect(parseLockWaitMs(raw).ok).toBe(false);
  });
});

const DENY_POLICY = 'export default { default: "deny", rules: [] };\n';

describe("openFirewall (startup refusal ⇒ exit 2)", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const realRoot = resolve(here, "../../../..");
  let tmp: string;

  afterEach(() => {
    if (tmp !== undefined) rmSync(tmp, { recursive: true, force: true });
  });

  function cfg(over: Partial<ProxyConfig>): ProxyConfig {
    const r = resolveProxyConfig(SHELL, deps());
    if (!r.ok) throw new Error("config");
    return { ...r.value, repoRoot: realRoot, ...over };
  }

  /** A temp repo root with a deny-by-default policy at p.mjs. */
  function tmpRepo(): string {
    tmp = mkdtempSync(join(tmpdir(), "asf-cli-"));
    writeFileSync(join(tmp, "pnpm-workspace.yaml"), "");
    writeFileSync(join(tmp, "p.mjs"), DENY_POLICY);
    return tmp;
  }

  it("creates <repo>/data, opens a new store, reports policy hash and warns that the DB was created", async () => {
    const root = tmpRepo();
    const fw = await openFirewall(
      cfg({ repoRoot: root, policyPath: "p.mjs", auditDbPath: join(root, "data", "audit.db") }),
    );
    expect(fw.ok).toBe(true);
    if (!fw.ok) return;
    expect(fw.value.policy.default).toBe("deny");
    expect(fw.value.store.readonly).toBe(false);
    const report = fw.value.report;
    expect(report).toMatchObject({
      policyRelPath: "p.mjs",
      policySha256: createHash("sha256").update(DENY_POLICY).digest("hex"),
      auditDbCreated: true,
      audit: { ok: true, count: 0 },
    });
    const lines = firewallReportLines(report, 0);
    expect(lines[0]).toContain(`policy p.mjs sha256 ${report.policySha256}`);
    expect(lines.join("\n")).toMatch(/0 records, head hash/);
    expect(lines.join("\n")).toMatch(/WARNING: audit DB .* was CREATED/);
    // a second start on the same file: existing, no warning, count + head hash reported
    const att = fw.value.store.recordAttempt({
      sessionId: "s",
      tool: "create_refund",
      args: { payment_id: "pay_1", amount: 1 },
      reason: "seed record for the test",
      decision: "deny",
      matchedRules: ["x"],
    });
    expect(att.ok).toBe(true);
    fw.value.store.close();
    const again = await openFirewall(
      cfg({ repoRoot: root, policyPath: "p.mjs", auditDbPath: join(root, "data", "audit.db") }),
    );
    expect(again.ok).toBe(true);
    if (!again.ok) return;
    expect(again.value.report.auditDbCreated).toBe(false);
    expect(again.value.report.audit).toMatchObject({ ok: true, count: 1 });
    const l2 = firewallReportLines(again.value.report, 0).join("\n");
    expect(l2).toMatch(/1 records, head hash [0-9a-f]{64}/);
    expect(l2).not.toMatch(/CREATED/);
    again.value.store.close();
  });

  it("loads the repo's policies/default.ts (hash reported) before refusing an audit DB outside data/", async () => {
    tmp = mkdtempSync(join(tmpdir(), "asf-cli-"));
    const fw = await openFirewall(cfg({ auditDbPath: join(tmp, "a.db") }));
    expect(!fw.ok && fw.error.code).toBe("proxy.bad_audit_db");
    expect(() => readFileSync(join(tmp, "a.db"))).toThrow();
  });

  it("refuses a data/ subdirectory symlinked outside the repo, and a DB file that is a symlink", async () => {
    const root = tmpRepo();
    mkdirSync(join(root, "data"));
    mkdirSync(join(root, "elsewhere"));
    symlinkSync(join(root, "elsewhere"), join(root, "data", "link"));
    const viaDir = await openFirewall(
      cfg({ repoRoot: root, policyPath: "p.mjs", auditDbPath: join(root, "data", "link", "a.db") }),
    );
    expect(!viaDir.ok && viaDir.error.code).toBe("proxy.bad_audit_db");
    writeFileSync(join(root, "elsewhere", "real.db"), "");
    symlinkSync(join(root, "elsewhere", "real.db"), join(root, "data", "a.db"));
    const viaFile = await openFirewall(
      cfg({ repoRoot: root, policyPath: "p.mjs", auditDbPath: join(root, "data", "a.db") }),
    );
    expect(!viaFile.ok && viaFile.error.code).toBe("proxy.bad_audit_db");
  });

  it("refuses when <repo>/data itself is a symlink out of the repo", () => {
    const root = tmpRepo();
    mkdirSync(join(root, "outside"));
    symlinkSync(join(root, "outside"), join(root, "data"));
    const r = confineAuditDb(join(root, "data", "a.db"), root);
    expect(!r.ok && r.error.code).toBe("proxy.bad_audit_db");
  });

  it("refuses a missing nested parent directory (never created outside data/ itself)", () => {
    const root = tmpRepo();
    const r = confineAuditDb(join(root, "data", "nested", "a.db"), root);
    expect(!r.ok && r.error.code).toBe("proxy.bad_audit_db");
    mkdirSync(join(root, "data", "nested"));
    const ok2 = confineAuditDb(join(root, "data", "nested", "a.db"), root);
    expect(ok2.ok && ok2.value.existed).toBe(false);
  });

  it("refuses a missing policy file", async () => {
    const root = tmpRepo();
    const fw = await openFirewall(
      cfg({ repoRoot: root, policyPath: "nope.mjs", auditDbPath: join(root, "data", "a.db") }),
    );
    expect(!fw.ok && fw.error.code).toBe("policy.not_found");
  });

  it("refuses an allow-by-default policy before opening the store", async () => {
    const root = tmpRepo();
    writeFileSync(join(root, "open.mjs"), 'export default { default: "allow", rules: [] };\n');
    const fw = await openFirewall(
      cfg({ repoRoot: root, policyPath: "open.mjs", auditDbPath: join(root, "data", "a.db") }),
    );
    expect(!fw.ok && fw.error.code).toBe("policy.allow_default");
    expect(() => readFileSync(join(root, "data", "a.db"))).toThrow();
  });

  it("refuses an audit DB that cannot be opened", async () => {
    const root = tmpRepo();
    mkdirSync(join(root, "data"));
    mkdirSync(join(root, "data", "dir.db"));
    const fw = await openFirewall(
      cfg({ repoRoot: root, policyPath: "p.mjs", auditDbPath: join(root, "data", "dir.db") }),
    );
    expect(fw.ok).toBe(false);
  });

  it("refuses a policy symlinked from outside the repo", async () => {
    tmp = mkdtempSync(join(tmpdir(), "asf-cli-"));
    mkdirSync(join(tmp, "root"));
    writeFileSync(join(tmp, "outside.mjs"), DENY_POLICY);
    symlinkSync(join(tmp, "outside.mjs"), join(tmp, "root", "p.mjs"));
    const fw = await openFirewall(
      cfg({
        repoRoot: join(tmp, "root"),
        policyPath: "p.mjs",
        auditDbPath: join(tmp, "root", "data", "a.db"),
      }),
    );
    expect(!fw.ok && fw.error.code).toBe("policy.outside_repo");
  });
});

describe("firewallReportLines", () => {
  it("warns loudly on a broken chain", () => {
    const lines = firewallReportLines(
      {
        policyRelPath: "policies/default.ts",
        policySha256: "a".repeat(64),
        auditDbPath: "/repo/data/audit.db",
        auditDbCreated: false,
        audit: { ok: false, brokenAtSeq: 7, reason: "hash_mismatch" },
      },
      3,
    );
    expect(lines[0]).toBe(`policy policies/default.ts sha256 ${"a".repeat(64)} loaded (3 rules)`);
    expect(lines[1]).toMatch(/^WARNING: audit log .* FAILED chain verification at seq 7/);
  });
});

describe("startProxy money pipeline wiring (T008)", () => {
  it("a refund is evaluated, forwarded without reason, audited; read results are redacted for the agent", async () => {
    const fake = fakeUpstream({
      handler: (name, args) => {
        if (name === "fetch_payment") {
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  id: args?.["payment_id"],
                  status: "captured",
                  amount: 100_000,
                  amount_refunded: 0,
                  currency: "INR",
                  email: "bob@example.com",
                }),
              },
            ],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: JSON.stringify({ id: "rfnd_CLI1", args }) }],
        });
      },
    });
    const r = resolveProxyConfig(SHELL, deps());
    if (!r.ok) throw new Error("config");
    const firewall = memFirewall();
    const running = startProxy({
      config: r.value,
      logger: () => undefined,
      factory: fake.factory,
      firewall,
    });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await running.proxy.connect(b);
    const agent = new Client({ name: "t", version: "0" }, { capabilities: {} });
    await agent.connect(a);
    const refund = await agent.request(
      {
        method: "tools/call",
        params: {
          name: "create_refund",
          arguments: {
            payment_id: "pay_CLI1",
            amount: 5_000,
            reason: "customer cust_1 was double charged for order_9",
          },
        },
      },
      CallToolResultSchema,
    );
    expect(jsonOf(refund)).toMatchObject({ id: "rfnd_CLI1" });
    const sent = fake.calls.find((c) => c.name === "create_refund");
    expect(sent?.args).toEqual({ payment_id: "pay_CLI1", amount: 5_000 });
    const rows = firewall.store.readAll();
    expect(rows.ok && rows.value).toMatchObject([
      { kind: "attempt", decision: "allow", tool: "create_refund" },
      { kind: "outcome", outcome: "success", upstreamRef: "rfnd_CLI1" },
    ]);
    const read = await agent.request(
      {
        method: "tools/call",
        params: { name: "fetch_payment", arguments: { payment_id: "pay_CLI1" } },
      },
      CallToolResultSchema,
    );
    expect(JSON.stringify(read)).not.toContain("bob@example.com");
    expect(jsonOf(read)).toMatchObject({ id: "pay_CLI1", currency: "INR", email: "[REDACTED]" });
    await running.shutdown();
    await agent.close();
    // shutdown closed the store
    expect(firewall.store.readAll().ok).toBe(false);
  });
});

describe("startup audit verification ⇒ money pipeline latch (owner decision)", () => {
  let tmp: string | undefined;
  afterEach(() => {
    if (tmp !== undefined) rmSync(tmp, { recursive: true, force: true });
    tmp = undefined;
  });

  const PAYMENT = {
    status: "captured",
    amount: 100_000,
    amount_refunded: 0,
    currency: "INR",
  };

  /** A temp repo with a deny-by-default policy and an audit DB seeded by `seed` (store closed afterwards). */
  function seededRepo(seed: (store: Firewall["store"]) => void): { root: string; db: string } {
    const root = mkdtempSync(join(tmpdir(), "asf-latch-"));
    tmp = root;
    writeFileSync(join(root, "pnpm-workspace.yaml"), "");
    writeFileSync(join(root, "p.mjs"), DENY_POLICY);
    mkdirSync(join(root, "data"));
    const db = join(root, "data", "audit.db");
    const s = openAuditStore({ path: db });
    if (!s.ok) throw new Error("store");
    seed(s.value);
    s.value.close();
    return { root, db };
  }

  function seedAttempt(store: Firewall["store"], paymentId: string): string {
    const a = store.recordAttempt({
      sessionId: "s0",
      tool: "create_refund",
      args: { payment_id: paymentId, amount: 100 },
      reason: "seed record for the latch test",
      decision: "deny",
      matchedRules: ["x"],
    });
    if (!a.ok) throw new Error("seed");
    return a.value.id;
  }

  function tamper(db: string, seq: number): void {
    const d = new Database(db);
    try {
      d.exec("DROP TRIGGER audit_log_no_update");
      const row: unknown = d.prepare("SELECT body_json FROM audit_log WHERE seq = ?").get(seq);
      if (typeof row !== "object" || row === null || !("body_json" in row)) throw new Error("row");
      const body = String(row.body_json);
      d.prepare("UPDATE audit_log SET body_json = ? WHERE seq = ?").run(
        body.replace('"amount":100', '"amount":100000'),
        seq,
      );
    } finally {
      d.close();
    }
  }

  async function run(root: string, db: string) {
    const r = resolveProxyConfig(SHELL, deps());
    if (!r.ok) throw new Error("config");
    const config: ProxyConfig = {
      ...r.value,
      repoRoot: root,
      policyPath: "p.mjs",
      auditDbPath: db,
    };
    const fw = await openFirewall(config);
    if (!fw.ok) throw new Error(`openFirewall: ${fw.error.code}`);
    const policy = compilePolicy(defaultPolicy);
    if (!policy.ok) throw new Error("policy");
    const fake = fakeUpstream({
      handler: (name, args) =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify(
                name === "fetch_payment"
                  ? { id: args?.["payment_id"], ...PAYMENT }
                  : { id: "rfnd_LATCH1", args },
              ),
            },
          ],
        }),
    });
    const startDegraded = startupDegradation(fw.value.report);
    const logs: string[] = [];
    const running = startProxy({
      config,
      logger: (l) => logs.push(l),
      factory: fake.factory,
      // the default policy (allows a small refund); the store + report come from openFirewall
      firewall: { policy: policy.value, store: fw.value.store },
      ...(startDegraded === undefined ? {} : { startDegraded }),
    });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await running.proxy.connect(b);
    const agent = new Client({ name: "t", version: "0" }, { capabilities: {} });
    await agent.connect(a);
    const refund = await agent.request(
      {
        method: "tools/call",
        params: {
          name: "create_refund",
          arguments: {
            payment_id: "pay_LATCH1",
            amount: 5_000,
            reason: "customer cust_1 was double charged for order_9",
          },
        },
      },
      CallToolResultSchema,
    );
    const read = await agent.request(
      {
        method: "tools/call",
        params: { name: "fetch_payment", arguments: { payment_id: "pay_LATCH1" } },
      },
      CallToolResultSchema,
    );
    const rows = fw.value.store.readAll();
    const result = {
      report: fw.value.report,
      reportLines: firewallReportLines(fw.value.report, 0),
      degraded: running.pipeline.isDegraded(),
      refund,
      read,
      refundsSent: fake.calls.filter((c) => c.name === "create_refund"),
      readsSent: fake.calls.filter((c) => c.name === "fetch_payment"),
      rows: rows.ok ? rows.value : [],
      logs,
    };
    await running.shutdown();
    await agent.close();
    return result;
  }

  it("broken chain ⇒ starts, money call denied audit_unavailable (audited best-effort), read call forwarded", async () => {
    const { root, db } = seededRepo((s) => {
      seedAttempt(s, "pay_SEED1");
      seedAttempt(s, "pay_SEED2");
    });
    tamper(db, 1);
    const r = await run(root, db);
    expect(r.report.audit.ok).toBe(false);
    expect(r.reportLines.join("\n")).toMatch(/WARNING: MONEY ACTIONS ARE DISABLED/);
    expect(r.logs.some((l) => l.startsWith("AUDIT DEGRADED AT STARTUP"))).toBe(true);
    expect(r.degraded).toBe(true);
    expect(r.refund.isError).toBe(true);
    expect(jsonOf(r.refund)).toEqual({
      decision: "deny",
      ruleId: "audit_unavailable",
      message: AUDIT_UNVERIFIED_MESSAGE,
    });
    expect(AUDIT_UNVERIFIED_MESSAGE).toBe(
      "audit log failed verification at startup; money actions disabled until it is repaired",
    );
    expect(r.refundsSent).toEqual([]);
    expect(r.read.isError).not.toBe(true);
    expect(r.readsSent).toHaveLength(1);
    expect(r.rows.slice(-2)).toMatchObject([
      {
        kind: "attempt",
        decision: "deny",
        tool: "create_refund",
        matchedRules: ["audit_unavailable"],
      },
      { kind: "outcome", outcome: "denied" },
    ]);
  });

  it("healthy chain ⇒ not degraded, money call forwarded", async () => {
    const { root, db } = seededRepo((s) => {
      const id = seedAttempt(s, "pay_SEED1");
      const o = s.recordOutcome({ attemptId: id, outcome: "denied", latencyMs: 0 });
      if (!o.ok) throw new Error("seed outcome");
    });
    const r = await run(root, db);
    expect(r.report.audit.ok).toBe(true);
    expect(startupDegradation(r.report)).toBeUndefined();
    expect(r.reportLines.join("\n")).not.toMatch(/MONEY ACTIONS ARE DISABLED/);
    expect(r.degraded).toBe(false);
    expect(jsonOf(r.refund)).toMatchObject({ id: "rfnd_LATCH1" });
    expect(r.refundsSent).toHaveLength(1);
  });

  it("dangling attempts only ⇒ not degraded, money call forwarded", async () => {
    const { root, db } = seededRepo((s) => {
      seedAttempt(s, "pay_SEED1");
    });
    const r = await run(root, db);
    expect(r.report.audit.ok).toBe(true);
    expect(r.degraded).toBe(false);
    expect(jsonOf(r.refund)).toMatchObject({ id: "rfnd_LATCH1" });
    expect(r.refundsSent).toHaveLength(1);
  });
});

describe("T009 config: ASF_DUPLICATE_WINDOW_MS (shell env only)", () => {
  it.each([
    [undefined, 600_000],
    ["", 600_000],
    ["60000", 60_000],
    ["86400000", 86_400_000],
    ["900000", 900_000],
  ])("%j ⇒ %d", (raw, n) => {
    expect(parseDuplicateWindowMs(raw)).toEqual({ ok: true, value: n });
  });

  it.each(["0", "59999", "86400001", "1.5", "-1", " 60000", "6e4", "123456789"])(
    "rejects %j",
    (raw) => {
      const r = parseDuplicateWindowMs(raw);
      expect(!r.ok && r.error.code).toBe("proxy.bad_duplicate_window");
    },
  );

  it("default, shell override, bad shell value refuses to start", () => {
    const d = resolveProxyConfig(SHELL, deps());
    expect(d.ok && d.value.duplicateWindowMs).toBe(600_000);
    const s = resolveProxyConfig({ ...SHELL, ASF_DUPLICATE_WINDOW_MS: "120000" }, deps());
    expect(s.ok && s.value.duplicateWindowMs).toBe(120_000);
    const bad = resolveProxyConfig({ ...SHELL, ASF_DUPLICATE_WINDOW_MS: "10" }, deps());
    expect(!bad.ok && bad.error.code).toBe("proxy.bad_duplicate_window");
  });

  it("a value only in .env is ignored with a note", () => {
    const r = resolveProxyConfig(
      SHELL,
      deps({ [`${ROOT}/.env`]: "ASF_DUPLICATE_WINDOW_MS=60000\n" }),
    );
    expect(r.ok && r.value.duplicateWindowMs).toBe(600_000);
    expect(r.ok && r.value.notes.join(" ")).toMatch(
      /ASF_DUPLICATE_WINDOW_MS from \.env is ignored/,
    );
  });
});
