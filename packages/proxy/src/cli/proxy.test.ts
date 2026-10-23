import { readFileSync } from "node:fs";
import { PassThrough } from "node:stream";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { fakeUpstream, jsonOf, lateUpstream } from "../test-support/fake-upstream.js";
import { DEFAULT_RAZORPAY_MCP_IMAGE } from "../tool-discovery.js";
import { DEFAULT_UPSTREAM_TIMEOUT_MS } from "../upstream.js";
import {
  AGENT_MAX_MESSAGE_BYTES,
  loadCachedTools,
  parseTimeoutMs,
  resolveProxyConfig,
  startProxy,
  stderrLogger,
  type ConfigDeps,
  type ProxyConfig,
} from "./proxy.js";

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
    });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await running.proxy.connect(b);
    const agent = new Client({ name: "t", version: "0" }, { capabilities: {} });
    await agent.connect(a);
    expect((await agent.listTools()).tools).toHaveLength(41);
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
