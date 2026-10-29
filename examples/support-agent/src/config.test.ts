import { describe, expect, it } from "vitest";
import { DEFAULT_RAZORPAY_MCP_IMAGE } from "@asf/proxy";
import { checkFirewallEnvFile, loadConfig, type ConfigDeps } from "./config.js";

const ROOT = "/repo";
const KEY_ID = "rzp_test_Key123";
const KEY_SECRET = "TopSecretValue987";
const SHELL = { RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: KEY_SECRET };

function deps(files: Record<string, string> = {}): ConfigDeps {
  return {
    cwd: `${ROOT}/examples/support-agent`,
    moduleDir: `${ROOT}/examples/support-agent/src`,
    isRepoRoot: (d) => d === ROOT,
    readFile: (p) => files[p],
  };
}

describe("loadConfig", () => {
  it("test keys from the shell or .env (shell wins)", () => {
    const r = loadConfig(SHELL, deps());
    expect(r.ok && r.value.keys).toEqual({ keyId: KEY_ID, keySecret: KEY_SECRET });
    expect(r.ok && r.value.repoRoot).toBe(ROOT);
    const fromFile = loadConfig(
      {},
      deps({ [`${ROOT}/.env`]: `RAZORPAY_KEY_ID=${KEY_ID}\nRAZORPAY_KEY_SECRET=${KEY_SECRET}\n` }),
    );
    expect(fromFile.ok && fromFile.value.keys.keyId).toBe(KEY_ID);
  });

  it.each([
    ["shell key id", { ...SHELL, RAZORPAY_KEY_ID: "rzp_live_Abc123" }, {}],
    ["any shell var", { ...SHELL, OTHER: "x rzp_live_Abc123" }, {}],
    ["uppercase", { ...SHELL, OTHER: "RZP_LIVE_ABC" }, {}],
    ["only in .env", SHELL, { [`${ROOT}/.env`]: "SOMETHING=rzp_live_Abc123\n" }],
  ])("refuses a live key (%s)", (_l, shell, files) => {
    const r = loadConfig(shell, deps(files));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("discover.live_key");
      expect(r.error.message).not.toContain("Abc123");
    }
  });

  it("missing or non-test keys are refused; messages never echo values", () => {
    expect(loadConfig({}, deps()).ok).toBe(false);
    const r = loadConfig({ ...SHELL, RAZORPAY_KEY_ID: "key_Abcdef" }, deps());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).not.toContain("key_Abcdef");
  });

  it("image override from the shell only", () => {
    const fromFile = loadConfig(
      SHELL,
      deps({ [`${ROOT}/.env`]: "ASF_RAZORPAY_MCP_IMAGE=evil/x\n" }),
    );
    expect(fromFile.ok && fromFile.value.image).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    const shell = loadConfig({ ...SHELL, ASF_RAZORPAY_MCP_IMAGE: "razorpay/mcp:v1" }, deps());
    expect(shell.ok && shell.value.image).toBe("razorpay/mcp:v1");
    expect(loadConfig({ ...SHELL, ASF_RAZORPAY_MCP_IMAGE: "--privileged" }, deps()).ok).toBe(false);
  });

  it("no repo root ⇒ refused", () => {
    const r = loadConfig(SHELL, { ...deps(), isRepoRoot: () => false });
    expect(r.ok === false && r.error.code).toBe("example.no_repo_root");
  });
});

describe("checkFirewallEnvFile (firewall mode: the proxy reads the keys from .env)", () => {
  const ENV = `${ROOT}/.env`;

  it("keys in .env ⇒ ok; dotEnv holds only the file", () => {
    const r = loadConfig(
      {},
      deps({ [ENV]: `RAZORPAY_KEY_ID=${KEY_ID}\nRAZORPAY_KEY_SECRET=${KEY_SECRET}\n` }),
    );
    if (!r.ok) throw new Error(r.error.code);
    const c = checkFirewallEnvFile(r.value.dotEnv);
    expect(c.ok && c.value.keyId).toBe(KEY_ID);
  });

  it("keys only in the shell ⇒ a clear error naming .env, never the values", () => {
    const r = loadConfig(SHELL, deps());
    if (!r.ok) throw new Error(r.error.code);
    expect(r.value.dotEnv).toEqual({});
    const c = checkFirewallEnvFile(r.value.dotEnv);
    expect(!c.ok && c.error.code).toBe("example.firewall_keys");
    expect(!c.ok && c.error.message).toMatch(/\.env/);
    expect(!c.ok && c.error.message).toMatch(/RAZORPAY_KEY_ID is not set/);
    expect(JSON.stringify(c)).not.toContain(KEY_SECRET);
  });

  it("a malformed secret in .env ⇒ refused without echoing it", () => {
    const c = checkFirewallEnvFile({ RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: "short!" });
    expect(!c.ok && c.error.code).toBe("example.firewall_keys");
    expect(JSON.stringify(c)).not.toContain("short!");
  });
});
