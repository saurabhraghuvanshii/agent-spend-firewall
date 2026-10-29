import { describe, expect, it } from "vitest";
import {
  AGENT_ASF_SETTINGS,
  assertAgentEnvSafe,
  buildAgentEnv,
  isForbiddenAgentEnv,
} from "./agent-env.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const SHELL = {
  PATH: "/usr/bin",
  HOME: "/home/u",
  ASF_ADMIN_TOKEN: "a".repeat(40),
  ASF_ADMIN_TOKEN_FILE: "/secret/token",
  ASF_API_APPROVALS: "1",
  TELEGRAM_BOT_TOKEN: "123456:abc",
  TELEGRAM_CHAT_ID: "42",
  ASF_POLICY: "policies/default.ts",
  ASF_AUDIT_DB: "data/demo.db",
  ASF_MONEY_CALL_TIMEOUT_MS: "5000",
  ASF_VERIFY_WAIT_MS: "15000",
  ASF_DEMO_DELAY_REFUND_MS: "15000",
  ASF_DUPLICATE_WINDOW_MS: "600000",
  ASF_API_PORT: "8787",
  DOCKER_HOST: "unix:///var/run/docker.sock",
  RAZORPAY_KEY_ID: KEYS.keyId,
  RAZORPAY_KEY_SECRET: KEYS.keySecret,
  AWS_SECRET_ACCESS_KEY: "nope",
  GITHUB_TOKEN: "nope",
};
const MERGED = { ...SHELL, ANTHROPIC_API_KEY: "sk-ant-test" };

function build(target: "firewall" | "direct") {
  const r = buildAgentEnv({ target, shell: SHELL, merged: MERGED, keys: KEYS });
  if (!r.ok) throw new Error(r.error.message);
  return r.value;
}

describe("buildAgentEnv", () => {
  it("firewall: exactly the allowlist; no Razorpay keys (the proxy reads .env itself)", () => {
    const env = build("firewall");
    expect(Object.keys(env).sort()).toEqual(
      [
        "PATH",
        "HOME",
        "ANTHROPIC_API_KEY",
        ...AGENT_ASF_SETTINGS,
        "DOCKER_HOST",
        "CLAUDE_AGENT_SDK_CLIENT_APP",
      ].sort(),
    );
    expect(env["RAZORPAY_KEY_ID"]).toBeUndefined();
  });

  it("direct: adds the two Razorpay keys", () => {
    const env = build("direct");
    expect(env["RAZORPAY_KEY_ID"]).toBe(KEYS.keyId);
    expect(env["RAZORPAY_KEY_SECRET"]).toBe(KEYS.keySecret);
  });

  it.each(["firewall", "direct"] as const)(
    "%s: NEVER the admin token, token file, API approvals, Telegram, or unrelated secrets",
    (target) => {
      const env = build(target);
      for (const k of [
        "ASF_ADMIN_TOKEN",
        "ASF_ADMIN_TOKEN_FILE",
        "ASF_API_APPROVALS",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "ASF_API_PORT",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
      ]) {
        expect(env[k]).toBeUndefined();
      }
      expect(JSON.stringify(env)).not.toContain("a".repeat(40));
    },
  );

  it("ASF_* settings come from the shell only (not .env)", () => {
    const r = buildAgentEnv({
      target: "firewall",
      shell: { PATH: "/usr/bin" },
      merged: { PATH: "/usr/bin", ASF_DEMO_DELAY_REFUND_MS: "15000", ASF_POLICY: "x.ts" },
      keys: KEYS,
    });
    expect(r.ok && r.value["ASF_DEMO_DELAY_REFUND_MS"]).toBeUndefined();
    expect(r.ok && r.value["ASF_POLICY"]).toBeUndefined();
  });

  it("a live key in any passed value is refused", () => {
    const r = buildAgentEnv({
      target: "firewall",
      shell: { PATH: "/usr/bin", ASF_POLICY: "rzp_live_x" },
      merged: {},
      keys: KEYS,
    });
    expect(r.ok === false && r.error.code).toBe("agent_env.live_key");
  });
});

describe("assertAgentEnvSafe / isForbiddenAgentEnv", () => {
  it("refuses forbidden names in any case", () => {
    for (const n of [
      "ASF_ADMIN_TOKEN",
      "asf_admin_token",
      "ASF_ADMIN_TOKEN_FILE",
      "ASF_API_APPROVALS",
      "TELEGRAM_X",
      "telegram_bot_token",
    ]) {
      expect(isForbiddenAgentEnv(n)).toBe(true);
      expect(assertAgentEnvSafe({ [n]: "v" }).ok).toBe(false);
    }
    expect(isForbiddenAgentEnv("ASF_POLICY")).toBe(false);
    expect(assertAgentEnvSafe({ PATH: "/bin" }).ok).toBe(true);
  });
});
