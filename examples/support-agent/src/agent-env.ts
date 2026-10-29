/**
 * The environment handed to the Claude Agent SDK process (T015, D-039). The SDK's `env` option REPLACES the
 * subprocess environment, and MCP servers the agent spawns (the firewall proxy, or the direct docker upstream)
 * inherit it — so this allowlist decides what the agent and its MCP child can see.
 *
 * Allowed:
 * - `PATH`, `HOME` (shell) — to find node / pnpm / docker and the Claude Code config dir;
 * - `ANTHROPIC_API_KEY` (shell or `.env`) — the agent's model access;
 * - the proxy's SHELL-only demo settings (`AGENT_ASF_SETTINGS`, shell only — the proxy ignores them in `.env`);
 * - docker client settings `DOCKER_*` from the proxy's `DOCKER_ENV_PASSTHROUGH` (shell only);
 * - `--target=direct` only: `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` (docker copies them into the upstream container
 *   by NAME; they never go on a command line). In firewall mode the proxy reads the keys from `<repo>/.env` itself.
 *
 * NEVER: `ASF_ADMIN_TOKEN`, `ASF_ADMIN_TOKEN_FILE`, `ASF_API_APPROVALS`, `TELEGRAM_*` — the agent must not be able
 * to approve its own refunds (D-036). `assertAgentEnvSafe` re-checks the result before it is used.
 */
import { err, ok, type Result } from "@asf/core";
import { DOCKER_ENV_PASSTHROUGH, type EnvLike, type TestKeys } from "@asf/proxy";
import type { Target } from "./mcp-target.js";

/** Proxy settings the human may set in the shell for a demo run; passed through to the proxy the agent spawns. */
export const AGENT_ASF_SETTINGS: readonly string[] = Object.freeze([
  "ASF_POLICY",
  "ASF_AUDIT_DB",
  "ASF_MONEY_CALL_TIMEOUT_MS",
  "ASF_VERIFY_WAIT_MS",
  "ASF_DEMO_DELAY_REFUND_MS",
  "ASF_DUPLICATE_WINDOW_MS",
]);

/** Names that must never reach the agent process (exact). */
export const FORBIDDEN_AGENT_ENV: readonly string[] = Object.freeze([
  "ASF_ADMIN_TOKEN",
  "ASF_ADMIN_TOKEN_FILE",
  "ASF_API_APPROVALS",
]);
/** Prefixes that must never reach the agent process. */
export const FORBIDDEN_AGENT_ENV_PREFIXES: readonly string[] = Object.freeze(["TELEGRAM_"]);

function nonEmpty(v: string | undefined): v is string {
  return typeof v === "string" && v !== "";
}

export function isForbiddenAgentEnv(name: string): boolean {
  const upper = name.toUpperCase();
  return (
    FORBIDDEN_AGENT_ENV.includes(upper) ||
    FORBIDDEN_AGENT_ENV_PREFIXES.some((p) => upper.startsWith(p))
  );
}

/** Build the agent env (see the module comment). `merged` = shell over `.env`; `shell` = the real shell only. */
export function buildAgentEnv(input: {
  readonly target: Target;
  readonly shell: EnvLike;
  readonly merged: EnvLike;
  readonly keys: TestKeys;
}): Result<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const name of ["PATH", "HOME"]) {
    const v = input.shell[name];
    if (nonEmpty(v)) out[name] = v;
  }
  const apiKey = input.merged["ANTHROPIC_API_KEY"];
  if (nonEmpty(apiKey)) out["ANTHROPIC_API_KEY"] = apiKey;
  for (const name of AGENT_ASF_SETTINGS) {
    const v = input.shell[name];
    if (nonEmpty(v)) out[name] = v;
  }
  for (const name of DOCKER_ENV_PASSTHROUGH) {
    const v = input.shell[name];
    if (nonEmpty(v)) out[name] = v;
  }
  if (input.target === "direct") {
    out["RAZORPAY_KEY_ID"] = input.keys.keyId;
    out["RAZORPAY_KEY_SECRET"] = input.keys.keySecret;
  }
  out["CLAUDE_AGENT_SDK_CLIENT_APP"] = "asf-support-agent/0.0.0";
  return assertAgentEnvSafe(out);
}

/** Final gate: no forbidden name, no live key in any value. Messages name variables, never values. */
export function assertAgentEnvSafe(env: Record<string, string>): Result<Record<string, string>> {
  for (const [name, value] of Object.entries(env)) {
    if (isForbiddenAgentEnv(name)) {
      return err("agent_env.forbidden", `refusing to pass ${name} to the agent`);
    }
    if (value.toLowerCase().includes("rzp_live_")) {
      return err("agent_env.live_key", `refusing to run: ${name} contains a Razorpay LIVE key`);
    }
  }
  return ok(env);
}
