/**
 * Config for the demo support agent, seed and verify-live scripts (T015).
 *
 * Same rules as the proxy, through the proxy's own helpers (no duplicated logic):
 * - repo root = nearest ancestor with `pnpm-workspace.yaml` (`findRepoRoot`);
 * - `<repo>/.env` is merged UNDER the shell env (`mergeEnv`; shell wins). Values are never printed;
 * - Razorpay TEST keys only (`checkTestKeys`): any `rzp_live_` value anywhere ⇒ refused (the CLIs exit 2);
 * - the Razorpay MCP image override `ASF_RAZORPAY_MCP_IMAGE` comes from the SHELL only (like the proxy).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, type Result } from "@asf/core";
import {
  DEFAULT_RAZORPAY_MCP_IMAGE,
  checkTestKeys,
  findRepoRoot,
  mergeEnv,
  validateImageRef,
  type EnvLike,
  type TestKeys,
} from "@asf/proxy";

export interface ExampleConfig {
  readonly repoRoot: string;
  /** SECRET: never print. TEST keys (`rzp_test_`), validated. */
  readonly keys: TestKeys;
  /** The real shell environment (never `.env`). */
  readonly shell: EnvLike;
  /** Shell over `.env`. SECRET values inside: never print. */
  readonly merged: EnvLike;
  /** `<repo>/.env` alone (what the firewall proxy the agent spawns reads). SECRET values inside: never print. */
  readonly dotEnv: EnvLike;
  /** Razorpay MCP docker image (pinned default, or the SHELL override). */
  readonly image: string;
}

export interface ConfigDeps {
  readonly cwd: string;
  readonly moduleDir: string;
  readonly isRepoRoot: (dir: string) => boolean;
  /** File contents, or `undefined` if it doesn't exist. */
  readonly readFile: (path: string) => string | undefined;
}

export const realConfigDeps: ConfigDeps = {
  cwd: process.cwd(),
  moduleDir: dirname(fileURLToPath(import.meta.url)),
  isRepoRoot: (dir) => existsSync(join(dir, "pnpm-workspace.yaml")),
  readFile: (path) => (existsSync(path) ? readFileSync(path, "utf8") : undefined),
};

/** Exit code for a refused configuration (live key, missing key, bad setting) — same as the proxy. */
export const EXIT_REFUSED = 2;

export function loadConfig(shellEnv: EnvLike, deps: ConfigDeps): Result<ExampleConfig> {
  const starts = [shellEnv["INIT_CWD"], deps.cwd, deps.moduleDir].filter(
    (s): s is string => typeof s === "string" && s !== "",
  );
  let repoRoot: string | undefined;
  for (const s of starts) {
    repoRoot = findRepoRoot(s, deps.isRepoRoot);
    if (repoRoot !== undefined) break;
  }
  if (repoRoot === undefined) {
    return err("example.no_repo_root", "cannot find the repo root (pnpm-workspace.yaml)");
  }
  const envFile = deps.readFile(join(repoRoot, ".env"));
  const merged = mergeEnv(shellEnv, envFile);
  const dotEnv = mergeEnv({}, envFile);
  // Refuses any rzp_live_ value in ANY variable (shell or .env), then requires valid test keys.
  const keys = checkTestKeys(merged);
  if (!keys.ok) return keys;
  const override = shellEnv["ASF_RAZORPAY_MCP_IMAGE"];
  const image = validateImageRef(
    override === undefined || override === "" ? DEFAULT_RAZORPAY_MCP_IMAGE : override,
  );
  if (!image.ok) return image;
  return ok({ repoRoot, keys: keys.value, shell: shellEnv, merged, dotEnv, image: image.value });
}

/**
 * `--target=firewall` pre-check: the agent's env never carries the Razorpay keys (`agent-env.ts`), so the proxy it
 * spawns can only read them from `<repo>/.env`. Keys only in the shell would let this script start and then fail
 * inside the MCP child, where the error lands in Claude Code's MCP logs. Same checks as the proxy
 * (`checkTestKeys`); the message names variables, never values.
 */
export function checkFirewallEnvFile(dotEnv: EnvLike): Result<TestKeys> {
  const r = checkTestKeys(dotEnv);
  if (r.ok) return r;
  return err(
    "example.firewall_keys",
    `--target=firewall needs Razorpay TEST keys (RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET) in the repo's .env: the firewall proxy reads them there, not from your shell (${r.error.message})`,
  );
}

/** `loadConfig` for a CLI: print the (secret-free) reason and exit 2 on refusal. */
export function loadConfigOrExit(): ExampleConfig {
  const c = loadConfig(process.env, realConfigDeps);
  if (!c.ok) {
    process.stderr.write(`error: ${c.error.message}\n`);
    process.exit(EXIT_REFUSED);
  }
  return c.value;
}
