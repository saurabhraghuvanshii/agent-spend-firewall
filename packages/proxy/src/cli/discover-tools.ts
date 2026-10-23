/**
 * `pnpm --filter @asf/proxy discover [--timeout <ms>] [--out <path>]` — list the Razorpay MCP server's tools and
 * write them to `docs/razorpay-tools.json` (T002).
 *
 * Upstream: the local Razorpay MCP server in a hardened Docker container over stdio (see `dockerRunArgs`:
 * `--network none --pull=never --read-only --cap-drop ALL --security-opt no-new-privileges --init --name
 * asf-discover-<hex>`). Image: `DEFAULT_RAZORPAY_MCP_IMAGE` (pinned by digest), overridable with
 * `ASF_RAZORPAY_MCP_IMAGE` from the SHELL environment only (a value in `.env` is ignored). Because of
 * `--pull=never` the image must already be present: `docker pull <image>` first (exit 1 with that hint otherwise).
 *
 * Keys: from the shell environment, else from `<repoRoot>/.env` (parsed, never printed; non-empty shell values
 * win). Only `rzp_test_` key ids are accepted, so the human's setup is validated, but the real keys are NEVER
 * passed to the container: it gets `DISCOVERY_PLACEHOLDER_KEYS` (tools/list needs no Razorpay call). Docker client
 * variables (`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, …) also come from the shell environment only.
 *
 * The container is always force-removed (`docker rm -f <name>`, bounded) after the run, including on timeout and
 * SIGINT/SIGTERM; a cleanup failure is reported as a warning and doesn't change the exit code.
 *
 * Exit codes: 0 written, 1 discovery/write failed (existing file untouched), 2 refused (keys, bad usage/config).
 * Everything printed from upstream goes through redaction (key values ⇒ `[REDACTED]`) and `escapeForTerminal`.
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { err, ok, type Result } from "@asf/core";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  assertNoSecrets,
  buildChildEnv,
  buildToolsFile,
  checkTestKeys,
  DEFAULT_DISCOVERY_TIMEOUT_MS,
  DEFAULT_RAZORPAY_MCP_IMAGE,
  DISCOVERY_PLACEHOLDER_KEYS,
  discoverTools,
  discoveryContainerName,
  dockerRmArgs,
  dockerRunArgs,
  errorText,
  listerFromClient,
  redactSecrets,
  renderToolsFile,
  validateImageRef,
  type ConnectLister,
  type EnvLike,
  type TestKeys,
} from "../tool-discovery.js";
import { escapeForTerminal } from "./audit-verify.js";

export const DEFAULT_TOOLS_OUT = "docs/razorpay-tools.json";
const MAX_STDERR_CHARS = 4000;
/** Upper bound for `docker image inspect` / `docker rm -f`. */
export const DOCKER_AUX_TIMEOUT_MS = 15_000;

export type DiscoverExitCode = 0 | 1 | 2;

export interface RunDiscoverResult {
  readonly exitCode: DiscoverExitCode;
  readonly output: string;
}

export interface UpstreamSpawn {
  readonly command: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}

export interface UpstreamHandle {
  readonly connect: ConnectLister;
  /** Child stderr captured so far (raw: caller must redact and escape). */
  readonly stderr: () => string;
}

export type ImageInspection =
  | { readonly kind: "present"; readonly digest: string | undefined }
  | { readonly kind: "missing" }
  | { readonly kind: "error"; readonly message: string };

export interface DiscoverDeps {
  readonly cwd: string;
  /** Contents of a file, or `undefined` if it doesn't exist. Used only for `<repoRoot>/.env`. */
  readonly readEnvFile: (path: string) => string | undefined;
  readonly isRepoRoot: (dir: string) => boolean;
  readonly baseChildEnv: () => Record<string, string>;
  readonly upstream: (spawn: UpstreamSpawn) => UpstreamHandle;
  /** Is the image present locally (we run with `--pull=never`), and its repo digest if known. */
  readonly inspectImage: (
    image: string,
    env: Readonly<Record<string, string>>,
  ) => Promise<ImageInspection>;
  /** `docker rm -f <name>`, bounded. "No such container" counts as success. Must not throw. */
  readonly removeContainer: (
    name: string,
    env: Readonly<Record<string, string>>,
  ) => Promise<Result<null>>;
  /** Random lowercase hex for the container name suffix. */
  readonly randomHex: () => string;
  readonly writeFileAtomic: (path: string, content: string) => void;
  readonly now: () => Date;
  /** External cancellation (SIGINT/SIGTERM). */
  readonly signal?: AbortSignal;
}

const esc = escapeForTerminal;
const USAGE =
  "usage: discover [--timeout <ms>] [--out <path>]   (keys: RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET; image: ASF_RAZORPAY_MCP_IMAGE in the shell env)";

type ParsedArgs =
  { ok: true; timeoutMs: number; out: string | undefined } | { ok: false; message: string };

function parseArgs(argv: readonly string[]): ParsedArgs {
  let timeoutMs = DEFAULT_DISCOVERY_TIMEOUT_MS;
  let out: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") continue; // pnpm may forward a literal separator
    let name: string | undefined;
    let value: string | undefined;
    if (a === "--timeout" || a === "--out") {
      name = a;
      value = argv[i + 1];
      i++;
    } else if (a !== undefined && (a.startsWith("--timeout=") || a.startsWith("--out="))) {
      const eq = a.indexOf("=");
      name = a.slice(0, eq);
      value = a.slice(eq + 1);
    } else {
      return { ok: false, message: `unknown argument: ${String(a)}` };
    }
    if (value === undefined || value === "")
      return { ok: false, message: `${name} requires a value` };
    if (name === "--timeout") {
      if (!/^[0-9]{1,7}$/.test(value))
        return { ok: false, message: "--timeout must be an integer (ms)" };
      const n = Number(value);
      if (n < 1000 || n > 600_000) {
        return { ok: false, message: "--timeout must be between 1000 and 600000 ms" };
      }
      timeoutMs = n;
    } else {
      out = value;
    }
  }
  return { ok: true, timeoutMs, out };
}

/** Repo root: walk up from `INIT_CWD` (where `pnpm` was invoked) or cwd to the dir with `pnpm-workspace.yaml`. */
export function findRepoRoot(
  start: string,
  isRepoRoot: (dir: string) => boolean,
): string | undefined {
  let dir = resolve(start);
  for (;;) {
    if (isRepoRoot(dir)) return dir;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/**
 * Merge `.env` values under the shell environment: a variable set in the shell wins, unless its value is the
 * empty string (`FOO= pnpm …`, or an exported-but-empty var), which is treated as unset so it can't blank out a
 * value from `.env`.
 */
export function mergeEnv(
  shell: EnvLike,
  fileContent: string | undefined,
): Record<string, string | undefined> {
  const merged: Record<string, string | undefined> = {};
  if (fileContent !== undefined) {
    for (const [k, v] of Object.entries(parseEnv(fileContent))) merged[k] = v;
  }
  for (const [k, v] of Object.entries(shell)) {
    if (v !== undefined && v !== "") merged[k] = v;
  }
  return merged;
}

export async function runDiscover(
  argv: readonly string[],
  shellEnv: EnvLike,
  deps: DiscoverDeps,
): Promise<RunDiscoverResult> {
  const state: RunState = { keys: undefined, container: undefined };
  let result: RunDiscoverResult;
  try {
    result = await discoverAndWrite(argv, shellEnv, deps, state);
  } catch (e: unknown) {
    result = {
      exitCode: 1,
      output: failure(`discovery failed unexpectedly: ${errorText(e)}`, state.keys, state.stderr),
    };
  }
  const c = state.container;
  if (c === undefined) return result;
  let warning: string | undefined;
  try {
    const removed = await deps.removeContainer(c.name, c.dockerEnv);
    if (!removed.ok) warning = removed.error.message;
  } catch (e: unknown) {
    warning = `container cleanup failed: ${errorText(e)}`;
  }
  if (warning === undefined) return result;
  return {
    exitCode: result.exitCode,
    output: `${result.output}\nwarning: ${esc(redact(warning, state.keys))} (remove it manually: docker rm -f ${c.name})`,
  };
}

interface RunState {
  keys: TestKeys | undefined;
  /** Set once `docker run` has been spawned: it must be cleaned up. */
  container: { name: string; dockerEnv: Readonly<Record<string, string>> } | undefined;
  stderr?: () => string;
}

async function discoverAndWrite(
  argv: readonly string[],
  shellEnv: EnvLike,
  deps: DiscoverDeps,
  state: RunState,
): Promise<RunDiscoverResult> {
  const args = parseArgs(argv);
  if (!args.ok) return { exitCode: 2, output: `error: ${esc(args.message)}\n${USAGE}` };

  const start = shellEnv["INIT_CWD"] || deps.cwd;
  const root = findRepoRoot(start, deps.isRepoRoot);
  if (root === undefined) {
    return { exitCode: 2, output: "error: cannot find the repo root (pnpm-workspace.yaml)" };
  }

  // Keys are validated on the merged env (shell + .env) so the human's real setup is checked, but the real values
  // are only used for redaction: the container gets placeholders.
  const env = mergeEnv(shellEnv, deps.readEnvFile(join(root, ".env")));
  const guard = checkTestKeys(env);
  if (!guard.ok) return { exitCode: 2, output: `error: ${esc(guard.error.message)}` };
  const keys = guard.value;
  state.keys = keys;

  // Image override and docker client config: shell env only, never `.env`.
  const image = validateImageRef(shellEnv["ASF_RAZORPAY_MCP_IMAGE"] || DEFAULT_RAZORPAY_MCP_IMAGE);
  if (!image.ok) return { exitCode: 2, output: `error: ${esc(image.error.message)}` };
  const name = discoveryContainerName(deps.randomHex());
  if (!name.ok) return { exitCode: 2, output: `error: ${esc(name.error.message)}` };

  const outPath = args.out === undefined ? join(root, DEFAULT_TOOLS_OUT) : resolve(root, args.out);
  const childEnv = buildChildEnv(deps.baseChildEnv(), shellEnv, DISCOVERY_PLACEHOLDER_KEYS);
  const dockerEnv = childEnvWithoutKeys(childEnv);

  const inspection = await deps.inspectImage(image.value, dockerEnv);
  if (inspection.kind === "missing") {
    return {
      exitCode: 1,
      output: [
        `error: docker image ${esc(image.value)} is not present locally; discovery runs with --pull=never`,
        `pull it first: docker pull ${esc(image.value)}`,
        "nothing written",
      ].join("\n"),
    };
  }
  if (inspection.kind === "error") {
    return { exitCode: 1, output: failure(inspection.message, keys, undefined) };
  }

  state.container = { name: name.value, dockerEnv };
  const upstream = deps.upstream({
    command: "docker",
    args: dockerRunArgs(image.value, name.value),
    env: childEnv,
  });
  state.stderr = upstream.stderr;

  const discovery = await discoverTools({
    connect: upstream.connect,
    timeoutMs: args.timeoutMs,
    ...(deps.signal === undefined ? {} : { signal: deps.signal }),
  });
  if (!discovery.ok) {
    return {
      exitCode: 1,
      output: failure(
        `${discovery.error.message} (${discovery.error.code})`,
        keys,
        upstream.stderr,
      ),
    };
  }

  const file = buildToolsFile({
    discovery: discovery.value,
    image: image.value,
    imageDigest: inspection.digest,
    discoveredAt: deps.now(),
  });
  const rendered = assertNoSecrets(renderToolsFile(file), keys);
  if (!rendered.ok)
    return { exitCode: 1, output: failure(rendered.error.message, keys, undefined) };

  deps.writeFileAtomic(outPath, rendered.value);
  const names = discovery.value.tools.map((t) => esc(t.name));
  const notes =
    shellEnv["ASF_RAZORPAY_MCP_IMAGE"] === undefined && env["ASF_RAZORPAY_MCP_IMAGE"] !== undefined
      ? [
          "note: ASF_RAZORPAY_MCP_IMAGE from .env is ignored (set it in the shell to override the image)",
        ]
      : [];
  return {
    exitCode: 0,
    output: [
      `OK: wrote ${String(names.length)} tools to ${esc(redact(outPath, keys))}`,
      `server: ${esc(redact(discovery.value.server.name, keys))} ${esc(redact(discovery.value.server.version, keys))}`,
      ...(inspection.digest === undefined
        ? []
        : [`image: ${esc(redact(inspection.digest, keys))}`]),
      `tools: ${names.join(", ")}`,
      ...notes,
    ].join("\n"),
  };
}

function redact(text: string, keys: TestKeys | undefined): string {
  return keys === undefined ? text : redactSecrets(text, keys);
}

function failure(
  message: string,
  keys: TestKeys | undefined,
  stderr: (() => string) | undefined,
): string {
  const lines = [`error: ${esc(redact(message, keys))}`, "nothing written"];
  const raw = stderr?.() ?? "";
  if (raw.trim() !== "") {
    const tail = raw.length > MAX_STDERR_CHARS ? raw.slice(-MAX_STDERR_CHARS) : raw;
    lines.push("upstream stderr (redacted):");
    for (const l of redact(tail, keys).split("\n")) {
      if (l !== "") lines.push(`  ${esc(l)}`);
    }
  }
  return lines.join("\n");
}

function childEnvWithoutKeys(env: Readonly<Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (!k.startsWith("RAZORPAY_")) out[k] = v;
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Real dependencies
// ---------------------------------------------------------------------------------------------------------------

/** Real upstream: MCP SDK client over stdio to `docker run …`. Only `tools/list` is exposed. */
export function dockerUpstream(spawn: UpstreamSpawn): UpstreamHandle {
  let stderrBuf = "";
  const transport = new StdioClientTransport({
    command: spawn.command,
    args: [...spawn.args],
    env: { ...spawn.env },
    stderr: "pipe",
  });
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    stderrBuf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (stderrBuf.length > MAX_STDERR_CHARS * 4) stderrBuf = stderrBuf.slice(-MAX_STDERR_CHARS * 2);
  });
  const client = new Client({ name: "asf-discover", version: "0.0.0" }, { capabilities: {} });

  const connect: ConnectLister = async (signal) => {
    const onAbort = (): void => {
      void transport.close().catch((e: unknown) => {
        stderrBuf += `\n[asf] closing transport after abort failed: ${errorText(e)}\n`;
      });
    };
    signal.addEventListener("abort", onAbort, { once: true });
    await client.connect(transport, { signal });
    const inner = listerFromClient(client, signal);
    return {
      listTools: (cursor) => inner.listTools(cursor),
      serverInfo: () => inner.serverInfo(),
      close: async () => {
        signal.removeEventListener("abort", onAbort);
        await inner.close();
      },
    };
  };
  return { connect, stderr: () => stderrBuf };
}

const REPO_DIGEST = /^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$/;

/** Parse `docker image inspect --format '{{json .RepoDigests}}'` output: the first well-formed repo digest. */
export function pickRepoDigest(stdout: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    return undefined; // provenance is optional: unparseable output just means "unknown digest"
  }
  if (!Array.isArray(parsed)) return undefined;
  for (const d of parsed) if (typeof d === "string" && REPO_DIGEST.test(d)) return d;
  return undefined;
}

function dockerInspectImage(
  image: string,
  env: Readonly<Record<string, string>>,
): Promise<ImageInspection> {
  return new Promise((done) => {
    execFile(
      "docker",
      ["image", "inspect", "--format", "{{json .RepoDigests}}", image],
      { env: { ...env }, timeout: DOCKER_AUX_TIMEOUT_MS },
      (error, stdout, stderr) => {
        if (error === null) return done({ kind: "present", digest: pickRepoDigest(stdout) });
        if (/no such image/i.test(stderr)) return done({ kind: "missing" });
        done({
          kind: "error",
          message: `docker image inspect failed (${error.killed ? "timed out" : `exit ${String(error.code)}`}); is docker running?`,
        });
      },
    );
  });
}

/** Bounded `docker rm -f`. Never throws; the message names the container but never includes docker's stderr. */
export function dockerRemoveContainer(
  name: string,
  env: Readonly<Record<string, string>>,
): Promise<Result<null>> {
  return new Promise((done) => {
    let args: string[];
    try {
      args = dockerRmArgs(name);
    } catch (e: unknown) {
      done(err("discover.cleanup_failed", `container cleanup refused: ${errorText(e)}`));
      return;
    }
    execFile(
      "docker",
      args,
      { env: { ...env }, timeout: DOCKER_AUX_TIMEOUT_MS },
      (error, _stdout, stderr) => {
        // Already gone (`--rm` won the race) is success.
        if (error === null || /no such container|already in progress/i.test(stderr)) {
          return done(ok(null));
        }
        done(
          err(
            "discover.cleanup_failed",
            `docker rm -f ${name} failed (${error.killed ? "timed out" : `exit ${String(error.code)}`})`,
          ),
        );
      },
    );
  });
}

/** Write to a temp file in the same directory, then rename, so a failed write never leaves a half file. */
export function writeFileAtomic(path: string, content: string): void {
  const tmp = `${path}.${String(process.pid)}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync(tmp, content, { encoding: "utf8", flag: "wx" });
    renameSync(tmp, path);
  } catch (e: unknown) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

export const realDiscoverDeps: DiscoverDeps = {
  cwd: process.cwd(),
  readEnvFile: (path) => (existsSync(path) ? readFileSync(path, "utf8") : undefined),
  isRepoRoot: (dir) => existsSync(join(dir, "pnpm-workspace.yaml")),
  baseChildEnv: getDefaultEnvironment,
  upstream: dockerUpstream,
  inspectImage: dockerInspectImage,
  removeContainer: dockerRemoveContainer,
  randomHex: () => randomBytes(8).toString("hex"),
  writeFileAtomic,
  now: () => new Date(),
};

function isMain(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch (e: unknown) {
    if (e instanceof Error && "code" in e && e.code === "ENOENT") return false;
    throw e;
  }
}

if (isMain()) {
  // SIGINT/SIGTERM abort discovery; runDiscover then still force-removes the container before we exit.
  const controller = new AbortController();
  const onSignal = (): void => {
    controller.abort();
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  const { exitCode, output } = await runDiscover(process.argv.slice(2), process.env, {
    ...realDiscoverDeps,
    signal: controller.signal,
  });
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  (exitCode === 0 ? process.stdout : process.stderr).write(`${output}\n`);
  process.exitCode = exitCode;
}
