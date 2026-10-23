/**
 * `pnpm -s --filter @asf/proxy start` — run the Agent Spend Firewall as an MCP server on stdio (T003).
 *
 * STDOUT IS THE MCP CHANNEL: everything else (logs, warnings) goes to stderr, escaped and redacted.
 *
 * Config (shell env wins; `<repoRoot>/.env` is parsed at runtime and never printed):
 * - `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` — TEST keys only (`rzp_test_`); any `rzp_live_` value anywhere ⇒ exit 2.
 *   Passed to the upstream container through its environment by NAME (`-e RAZORPAY_KEY_ID`), never in argv.
 * - `ASF_UPSTREAM_TIMEOUT_MS` — per-call upstream timeout, 1000..600000, default 30000 (T010 refines money tools).
 * - `ASF_RAZORPAY_MCP_IMAGE` — image override, SHELL env only (like discovery); default is the pinned digest.
 * - Docker client variables (`DOCKER_HOST`, …) — shell env only.
 *
 * Startup never waits for upstream: the stdio server starts at once and connects to upstream in the background, so
 * the MCP client's initialize doesn't time out on a slow container start. If upstream is down, `tools/list` serves
 * the committed `docs/razorpay-tools.json` snapshot and calls fail with `upstream_unavailable` (see server.ts).
 *
 * Incoming agent messages are capped at `AGENT_MAX_MESSAGE_BYTES` (SDK stdio `maxBufferSize`): a larger message
 * closes the agent channel and the proxy exits.
 *
 * Exit codes: 0 clean shutdown, 1 fatal runtime error, 2 refused (keys / config).
 */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, type Result } from "@asf/core";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createProxyServer, type ProxyServer } from "../server.js";
import {
  buildChildEnv,
  checkTestKeys,
  DEFAULT_RAZORPAY_MCP_IMAGE,
  errorText,
  redactSecrets,
  toolsFileSchema,
  validateImageRef,
  type DiscoveredTool,
  type EnvLike,
  type TestKeys,
} from "../tool-discovery.js";
import {
  DEFAULT_UPSTREAM_TIMEOUT_MS,
  dockerUpstreamFactory,
  Upstream,
  type Logger,
  type Redactor,
  type UpstreamTransportFactory,
} from "../upstream.js";
import { escapeForTerminal } from "./audit-verify.js";
import { DEFAULT_TOOLS_OUT, findRepoRoot, mergeEnv } from "./discover-tools.js";

export const MIN_UPSTREAM_TIMEOUT_MS = 1_000;
export const MAX_UPSTREAM_TIMEOUT_MS = 600_000;
/** Upper bound for graceful shutdown (closing upstream + `docker rm -f`) before a forced exit. */
export const SHUTDOWN_TIMEOUT_MS = 20_000;
/**
 * Max bytes of one buffered (not yet newline-terminated) agent message on stdio. Tool arguments are small; the SDK
 * default is 10 MiB. Exceeding it makes the SDK drop the buffer and close the agent channel.
 */
export const AGENT_MAX_MESSAGE_BYTES = 1024 * 1024;

export interface ProxyConfig {
  readonly repoRoot: string;
  readonly keys: TestKeys;
  readonly image: string;
  readonly callTimeoutMs: number;
  /** Child env for `docker run`: SDK default env + docker client vars (shell) + the two Razorpay keys. */
  readonly childEnv: Readonly<Record<string, string>>;
  /** Same without the Razorpay keys, for `docker rm -f`. */
  readonly dockerEnv: Readonly<Record<string, string>>;
  readonly cachedTools: readonly DiscoveredTool[];
  /** Non-fatal notes for the log (secret-free). */
  readonly notes: readonly string[];
}

export interface ConfigDeps {
  readonly cwd: string;
  /** Directory of this module, a fallback start for the repo-root search (MCP clients may spawn from anywhere). */
  readonly moduleDir: string;
  readonly isRepoRoot: (dir: string) => boolean;
  /** Contents of a file, or `undefined` if it doesn't exist. */
  readonly readFile: (path: string) => string | undefined;
  readonly baseChildEnv: () => Record<string, string>;
}

export function parseTimeoutMs(raw: string | undefined): Result<number> {
  if (raw === undefined || raw === "") return ok(DEFAULT_UPSTREAM_TIMEOUT_MS);
  if (!/^[0-9]{1,7}$/.test(raw)) {
    return err(
      "proxy.bad_timeout",
      "ASF_UPSTREAM_TIMEOUT_MS must be an integer number of milliseconds",
    );
  }
  const n = Number(raw);
  if (n < MIN_UPSTREAM_TIMEOUT_MS || n > MAX_UPSTREAM_TIMEOUT_MS) {
    return err(
      "proxy.bad_timeout",
      `ASF_UPSTREAM_TIMEOUT_MS must be between ${String(MIN_UPSTREAM_TIMEOUT_MS)} and ${String(MAX_UPSTREAM_TIMEOUT_MS)}`,
    );
  }
  return ok(n);
}

/** Parse the committed tool snapshot. Problems are notes, not errors: the cache is only a fallback for listing. */
export function loadCachedTools(content: string | undefined): {
  tools: readonly DiscoveredTool[];
  note?: string;
} {
  if (content === undefined)
    return { tools: [], note: `no cached tool list at ${DEFAULT_TOOLS_OUT}` };
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return { tools: [], note: `${DEFAULT_TOOLS_OUT} is not valid JSON; no cached tool list` };
  }
  const parsed = toolsFileSchema.safeParse(json);
  if (!parsed.success)
    return { tools: [], note: `${DEFAULT_TOOLS_OUT} is malformed; no cached tool list` };
  return {
    tools: parsed.data.tools.map((t) =>
      t.annotations === undefined
        ? { name: t.name, description: t.description, inputSchema: t.inputSchema }
        : {
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
            annotations: t.annotations,
          },
    ),
  };
}

export function resolveProxyConfig(shellEnv: EnvLike, deps: ConfigDeps): Result<ProxyConfig> {
  const starts = [shellEnv["INIT_CWD"], deps.cwd, deps.moduleDir].filter(
    (s): s is string => typeof s === "string" && s !== "",
  );
  let repoRoot: string | undefined;
  for (const s of starts) {
    repoRoot = findRepoRoot(s, deps.isRepoRoot);
    if (repoRoot !== undefined) break;
  }
  if (repoRoot === undefined) {
    return err("proxy.no_repo_root", "cannot find the repo root (pnpm-workspace.yaml)");
  }

  const env = mergeEnv(shellEnv, deps.readFile(join(repoRoot, ".env")));
  const guard = checkTestKeys(env);
  if (!guard.ok) return guard;

  const timeout = parseTimeoutMs(env["ASF_UPSTREAM_TIMEOUT_MS"]);
  if (!timeout.ok) return timeout;

  // Image override and docker client config: shell env only, never `.env`.
  const image = validateImageRef(shellEnv["ASF_RAZORPAY_MCP_IMAGE"] || DEFAULT_RAZORPAY_MCP_IMAGE);
  if (!image.ok) return image;

  const notes: string[] = [];
  if (!shellEnv["ASF_RAZORPAY_MCP_IMAGE"] && env["ASF_RAZORPAY_MCP_IMAGE"] !== undefined) {
    notes.push(
      "ASF_RAZORPAY_MCP_IMAGE from .env is ignored (set it in the shell to override the image)",
    );
  }
  const cache = loadCachedTools(deps.readFile(join(repoRoot, DEFAULT_TOOLS_OUT)));
  if (cache.note !== undefined) notes.push(cache.note);

  const childEnv = buildChildEnv(deps.baseChildEnv(), shellEnv, guard.value);
  const dockerEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(childEnv)) if (!k.startsWith("RAZORPAY_")) dockerEnv[k] = v;

  return ok({
    repoRoot,
    keys: guard.value,
    image: image.value,
    callTimeoutMs: timeout.value,
    childEnv,
    dockerEnv,
    cachedTools: cache.tools,
    notes,
  });
}

/** Logger writing one escaped line per message to the given sink (stderr in production). */
export function stderrLogger(write: (s: string) => void): Logger {
  return (line) => {
    for (const l of line.split("\n")) write(`[asf-proxy] ${escapeForTerminal(l)}\n`);
  };
}

export interface RunningProxy {
  readonly proxy: ProxyServer;
  readonly upstream: Upstream;
  /** Close the agent channel and upstream (incl. `docker rm -f`). Idempotent. */
  shutdown(): Promise<void>;
}

export interface StartProxyOptions {
  readonly config: ProxyConfig;
  readonly logger: Logger;
  /** Injected for tests; default: hardened docker. */
  readonly factory?: UpstreamTransportFactory;
}

/** Build upstream + server (not yet connected to the agent). Kicks off the upstream connection in the background. */
export function startProxy(opts: StartProxyOptions): RunningProxy {
  const { config, logger } = opts;
  const redact: Redactor = (s) => redactSecrets(s, config.keys);
  const factory =
    opts.factory ??
    dockerUpstreamFactory({
      image: config.image,
      childEnv: config.childEnv,
      dockerEnv: config.dockerEnv,
      randomHex: () => randomBytes(8).toString("hex"),
      redact,
      logger,
    });
  const upstream = new Upstream({
    factory,
    logger,
    redact,
    callTimeoutMs: config.callTimeoutMs,
    clientInfo: { name: "agent-spend-firewall", version: "0.0.0" },
  });
  const proxy = createProxyServer({
    upstream,
    cachedTools: config.cachedTools,
    callTimeoutMs: config.callTimeoutMs,
    logger,
    redact,
  });
  upstream.onLateResponse((e) => {
    // Metadata only — the response body is never logged (T010 reconciles money calls from this event).
    logger(
      `late upstream response: id ${escapeForTerminal(String(e.requestId))}, tool ${escapeForTerminal(e.tool ?? "(untracked)")}, ${e.responseType}, generation ${String(e.generation)}`,
    );
  });
  void upstream.connect().then((r) => {
    if (!r.ok) logger(`upstream not available yet: ${redact(r.error.message)}`);
  });
  let shuttingDown: Promise<void> | undefined;
  return {
    proxy,
    upstream,
    shutdown: () => {
      shuttingDown ??= (async () => {
        try {
          await proxy.close();
        } catch (e: unknown) {
          logger(`closing the agent channel failed: ${redact(errorText(e))}`);
        }
        await upstream.close();
      })();
      return shuttingDown;
    },
  };
}

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

async function main(): Promise<void> {
  const logger = stderrLogger((s) => process.stderr.write(s));
  const config = resolveProxyConfig(process.env, {
    cwd: process.cwd(),
    moduleDir: dirname(fileURLToPath(import.meta.url)),
    isRepoRoot: (dir) => existsSync(join(dir, "pnpm-workspace.yaml")),
    readFile: (path) => (existsSync(path) ? readFileSync(path, "utf8") : undefined),
    baseChildEnv: getDefaultEnvironment,
  });
  if (!config.ok) {
    logger(`error: ${config.error.message}`);
    process.exitCode = 2;
    return;
  }
  for (const n of config.value.notes) logger(`note: ${n}`);
  logger(
    `upstream image ${config.value.image}; call timeout ${String(config.value.callTimeoutMs)} ms`,
  );

  const running = startProxy({ config: config.value, logger });
  const redact: Redactor = (s) => redactSecrets(s, config.value.keys);

  let exiting = false;
  const exit = (why: string, code: 0 | 1): void => {
    if (exiting) return;
    exiting = true;
    logger(`shutting down (${why})`);
    const force = setTimeout(() => {
      logger("shutdown timed out; exiting (check: docker ps --filter name=asf-upstream-)");
      process.exit(code === 0 ? 1 : code);
    }, SHUTDOWN_TIMEOUT_MS);
    force.unref();
    void running.shutdown().finally(() => {
      process.exit(code);
    });
  };
  process.once("SIGINT", () => {
    exit("SIGINT", 0);
  });
  process.once("SIGTERM", () => {
    exit("SIGTERM", 0);
  });
  process.once("SIGHUP", () => {
    exit("SIGHUP", 0);
  });
  process.stdin.once("end", () => {
    exit("stdin closed", 0);
  });
  process.on("unhandledRejection", (reason: unknown) => {
    // Logged, not fatal: one failed request must not take the firewall down.
    logger(`unhandled rejection: ${redact(errorText(reason))}`);
  });
  process.on("uncaughtException", (e: Error) => {
    logger(`fatal: ${redact(errorText(e))}`);
    exit("uncaught exception", 1);
  });

  running.proxy.server.onclose = () => {
    exit("agent channel closed", 0);
  };
  await running.proxy.connect(
    new StdioServerTransport(process.stdin, process.stdout, {
      maxBufferSize: AGENT_MAX_MESSAGE_BYTES,
    }),
  );
  logger("listening on stdio");
}

if (isMain()) {
  await main();
}
