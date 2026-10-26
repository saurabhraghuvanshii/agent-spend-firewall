/**
 * `pnpm -s --filter @asf/proxy start` — run the Agent Spend Firewall as an MCP server on stdio (T003).
 *
 * STDOUT IS THE MCP CHANNEL: everything else (logs, warnings) goes to stderr, escaped and redacted.
 *
 * Config (shell env wins; `<repoRoot>/.env` is parsed at runtime and never printed):
 * - `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` — TEST keys only (`rzp_test_`); any `rzp_live_` value anywhere ⇒ exit 2.
 *   Passed to the upstream container through its environment by NAME (`-e RAZORPAY_KEY_ID`), never in argv.
 * - `ASF_UPSTREAM_TIMEOUT_MS` — per-call upstream timeout, 1000..600000, default 30000 (T010 refines money tools).
 * - `ASF_POLICY` — SHELL env only: policy file inside the repo (default `policies/default.ts`); must compile and
 *   default to "deny". A value only in `.env` is ignored (stderr note).
 * - `ASF_AUDIT_DB` — SHELL env only: audit SQLite file, default `data/audit.db`. Must resolve inside `<repo>/data/`
 *   (lexically, and by the realpath of its parent directory; the file itself must not be a symlink) ⇒ else exit 2.
 *   `<repo>/data/` is created if missing; other parent directories must already exist. A value only in `.env` is
 *   ignored (stderr note).
 * - `ASF_LOCK_WAIT_MS` — max wait for the money-path locks, 1..60000, default 5000.
 * - `ASF_RAZORPAY_MCP_IMAGE` — image override, SHELL env only (like discovery); default is the pinned digest.
 *
 * Why shell-only: the policy decides what money moves and the audit DB is the evidence trail; a `.env` file is
 * easier to tamper with unnoticed (and is often copied around) than the operator's shell / MCP client config.
 *
 * At startup the proxy logs (stderr) the policy's repo-relative path + SHA-256 of its file contents (the ENTRY file
 * only, not the modules it imports; computed just before the import, so it identifies what was about to be loaded,
 * not a guarantee against a concurrent edit), and the audit store's record count + head hash; it warns loudly when the audit DB was newly created (empty history means
 * duplicate / velocity limits start from zero) or its hash chain does not verify. A chain that does not verify does
 * NOT stop startup, but the money pipeline starts degraded: every money call is denied `audit_unavailable` (read
 * tools keep working). Dangling attempts (no outcome) alone don't degrade it. An unreadable DB still exits 2.
 * - Docker client variables (`DOCKER_HOST`, …) — shell env only.
 *
 * Startup never waits for upstream: the stdio server starts at once and connects to upstream in the background, so
 * the MCP client's initialize doesn't time out on a slow container start. If upstream is down, `tools/list` serves
 * the committed `docs/razorpay-tools.json` snapshot and calls fail with `upstream_unavailable` (see server.ts).
 *
 * Incoming agent messages are capped at `AGENT_MAX_MESSAGE_BYTES` (SDK stdio `maxBufferSize`): a larger message
 * closes the agent channel and the proxy exits.
 *
 * The policy is loaded and the audit store opened BEFORE serving: if either fails the proxy exits 2 (never serves
 * money tools without a policy and an audit log).
 *
 * Exit codes: 0 clean shutdown, 1 fatal runtime error, 2 refused (keys / config / policy / audit store).
 */
import { randomBytes } from "node:crypto";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, type CompiledPolicy, type Result } from "@asf/core";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createInMemoryApprovalStub, type ApprovalPort } from "../approval-port.js";
import { openAuditStore, type AuditStore } from "../audit-store.js";
import { systemClock, systemTimer } from "../context-adapters.js";
import {
  createFirewallInterceptor,
  createMoneyPipeline,
  DEFAULT_LOCK_WAIT_MS,
  type MoneyPipeline,
} from "../interceptor.js";
import { loadPolicy, resolvePolicyPath } from "../policy-loader.js";
import { redactSensitiveResult } from "../result-redaction.js";
import { advertiseTool } from "../schema-rewrite.js";
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
export const DEFAULT_AUDIT_DB = "data/audit.db";
/** Repo-relative directory the audit DB must live in. */
export const AUDIT_DB_DIR = "data";
/** Settings read from the SHELL environment only (a `.env` value is ignored with a note). */
export const SHELL_ONLY_SETTINGS = [
  "ASF_RAZORPAY_MCP_IMAGE",
  "ASF_POLICY",
  "ASF_AUDIT_DB",
] as const;
export const MIN_LOCK_WAIT_MS = 1;
export const MAX_LOCK_WAIT_MS_CONFIG = 60_000;

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
  /** Raw shell `ASF_POLICY` (resolved and confined by `loadPolicy`); `undefined` ⇒ `policies/default.ts`. */
  readonly policyPath: string | undefined;
  /** Absolute audit DB path, lexically inside `<repoRoot>/data/` (realpath-confined again by `openFirewall`). */
  readonly auditDbPath: string;
  readonly lockWaitMs: number;
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

export function parseLockWaitMs(raw: string | undefined): Result<number> {
  if (raw === undefined || raw === "") return ok(DEFAULT_LOCK_WAIT_MS);
  if (!/^[0-9]{1,6}$/.test(raw)) {
    return err("proxy.bad_lock_wait", "ASF_LOCK_WAIT_MS must be an integer number of milliseconds");
  }
  const n = Number(raw);
  if (n < MIN_LOCK_WAIT_MS || n > MAX_LOCK_WAIT_MS_CONFIG) {
    return err(
      "proxy.bad_lock_wait",
      `ASF_LOCK_WAIT_MS must be between ${String(MIN_LOCK_WAIT_MS)} and ${String(MAX_LOCK_WAIT_MS_CONFIG)}`,
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
  const lockWait = parseLockWaitMs(env["ASF_LOCK_WAIT_MS"]);
  if (!lockWait.ok) return lockWait;
  // Policy, audit DB, image override and docker client config: shell env only, never `.env`.
  const shellValue = (name: string): string | undefined => {
    const v = shellEnv[name];
    return v === undefined || v === "" ? undefined : v;
  };
  const notes: string[] = [];
  for (const name of SHELL_ONLY_SETTINGS) {
    const fromFile = env[name];
    if (shellValue(name) === undefined && fromFile !== undefined && fromFile !== "") {
      notes.push(`${name} from .env is ignored (set it in the shell environment to use it)`);
    }
  }

  const dbSetting = shellValue("ASF_AUDIT_DB") ?? DEFAULT_AUDIT_DB;
  if (dbSetting.includes("\0") || dbSetting === ":memory:") {
    return err("proxy.bad_audit_db", "ASF_AUDIT_DB must be a file path");
  }
  const auditDbPath = isAbsolute(dbSetting) ? resolve(dbSetting) : resolve(repoRoot, dbSetting);
  if (!isStrictlyInside(join(repoRoot, AUDIT_DB_DIR), auditDbPath)) {
    return err("proxy.bad_audit_db", `ASF_AUDIT_DB must be a file inside <repo>/${AUDIT_DB_DIR}/`);
  }
  const rawPolicy = shellValue("ASF_POLICY");

  const image = validateImageRef(
    shellValue("ASF_RAZORPAY_MCP_IMAGE") ?? DEFAULT_RAZORPAY_MCP_IMAGE,
  );
  if (!image.ok) return image;

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
    policyPath: rawPolicy,
    auditDbPath,
    lockWaitMs: lockWait.value,
    notes,
  });
}

/** True iff `child` is `dir` itself (when `allowEqual`) or strictly below it. Both absolute, normalised. */
function isStrictlyInside(dir: string, child: string, allowEqual = false): boolean {
  const rel = relative(dir, child);
  if (rel === "") return allowEqual;
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/** What the money pipeline needs from startup: a compiled deny-by-default policy and a writable audit store. */
export interface Firewall {
  readonly policy: CompiledPolicy;
  readonly store: AuditStore;
}

/** Startup facts logged to stderr so an operator can see WHICH policy and WHICH audit log are in force. */
export interface FirewallReport {
  /** Policy path relative to the (real) repo root, `/`-separated. */
  readonly policyRelPath: string;
  /** Lowercase hex SHA-256 of the policy file's bytes (read just before it was imported). */
  readonly policySha256: string;
  /** Real path of the audit DB. */
  readonly auditDbPath: string;
  /** True iff the audit DB file did not exist and was created by this start. */
  readonly auditDbCreated: boolean;
  /** `verify()` of the audit chain at startup. */
  readonly audit:
    | { readonly ok: true; readonly count: number; readonly headHash: string }
    | { readonly ok: false; readonly brokenAtSeq: number; readonly reason: string };
}

export interface OpenedFirewall extends Firewall {
  readonly report: FirewallReport;
}

/**
 * Confine the audit DB to `<repo>/data/` by REAL path: `<realRepo>/data` is created if missing (and must be a
 * directory), the DB's parent directory must exist and its realpath must be `<realRepo>/data` or below, and an
 * existing DB file must be a regular file (not a symlink). Returns the real DB path and whether it already existed.
 */
export function confineAuditDb(
  auditDbPath: string,
  repoRoot: string,
): Result<{ path: string; existed: boolean }> {
  const outside = err<{ path: string; existed: boolean }>(
    "proxy.bad_audit_db",
    `ASF_AUDIT_DB must be a file inside <repo>/${AUDIT_DB_DIR}/`,
  );
  if (!isStrictlyInside(join(repoRoot, AUDIT_DB_DIR), auditDbPath)) return outside;
  try {
    const realRoot = realpathSync(repoRoot);
    const dataDir = join(realRoot, AUDIT_DB_DIR);
    if (!existsSync(dataDir)) mkdirSync(dataDir);
    if (!statSync(dataDir).isDirectory()) return outside;
    const rel = relative(repoRoot, auditDbPath);
    const parent = dirname(join(realRoot, rel));
    if (!existsSync(parent)) {
      return err("proxy.bad_audit_db", "the ASF_AUDIT_DB parent directory does not exist");
    }
    const realParent = realpathSync(parent);
    if (!isStrictlyInside(dataDir, realParent, true)) return outside;
    const path = join(realParent, basename(auditDbPath));
    let existed = false;
    try {
      const st = lstatSync(path);
      if (!st.isFile()) return err("proxy.bad_audit_db", "ASF_AUDIT_DB is not a regular file");
      existed = true;
    } catch (e: unknown) {
      if (!(e instanceof Error && "code" in e && e.code === "ENOENT")) throw e;
    }
    return ok({ path, existed });
  } catch (e: unknown) {
    return err("proxy.bad_audit_db", "the ASF_AUDIT_DB location cannot be checked", {
      cause: e instanceof Error ? e.name : typeof e,
    });
  }
}

/**
 * Confine + hash the policy, load it, then confine and open the audit store (writable) and verify its chain. Any
 * failure ⇒ `err` (the CLI exits 2). The caller owns the returned store (`startProxy`'s shutdown closes it).
 */
export async function openFirewall(config: ProxyConfig): Promise<Result<OpenedFirewall>> {
  const policyPath = resolvePolicyPath(config.policyPath, config.repoRoot);
  if (!policyPath.ok) return policyPath;
  let policySha256: string;
  let realRoot: string;
  try {
    // Hash of the entry file only (imported modules are not covered), taken just before `loadPolicy` imports it.
    policySha256 = createHash("sha256").update(readFileSync(policyPath.value)).digest("hex");
    realRoot = realpathSync(config.repoRoot);
  } catch (e: unknown) {
    return err("policy.not_found", "policy file cannot be read", {
      cause: e instanceof Error ? e.name : typeof e,
    });
  }
  const policy = await loadPolicy(policyPath.value, config.repoRoot);
  if (!policy.ok) return policy;
  const db = confineAuditDb(config.auditDbPath, config.repoRoot);
  if (!db.ok) return db;
  const store = openAuditStore({ path: db.value.path });
  if (!store.ok) return store;
  const verified = store.value.verify();
  if (!verified.ok) {
    store.value.close();
    return err("audit.open_failed", "the audit log could not be read for verification");
  }
  const v = verified.value;
  return ok({
    policy: policy.value,
    store: store.value,
    report: {
      policyRelPath: relative(realRoot, policyPath.value).split(sep).join("/"),
      policySha256,
      auditDbPath: db.value.path,
      auditDbCreated: !db.value.existed,
      audit: v.ok
        ? { ok: true, count: v.count, headHash: v.headHash }
        : { ok: false, brokenAtSeq: v.brokenAt.seq, reason: v.brokenAt.reason },
    },
  });
}

/** Agent-facing deny message while money actions are disabled because the audit chain failed verification. */
export const AUDIT_UNVERIFIED_MESSAGE =
  "audit log failed verification at startup; money actions disabled until it is repaired";

/**
 * Owner decision: a broken audit chain at startup does NOT stop the proxy (read tools keep working) but the money
 * pipeline starts degraded — every money call is denied `audit_unavailable`. Dangling attempts alone don't trip it.
 */
export function startupDegradation(
  r: FirewallReport,
): { readonly reason: string; readonly message: string } | undefined {
  if (r.audit.ok) return undefined;
  return {
    reason: `audit log failed chain verification at seq ${String(r.audit.brokenAtSeq)} (${r.audit.reason})`,
    message: AUDIT_UNVERIFIED_MESSAGE,
  };
}

/** Lines `main` logs at startup for an opened firewall (see `FirewallReport`). */
export function firewallReportLines(r: FirewallReport, ruleCount: number): string[] {
  const lines = [
    `policy ${r.policyRelPath} sha256 ${r.policySha256} loaded (${String(ruleCount)} rules)`,
  ];
  if (r.audit.ok) {
    lines.push(
      `audit log ${r.auditDbPath}: ${String(r.audit.count)} records, head hash ${r.audit.headHash}`,
    );
  } else {
    lines.push(
      `WARNING: audit log ${r.auditDbPath} FAILED chain verification at seq ${String(r.audit.brokenAtSeq)} (${r.audit.reason}); it may have been tampered with — run audit:verify`,
      `WARNING: MONEY ACTIONS ARE DISABLED: every money tool call will be denied (audit_unavailable) until the audit log is repaired and the proxy restarted; read tools still work`,
    );
  }
  if (r.auditDbCreated) {
    lines.push(
      `WARNING: audit DB ${r.auditDbPath} did NOT exist and was CREATED empty: payment history is empty, so duplicate / velocity limits start from zero. If you expected an existing audit log, stop the proxy and check ASF_AUDIT_DB.`,
    );
  }
  return lines;
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
  readonly pipeline: MoneyPipeline;
  /** Close the agent channel and upstream (incl. `docker rm -f`). Idempotent. */
  shutdown(): Promise<void>;
}

export interface StartProxyOptions {
  readonly config: ProxyConfig;
  readonly logger: Logger;
  /** Policy + audit store from `openFirewall`. Closed by `shutdown`. */
  readonly firewall: Firewall;
  /** Default: in-memory stub (T011 replaces it); nothing awaiting approval is ever executed. */
  readonly approvals?: ApprovalPort;
  /** Start the money pipeline degraded (see `startupDegradation`); `main` derives it from `openFirewall`'s report. */
  readonly startDegraded?: { readonly reason: string; readonly message: string };
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
  const pipeline = createMoneyPipeline({
    policy: opts.firewall.policy,
    store: opts.firewall.store,
    upstream,
    approvals: opts.approvals ?? createInMemoryApprovalStub(),
    clock: systemClock,
    timer: systemTimer,
    redact,
    logger,
    lockWaitMs: config.lockWaitMs,
    ...(opts.startDegraded === undefined ? {} : { startDegraded: opts.startDegraded }),
  });
  const proxy = createProxyServer({
    upstream,
    cachedTools: config.cachedTools,
    // T004: money tools advertise a required `reason`, integer-paise amounts and INR; calls are checked to match.
    advertise: advertiseTool,
    // T008: moneyArgsStage → INR invariant → policy → audit → forward / deny / pending approval.
    interceptor: createFirewallInterceptor(pipeline, { logger }),
    // Card / token / PII redaction of results the agent sees (audit and policy lookups see raw upstream data).
    resultFilter: redactSensitiveResult,
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
    pipeline,
    shutdown: () => {
      shuttingDown ??= (async () => {
        try {
          await proxy.close();
        } catch (e: unknown) {
          logger(`closing the agent channel failed: ${redact(errorText(e))}`);
        }
        try {
          await upstream.close();
        } finally {
          opts.firewall.store.close();
        }
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
  const firewall = await openFirewall(config.value);
  if (!firewall.ok) {
    logger(`error: ${firewall.error.message} (${firewall.error.code})`);
    process.exitCode = 2;
    return;
  }
  for (const line of firewallReportLines(
    firewall.value.report,
    firewall.value.policy.rules.length,
  )) {
    logger(line);
  }

  const startDegraded = startupDegradation(firewall.value.report);
  const running = startProxy({
    config: config.value,
    logger,
    firewall: firewall.value,
    ...(startDegraded === undefined ? {} : { startDegraded }),
  });
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
