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
 * - `ASF_DUPLICATE_WINDOW_MS` — SHELL env only: how long an executed / possibly executed money action blocks an
 *   identical one (T009), integer ms 60000..86400000, default 600000 (10 min) ⇒ else exit 2. In-flight actions and
 *   pending approvals block for 24 h regardless.
 * - `ASF_RAZORPAY_MCP_IMAGE` — image override, SHELL env only (like discovery); default is the pinned digest.
 * - `ASF_MONEY_CALL_TIMEOUT_MS` — SHELL env only (T010): upstream timeout for MONEY tool calls, integer ms
 *   1000..120000, default 10000 ⇒ else exit 2. A timed-out money call is verified with Razorpay before anything else.
 * - `ASF_VERIFY_WAIT_MS` — SHELL env only (T010): how long a timed-out refund waits for upstream's late answer before
 *   deciding (retry once only after a late FAILURE answer + a complete refund list without the marker), integer ms
 *   1000..120000, default 15000 ⇒ else exit 2.
 *
 * - `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` (T011; shell or `.env`): both set ⇒ `require_approval` actions are sent to
 *   that Telegram chat with Approve / Reject buttons, approved ones execute through the normal money path, and the
 *   agent can poll `firewall_check_approval`. Pending approvals live in `<audit DB dir>/approvals.db`; their args stay
 *   in memory, so a restart expires them. Neither set ⇒ the in-memory stub (nothing awaiting approval ever executes).
 *   Only one set, or a malformed value ⇒ exit 2. The token is never logged.
 *
 * T010 startup reconciliation: right after start the money pipeline is `reconciling` (money calls denied
 * `firewall.reconciling`, reads work) while open attempts left by a crash and unsettled timeouts / upstream errors are
 * verified with Razorpay (never retried); still-unknown actions are flagged for a human and keep blocking duplicates.
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
 * T012 modes: the kill switch / shadow mode live in the audit log (`mode` records) and are read on EVERY money call
 * (`createModePreCheck`), so `asf-proxy mode kill on|off`, `mode shadow on|off`, `mode status` (`cli/mode.ts`; this
 * entry point dispatches `mode …` there) take effect on the next call. An unreadable mode ⇒ kill switch ON.
 *
 * Exit codes: 0 clean shutdown, 1 fatal runtime error, 2 refused (keys / config / policy / audit store).
 */
import { randomBytes } from "node:crypto";
import { userInfo } from "node:os";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, type CompiledPolicy, type Result } from "@asf/core";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createGrammyTransport,
  createTelegramApprover,
  openApprovalStore,
  CHAT_ID_RE,
  type ApprovalStore,
  type TelegramApprover,
} from "@asf/approvals";
import { createInMemoryApprovalStub, type ApprovalPort } from "../approval-port.js";
import { createApprovalService, type ApprovalService } from "../approval-service.js";
import { openAuditStore, type AuditStore } from "../audit-store.js";
import { systemClock, systemTimer } from "../context-adapters.js";
import {
  DEFAULT_DUPLICATE_WINDOW_MS,
  MAX_DUPLICATE_WINDOW_MS,
  MIN_DUPLICATE_WINDOW_MS,
} from "../idempotency.js";
import {
  createFirewallInterceptor,
  createMoneyPipeline,
  DEFAULT_LOCK_WAIT_MS,
  type MoneyPipeline,
} from "../interceptor.js";
import { createModePreCheck, createModeStore, describeMode, type ModeStore } from "../modes.js";
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
  DEFAULT_VERIFY_WAIT_MS,
  MAX_VERIFY_WAIT_MS,
  MIN_VERIFY_WAIT_MS,
  type ReconcileSummary,
} from "../failure.js";
import {
  DEFAULT_MONEY_CALL_TIMEOUT_MS,
  DEFAULT_UPSTREAM_TIMEOUT_MS,
  dockerUpstreamFactory,
  MAX_MONEY_CALL_TIMEOUT_MS,
  MIN_MONEY_CALL_TIMEOUT_MS,
  Upstream,
  type Logger,
  type Redactor,
  type UpstreamTransportFactory,
} from "../upstream.js";
import {
  AUDIT_DB_DIR,
  confineAuditDb,
  DEFAULT_AUDIT_DB,
  isStrictlyInside,
} from "./audit-db-path.js";
import { escapeForTerminal } from "./audit-verify.js";
import { runModeCommand } from "./mode.js";

export { AUDIT_DB_DIR, confineAuditDb, DEFAULT_AUDIT_DB } from "./audit-db-path.js";
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
/** Settings read from the SHELL environment only (a `.env` value is ignored with a note). */
export const SHELL_ONLY_SETTINGS = [
  "ASF_RAZORPAY_MCP_IMAGE",
  "ASF_POLICY",
  "ASF_AUDIT_DB",
  "ASF_DUPLICATE_WINDOW_MS",
  "ASF_MONEY_CALL_TIMEOUT_MS",
  "ASF_VERIFY_WAIT_MS",
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
  /** `ASF_DUPLICATE_WINDOW_MS` (shell env only). */
  readonly duplicateWindowMs: number;
  /** `ASF_MONEY_CALL_TIMEOUT_MS` (shell env only, T010). */
  readonly moneyCallTimeoutMs: number;
  /** `ASF_VERIFY_WAIT_MS` (shell env only, T010). */
  readonly verifyWaitMs: number;
  /** T011: Telegram approvals (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`); `undefined` ⇒ in-memory stub. SECRET token. */
  readonly telegram?: TelegramConfig;
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

export interface TelegramConfig {
  /** SECRET: never log it. */
  readonly token: string;
  readonly chatId: string;
}

/** Bot API token shape: `<bot id>:<secret>`. */
export const TELEGRAM_TOKEN_RE = /^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$/;

/** `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`: both or neither (fail closed on half a configuration). */
export function parseTelegramConfig(
  rawToken: string | undefined,
  rawChatId: string | undefined,
): Result<TelegramConfig | undefined> {
  const token = rawToken === undefined || rawToken === "" ? undefined : rawToken;
  const chatId = rawChatId === undefined || rawChatId === "" ? undefined : rawChatId;
  if (token === undefined && chatId === undefined) return ok(undefined);
  if (token === undefined || chatId === undefined) {
    return err(
      "proxy.bad_telegram",
      "set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID (or neither) for Telegram approvals",
    );
  }
  // Messages never echo the values.
  if (!TELEGRAM_TOKEN_RE.test(token)) {
    return err("proxy.bad_telegram", "TELEGRAM_BOT_TOKEN is not a valid bot token");
  }
  if (!CHAT_ID_RE.test(chatId)) {
    return err("proxy.bad_telegram", "TELEGRAM_CHAT_ID must be a numeric chat id");
  }
  return ok({ token, chatId });
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

export function parseDuplicateWindowMs(raw: string | undefined): Result<number> {
  if (raw === undefined || raw === "") return ok(DEFAULT_DUPLICATE_WINDOW_MS);
  if (!/^[0-9]{1,8}$/.test(raw)) {
    return err(
      "proxy.bad_duplicate_window",
      "ASF_DUPLICATE_WINDOW_MS must be an integer number of milliseconds",
    );
  }
  const n = Number(raw);
  if (n < MIN_DUPLICATE_WINDOW_MS || n > MAX_DUPLICATE_WINDOW_MS) {
    return err(
      "proxy.bad_duplicate_window",
      `ASF_DUPLICATE_WINDOW_MS must be between ${String(MIN_DUPLICATE_WINDOW_MS)} and ${String(MAX_DUPLICATE_WINDOW_MS)}`,
    );
  }
  return ok(n);
}

/** Integer ms setting in `[min, max]` (default when unset / empty); `code` names the error. */
function parseMsSetting(
  name: string,
  code: string,
  raw: string | undefined,
  def: number,
  min: number,
  max: number,
): Result<number> {
  if (raw === undefined || raw === "") return ok(def);
  if (!/^[0-9]{1,9}$/.test(raw)) {
    return err(code, `${name} must be an integer number of milliseconds`);
  }
  const n = Number(raw);
  if (n < min || n > max) {
    return err(code, `${name} must be between ${String(min)} and ${String(max)}`);
  }
  return ok(n);
}

export function parseMoneyCallTimeoutMs(raw: string | undefined): Result<number> {
  return parseMsSetting(
    "ASF_MONEY_CALL_TIMEOUT_MS",
    "proxy.bad_money_timeout",
    raw,
    DEFAULT_MONEY_CALL_TIMEOUT_MS,
    MIN_MONEY_CALL_TIMEOUT_MS,
    MAX_MONEY_CALL_TIMEOUT_MS,
  );
}

export function parseVerifyWaitMs(raw: string | undefined): Result<number> {
  return parseMsSetting(
    "ASF_VERIFY_WAIT_MS",
    "proxy.bad_verify_wait",
    raw,
    DEFAULT_VERIFY_WAIT_MS,
    MIN_VERIFY_WAIT_MS,
    MAX_VERIFY_WAIT_MS,
  );
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
  const duplicateWindow = parseDuplicateWindowMs(shellValue("ASF_DUPLICATE_WINDOW_MS"));
  if (!duplicateWindow.ok) return duplicateWindow;
  const moneyTimeout = parseMoneyCallTimeoutMs(shellValue("ASF_MONEY_CALL_TIMEOUT_MS"));
  if (!moneyTimeout.ok) return moneyTimeout;
  const verifyWait = parseVerifyWaitMs(shellValue("ASF_VERIFY_WAIT_MS"));
  if (!verifyWait.ok) return verifyWait;
  const telegram = parseTelegramConfig(env["TELEGRAM_BOT_TOKEN"], env["TELEGRAM_CHAT_ID"]);
  if (!telegram.ok) return telegram;

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
    duplicateWindowMs: duplicateWindow.value,
    moneyCallTimeoutMs: moneyTimeout.value,
    verifyWaitMs: verifyWait.value,
    ...(telegram.value === undefined ? {} : { telegram: telegram.value }),
    notes,
  });
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

/** Interval of the approval expiry sweep. */
export const APPROVAL_SWEEP_MS = 15_000;

export interface ApprovalWiring {
  readonly service: ApprovalService;
  readonly store: ApprovalStore;
  /** Started by `startProxy`, stopped by `shutdown`. */
  readonly telegram?: Pick<TelegramApprover, "start" | "stop">;
}

/** Approvals DB next to the audit DB (inside `<repo>/data/`, already confined). */
export function approvalsDbPath(auditDbPath: string): string {
  return join(dirname(auditDbPath), "approvals.db");
}

/**
 * T011: approval store + Telegram approver + service for `config.telegram` (`err` ⇒ exit 2). `transport` is
 * injectable for tests (default: grammy long polling with the bot token).
 */
export function openApprovals(
  config: ProxyConfig,
  logger: Logger,
  transport?: Parameters<typeof createTelegramApprover>[0]["transport"],
): Result<ApprovalWiring | undefined> {
  const tg = config.telegram;
  if (tg === undefined) return ok(undefined);
  const store = openApprovalStore({ path: approvalsDbPath(config.auditDbPath) });
  if (!store.ok) return store;
  const ref: { service?: ApprovalService } = {};
  const approver = createTelegramApprover({
    transport: transport ?? createGrammyTransport(tg.token, logger),
    chatId: tg.chatId,
    store: store.value,
    logger,
    onDecision: (d) =>
      ref.service === undefined
        ? Promise.resolve({ answer: "The firewall is starting; nothing was executed." })
        : ref.service.decide(d),
  });
  const service = createApprovalService({
    store: store.value,
    notifier: approver,
    clock: systemClock,
    logger,
  });
  ref.service = service;
  return ok({ service, store: store.value, telegram: approver });
}

export interface RunningProxy {
  readonly proxy: ProxyServer;
  readonly upstream: Upstream;
  readonly pipeline: MoneyPipeline;
  /** T010 startup reconciliation (started at once; money calls are denied `firewall.reconciling` until it settles). */
  readonly reconciled: Promise<Result<ReconcileSummary>>;
  /** Close the agent channel and upstream (incl. `docker rm -f`). Idempotent. */
  shutdown(): Promise<void>;
}

export interface StartProxyOptions {
  readonly config: ProxyConfig;
  readonly logger: Logger;
  /** Policy + audit store from `openFirewall`. Closed by `shutdown`. */
  readonly firewall: Firewall;
  /** Default: in-memory stub; nothing awaiting approval is ever executed. Ignored when `approvalWiring` is set. */
  readonly approvals?: ApprovalPort;
  /** T011: the real approval workflow (`openApprovals`). Closed by `shutdown`. */
  readonly approvalWiring?: ApprovalWiring;
  /** Start the money pipeline degraded (see `startupDegradation`); `main` derives it from `openFirewall`'s report. */
  readonly startDegraded?: { readonly reason: string; readonly message: string };
  /** Injected for tests; default: hardened docker. */
  readonly factory?: UpstreamTransportFactory;
  /** T012 mode state; default: `createModeStore(firewall.store)` (read on every money call). */
  readonly modes?: ModeStore;
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
  const wiring = opts.approvalWiring;
  const modes = opts.modes ?? createModeStore(opts.firewall.store);
  const mode = modes.read();
  logger(
    mode.ok
      ? `mode: ${describeMode(mode.value)}`
      : `WARNING: firewall mode unreadable (${mode.error.message}); the kill switch is treated as ON`,
  );
  if (mode.ok && mode.value.killSwitch) {
    logger("WARNING: KILL SWITCH IS ON: every money tool call will be denied (kill-switch)");
  } else if (mode.ok && mode.value.shadow) {
    logger(
      "WARNING: SHADOW MODE IS ON: policy decisions are only recorded; money calls are forwarded",
    );
  }
  const pipeline = createMoneyPipeline({
    policy: opts.firewall.policy,
    store: opts.firewall.store,
    upstream,
    approvals: wiring?.service ?? opts.approvals ?? createInMemoryApprovalStub(),
    ...(wiring === undefined
      ? {}
      : { approvalIdOf: (id: string) => wiring.service.approvalIdOf(id) }),
    clock: systemClock,
    timer: systemTimer,
    redact,
    logger,
    lockWaitMs: config.lockWaitMs,
    duplicateWindowMs: config.duplicateWindowMs,
    ...(opts.startDegraded === undefined ? {} : { startDegraded: opts.startDegraded }),
    // T010: verify before retry.
    lateResponses: upstream,
    verifyWaitMs: config.verifyWaitMs,
    startReconciling: true,
    // T012: kill switch / shadow mode, read per money call.
    preCheck: createModePreCheck(modes, logger),
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
    moneyCallTimeoutMs: config.moneyCallTimeoutMs,
    logger,
    redact,
    // T011: the agent polls approvals through a firewall-implemented tool.
    ...(wiring === undefined ? {} : { localTools: [wiring.service.checkTool] }),
  });
  let sweep: ReturnType<typeof setInterval> | undefined;
  if (wiring !== undefined) {
    wiring.service.attach({ pipeline, openCall: proxy.openDirectCall });
    // Approvals of an earlier run can't execute (their args were in memory): retire them before reconciling.
    const stale = wiring.service.expireStale();
    if (!stale.ok) logger(`approval store: expiring stale approvals failed (${stale.error.code})`);
    const started = wiring.telegram?.start();
    if (started !== undefined && !started.ok) {
      logger(`telegram approvals not started (${started.error.code})`);
    }
    sweep = setInterval(() => {
      void wiring.service.sweepExpired();
    }, APPROVAL_SWEEP_MS);
    sweep.unref();
  }
  upstream.onLateResponse((e) => {
    // Metadata only — the response body is never logged (T010 reconciles money calls from this event).
    logger(
      `late upstream response: id ${escapeForTerminal(String(e.requestId))}, tool ${escapeForTerminal(e.tool ?? "(untracked)")}, ${e.responseType}, generation ${String(e.generation)}`,
    );
  });
  void upstream.connect().then((r) => {
    if (!r.ok) logger(`upstream not available yet: ${redact(r.error.message)}`);
  });
  // T010: settle what an earlier run left unsettled before any money call is served.
  const reconciled = pipeline.reconcile();
  let shuttingDown: Promise<void> | undefined;
  return {
    proxy,
    upstream,
    pipeline,
    reconciled,
    shutdown: () => {
      shuttingDown ??= (async () => {
        try {
          await proxy.close();
        } catch (e: unknown) {
          logger(`closing the agent channel failed: ${redact(errorText(e))}`);
        }
        try {
          if (sweep !== undefined) clearInterval(sweep);
          await wiring?.telegram?.stop();
          await wiring?.service.idle();
          pipeline.close();
          await upstream.close();
        } finally {
          wiring?.store.close();
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
  const args = process.argv.slice(2);
  if (args[0] === "--") args.shift();
  if (args[0] === "mode") {
    const r = runModeCommand(args.slice(1), {
      env: process.env,
      cwd: process.cwd(),
      moduleDir: dirname(fileURLToPath(import.meta.url)),
      isRepoRoot: (dir) => existsSync(join(dir, "pnpm-workspace.yaml")),
      userName: () => {
        try {
          return userInfo().username;
        } catch (e: unknown) {
          process.stderr.write(
            `note: no OS user name (${e instanceof Error ? e.name : typeof e})\n`,
          );
          return undefined;
        }
      },
    });
    (r.exitCode === 0 ? process.stdout : process.stderr).write(`${r.output}\n`);
    process.exitCode = r.exitCode;
    return;
  }
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
    `upstream image ${config.value.image}; call timeout ${String(config.value.callTimeoutMs)} ms; money call timeout ${String(config.value.moneyCallTimeoutMs)} ms; verify wait ${String(config.value.verifyWaitMs)} ms`,
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
  const approvals = openApprovals(config.value, logger);
  if (!approvals.ok) {
    logger(`error: ${approvals.error.message} (${approvals.error.code})`);
    firewall.value.store.close();
    process.exitCode = 2;
    return;
  }
  logger(
    approvals.value === undefined
      ? "approvals: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set; actions needing approval are never executed"
      : `approvals: Telegram chat ${config.value.telegram?.chatId ?? "?"}; store ${approvals.value.store.path}`,
  );
  const running = startProxy({
    config: config.value,
    logger,
    firewall: firewall.value,
    ...(approvals.value === undefined ? {} : { approvalWiring: approvals.value }),
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
