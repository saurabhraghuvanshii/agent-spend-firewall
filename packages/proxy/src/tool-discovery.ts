/**
 * Discover the upstream Razorpay MCP server's tools (T002).
 *
 * Everything here is pure or takes its I/O through injected interfaces so it can be tested without Docker or
 * real keys. The MCP client is hidden behind `ToolLister`, which deliberately has NO way to call a tool:
 * discovery can only list.
 *
 * Secrets: the human's real key id / secret are validated (TEST mode only) but never leave this process. The
 * container only ever receives the fixed, non-secret `DISCOVERY_PLACEHOLDER_KEYS` (the Razorpay MCP server lists
 * its tools without contacting Razorpay, and the container has no network anyway). The real values never appear
 * in argv, error messages, or the rendered output (`assertNoSecrets`), and child stderr is redacted before display.
 */
import { err, ok, type Result } from "@asf/core";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { z } from "zod";

export type EnvLike = Readonly<Record<string, string | undefined>>;

/** Pinned by digest so discovery runs exactly the image that was reviewed. `--pull=never`: pull it yourself first. */
export const DEFAULT_RAZORPAY_MCP_IMAGE =
  "razorpay/mcp@sha256:435109006d6247103899938cf7b1747ba8be1c1a8a28d452cf9fa8eff506e5c6";

/**
 * Fake credentials handed to the discovery container instead of the real keys. NOT secrets. Verified against the
 * pinned image: `tools/list` works with these under `--network none` (tool registration needs no API call).
 */
export const DISCOVERY_PLACEHOLDER_KEYS: TestKeys = Object.freeze({
  keyId: "rzp_test_discoveryonly",
  keySecret: "placeholder",
});
export const DEFAULT_DISCOVERY_TIMEOUT_MS = 60_000;
export const MAX_DISCOVERY_PAGES = 50;
export const TOOLS_FILE_SCHEMA_VERSION = 1 as const;

// ---------------------------------------------------------------------------------------------------------------
// Key guard
// ---------------------------------------------------------------------------------------------------------------

const TEST_KEY_ID = /^rzp_test_[A-Za-z0-9]+$/;

export interface TestKeys {
  readonly keyId: string;
  readonly keySecret: string;
}

/**
 * Refuse anything but Razorpay TEST keys (AGENTS.md hard rule 3). Error messages name variables, never values.
 * Any environment value containing `rzp_live_` (any letter case) is refused too, so a live key can't sneak in via
 * another variable.
 */
export function checkTestKeys(env: EnvLike): Result<TestKeys> {
  for (const [name, value] of Object.entries(env)) {
    if (typeof value === "string" && value.toLowerCase().includes("rzp_live_")) {
      return err(
        "discover.live_key",
        `refusing to run: environment variable ${safeVarName(name)} contains a Razorpay LIVE key (rzp_live_); TEST mode only`,
      );
    }
  }
  const keyId = env["RAZORPAY_KEY_ID"];
  if (keyId === undefined || keyId === "") {
    return err("discover.missing_key_id", "RAZORPAY_KEY_ID is not set (expected a rzp_test_ key)");
  }
  if (!TEST_KEY_ID.test(keyId)) {
    return err(
      "discover.not_test_key",
      "refusing to run: RAZORPAY_KEY_ID is not a Razorpay TEST key (must match rzp_test_<alphanumeric>)",
    );
  }
  const keySecret = env["RAZORPAY_KEY_SECRET"];
  if (keySecret === undefined || keySecret === "") {
    return err("discover.missing_key_secret", "RAZORPAY_KEY_SECRET is not set");
  }
  return ok({ keyId, keySecret });
}

/** Variable names come from the environment; only print ones that look like normal identifiers. */
function safeVarName(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name) ? name : "(unprintable name)";
}

// ---------------------------------------------------------------------------------------------------------------
// Docker invocation
// ---------------------------------------------------------------------------------------------------------------

/** Docker image reference: no leading dash (would be parsed as a flag), no whitespace or shell metacharacters. */
const IMAGE_REF = /^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]{1,128})?(@sha256:[a-f0-9]{64})?$/;

export function validateImageRef(image: string): Result<string> {
  if (image.length > 255 || !IMAGE_REF.test(image)) {
    return err(
      "discover.bad_image",
      "ASF_RAZORPAY_MCP_IMAGE is not a valid docker image reference",
    );
  }
  return ok(image);
}

const CONTAINER_NAME = /^asf-discover-[a-f0-9]{8,32}$/;

/** `asf-discover-<hex>`; `hex` must be 8–32 lowercase hex chars (e.g. `randomBytes(8).toString("hex")`). */
export function discoveryContainerName(hex: string): Result<string> {
  const name = `asf-discover-${hex}`;
  return CONTAINER_NAME.test(name)
    ? ok(name)
    : err("discover.bad_container_name", "container name suffix must be 8-32 lowercase hex chars");
}

/**
 * Hardened `docker run` argv:
 * - `--network none`: the server needs no network to list tools, and can't phone home / exfiltrate.
 * - `--pull=never`: never fetch an image implicitly; the human `docker pull`s the pinned image first.
 * - `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--init`: minimal container privileges,
 *   proper signal handling. (`--read-only` here is docker's root-fs flag, NOT the Razorpay server's toolset flag:
 *   all toolsets stay enabled because we need to see the money tools to classify them. Discovery never calls a
 *   tool.)
 * - `--name`: a known name so the container can be force-removed on timeout/abort (`dockerRmArgs`).
 * - `-e NAME` (no `=value`) copies the variable from docker's environment, so values never appear in argv / `ps`.
 */
export function dockerRunArgs(image: string, containerName: string): string[] {
  if (!CONTAINER_NAME.test(containerName)) {
    throw new Error("dockerRunArgs: invalid container name");
  }
  return [
    "run",
    "-i",
    "--rm",
    "--name",
    containerName,
    "--network",
    "none",
    "--pull=never",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--init",
    "-e",
    "RAZORPAY_KEY_ID",
    "-e",
    "RAZORPAY_KEY_SECRET",
    image,
  ];
}

/** `docker rm -f <name>` argv, for cleanup after timeout / abort / any exit. */
export function dockerRmArgs(containerName: string): string[] {
  if (!CONTAINER_NAME.test(containerName)) {
    throw new Error("dockerRmArgs: invalid container name");
  }
  return ["rm", "-f", containerName];
}

/**
 * Docker client configuration variables passed through to the `docker` CLI. Taken from the SHELL environment
 * only (never from `.env`), so a repo file can't redirect docker to another daemon or credential store.
 */
export const DOCKER_ENV_PASSTHROUGH: readonly string[] = [
  "DOCKER_HOST",
  "DOCKER_CONTEXT",
  "DOCKER_CONFIG",
  "DOCKER_CERT_PATH",
  "DOCKER_TLS_VERIFY",
  "DOCKER_API_VERSION",
];

/**
 * Child process environment: the MCP SDK's safe default set (PATH, HOME, …) + docker client config (from
 * `shellEnv`, which must be the real shell environment, not the `.env`-merged one) + exactly the two Razorpay
 * variables set to `containerKeys` (discovery passes `DISCOVERY_PLACEHOLDER_KEYS`). Nothing else from the parent
 * environment (other API keys, tokens) is inherited.
 */
export function buildChildEnv(
  base: Readonly<Record<string, string>>,
  shellEnv: EnvLike,
  containerKeys: TestKeys,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(base)) {
    if (k.startsWith("RAZORPAY_")) continue;
    out[k] = v;
  }
  for (const name of DOCKER_ENV_PASSTHROUGH) {
    const v = shellEnv[name];
    if (typeof v === "string" && v !== "") out[name] = v;
  }
  out["RAZORPAY_KEY_ID"] = containerKeys.keyId;
  out["RAZORPAY_KEY_SECRET"] = containerKeys.keySecret;
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------------------------------------------

export interface ServerInfo {
  readonly name: string;
  readonly version: string;
}

/** The only upstream capability discovery needs. Intentionally has no `callTool`. */
export interface ToolLister {
  /** One `tools/list` page. The raw result is validated by `discoverTools`. */
  listTools(cursor: string | undefined): Promise<unknown>;
  serverInfo(): ServerInfo | undefined;
  close(): Promise<void>;
}

/**
 * Adapt a connected MCP SDK `Client` to `ToolLister`. Only `tools/list` and server info are reachable through it.
 * Requests are cancelled when `signal` aborts.
 */
export function listerFromClient(client: Client, signal: AbortSignal): ToolLister {
  return {
    listTools: (cursor) =>
      client.listTools(cursor === undefined ? undefined : { cursor }, { signal }),
    serverInfo: () => {
      const v = client.getServerVersion();
      return v === undefined ? undefined : { name: v.name, version: v.version };
    },
    close: () => client.close(),
  };
}

/** Opens a connected `ToolLister`. Must stop connecting (and release resources) when `signal` aborts. */
export type ConnectLister = (signal: AbortSignal) => Promise<ToolLister>;

const toolNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_.-]+$/, "tool name must be [A-Za-z0-9_.-]");

const jsonObjectSchema = z.record(z.string(), z.unknown());

const toolSchema = z.object({
  name: toolNameSchema,
  description: z.string().max(20_000).optional(),
  inputSchema: z.looseObject({ type: z.literal("object") }),
  annotations: jsonObjectSchema.optional(),
});

const listPageSchema = z.object({
  tools: z.array(toolSchema),
  nextCursor: z.string().min(1).max(1024).optional(),
});

export interface DiscoveredTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  /** MCP tool annotations (`readOnlyHint`, …) as reported upstream. Informational only: never trusted for gating. */
  readonly annotations?: Readonly<Record<string, unknown>>;
}

export interface DiscoveryResult {
  readonly server: ServerInfo;
  readonly tools: readonly DiscoveredTool[];
}

export interface DiscoverOptions {
  readonly connect: ConnectLister;
  readonly timeoutMs?: number;
  readonly maxPages?: number;
  /** Injected for tests; defaults to global timers. */
  readonly setTimer?: (fn: () => void, ms: number) => () => void;
  /** External cancellation (e.g. SIGINT). Treated like a timeout, with code `discover.aborted`. */
  readonly signal?: AbortSignal;
}

const serverInfoSchema = z.object({
  name: z.string().min(1).max(256),
  version: z.string().min(1).max(256),
});

/**
 * Connect, page through `tools/list`, validate and sort. Fails (never partially succeeds) on timeout, malformed
 * pages, an empty list, duplicate names, or a pagination loop. The lister is always closed.
 */
export async function discoverTools(opts: DiscoverOptions): Promise<Result<DiscoveryResult>> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_DISCOVERY_TIMEOUT_MS;
  const maxPages = opts.maxPages ?? MAX_DISCOVERY_PAGES;
  const setTimer =
    opts.setTimer ??
    ((fn: () => void, ms: number) => {
      const t = setTimeout(fn, ms);
      return () => clearTimeout(t);
    });

  const controller = new AbortController();
  let lister: ToolLister | undefined;
  let timedOut = false;
  let cancelTimer: () => void = () => undefined;
  let detachAbort: () => void = () => undefined;
  const timeout = new Promise<Result<DiscoveryResult>>((resolveTimeout) => {
    const stop = (result: Result<DiscoveryResult>): void => {
      if (timedOut) return;
      timedOut = true;
      controller.abort();
      resolveTimeout(result);
    };
    cancelTimer = setTimer(() => {
      stop(
        err(
          "discover.timeout",
          `upstream did not finish tools/list within ${String(timeoutMs)} ms`,
        ),
      );
    }, timeoutMs);
    const ext = opts.signal;
    if (ext !== undefined) {
      const onAbort = (): void => {
        stop(err("discover.aborted", "discovery was aborted"));
      };
      if (ext.aborted) onAbort();
      else {
        ext.addEventListener("abort", onAbort, { once: true });
        detachAbort = () => {
          ext.removeEventListener("abort", onAbort);
        };
      }
    }
  });

  const work = (async (): Promise<Result<DiscoveryResult>> => {
    try {
      lister = await opts.connect(controller.signal);
    } catch (e: unknown) {
      return err(
        "discover.connect_failed",
        `cannot connect to the upstream MCP server: ${errorText(e)}`,
      );
    }
    if (timedOut) return err("discover.timeout", "timed out");
    return listAll(lister, maxPages, () => timedOut);
  })();

  // Closes the lister once (it may be assigned late, after a timeout already decided the result).
  const closeLister = async (): Promise<void> => {
    if (lister === undefined) return;
    const l = lister;
    lister = undefined;
    try {
      await l.close();
    } catch {
      // Best effort: the result is already decided. Report it without the (upstream-controlled) error text.
      process.stderr.write("warning: closing the upstream MCP connection failed\n");
    }
  };

  try {
    return await Promise.race([work, timeout]);
  } finally {
    cancelTimer();
    detachAbort();
    await closeLister();
    controller.abort();
    if (timedOut) void work.then(closeLister, closeLister);
  }
}

async function listAll(
  lister: ToolLister,
  maxPages: number,
  isTimedOut: () => boolean,
): Promise<Result<DiscoveryResult>> {
  const info = serverInfoSchema.safeParse(lister.serverInfo());
  if (!info.success) {
    return err(
      "discover.malformed_server_info",
      "upstream did not report a valid serverInfo name/version",
    );
  }
  const seenCursors = new Set<string>();
  const byName = new Map<string, DiscoveredTool>();
  let cursor: string | undefined;
  for (let page = 0; ; page++) {
    if (page >= maxPages) {
      return err(
        "discover.too_many_pages",
        `tools/list returned more than ${String(maxPages)} pages`,
      );
    }
    let raw: unknown;
    try {
      raw = await lister.listTools(cursor);
    } catch (e: unknown) {
      return err("discover.list_failed", `tools/list failed: ${errorText(e)}`);
    }
    if (isTimedOut()) return err("discover.timeout", "timed out");
    const parsed = listPageSchema.safeParse(raw);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const where =
        issue === undefined ? "" : ` at ${issue.path.map(String).join(".")}: ${issue.message}`;
      return err("discover.malformed_list", `tools/list returned a malformed page${where}`, {
        page,
      });
    }
    for (const t of parsed.data.tools) {
      if (byName.has(t.name)) {
        return err("discover.duplicate_tool", `upstream listed tool ${t.name} more than once`);
      }
      const tool: DiscoveredTool =
        t.annotations === undefined
          ? { name: t.name, description: t.description ?? "", inputSchema: t.inputSchema }
          : {
              name: t.name,
              description: t.description ?? "",
              inputSchema: t.inputSchema,
              annotations: t.annotations,
            };
      byName.set(t.name, tool);
    }
    const next = parsed.data.nextCursor;
    if (next === undefined) break;
    if (seenCursors.has(next)) {
      return err(
        "discover.pagination_loop",
        "tools/list returned a cursor it had already returned",
      );
    }
    seenCursors.add(next);
    cursor = next;
  }
  if (byName.size === 0) return err("discover.empty", "upstream listed no tools");
  const tools = [...byName.values()].sort((a, b) => compareStrings(a.name, b.name));
  return ok({ server: info.data, tools });
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Error text for messages. Callers must still redact + escape before printing anything from upstream. */
export function errorText(e: unknown): string {
  if (e instanceof Error) return `${e.name}: ${e.message}`;
  return "non-error thrown";
}

// ---------------------------------------------------------------------------------------------------------------
// Output file
// ---------------------------------------------------------------------------------------------------------------

export const toolsFileSchema = z.object({
  schemaVersion: z.literal(TOOLS_FILE_SCHEMA_VERSION),
  server: serverInfoSchema,
  transport: z.literal("docker-stdio"),
  image: z.string().min(1),
  imageDigest: z.string().min(1).optional(),
  discoveredAt: z.iso.datetime(),
  tools: z
    .array(
      z.object({
        name: toolNameSchema,
        description: z.string(),
        inputSchema: z.looseObject({ type: z.literal("object") }),
        annotations: jsonObjectSchema.optional(),
      }),
    )
    .min(1),
});

export type ToolsFile = z.infer<typeof toolsFileSchema>;

export interface BuildToolsFileInput {
  readonly discovery: DiscoveryResult;
  readonly image: string;
  readonly imageDigest: string | undefined;
  readonly discoveredAt: Date;
}

export function buildToolsFile(input: BuildToolsFileInput): ToolsFile {
  const base = {
    schemaVersion: TOOLS_FILE_SCHEMA_VERSION,
    server: { name: input.discovery.server.name, version: input.discovery.server.version },
    transport: "docker-stdio" as const,
    image: input.image,
    discoveredAt: input.discoveredAt.toISOString(),
    tools: input.discovery.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: { ...t.inputSchema, type: "object" as const },
      ...(t.annotations === undefined ? {} : { annotations: { ...t.annotations } }),
    })),
  };
  return input.imageDigest === undefined ? base : { ...base, imageDigest: input.imageDigest };
}

/** Deterministic JSON: object keys sorted recursively, array order kept, 2-space indent, trailing newline. */
export function renderToolsFile(file: ToolsFile): string {
  return `${JSON.stringify(sortKeysDeep(file), null, 2)}\n`;
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort(compareStrings)) {
      // Define rather than assign, so a `__proto__` key from upstream stays a plain data property.
      Object.defineProperty(out, k, {
        value: sortKeysDeep((value as Record<string, unknown>)[k]),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return value;
}

/**
 * Every encoding of the key id / secret worth searching for: raw, JSON-escaped, `encodeURIComponent`, and the
 * HTTP Basic auth form `base64(id:secret)` (standard alphabet with and without padding, and URL-safe).
 * Empty values are skipped; longest first so redaction replaces whole forms.
 */
export function secretVariants(keys: TestKeys): string[] {
  const out = new Set<string>();
  for (const s of [keys.keyId, keys.keySecret]) {
    if (s === "") continue;
    out.add(s);
    out.add(JSON.stringify(s).slice(1, -1));
    out.add(encodeURIComponent(s));
  }
  if (keys.keyId !== "" && keys.keySecret !== "") {
    const basic = Buffer.from(`${keys.keyId}:${keys.keySecret}`, "utf8");
    out.add(basic.toString("base64"));
    out.add(basic.toString("base64").replace(/=+$/, ""));
    out.add(basic.toString("base64url"));
  }
  out.delete("");
  return [...out].sort((a, b) => b.length - a.length);
}

/** Refuse to write output that contains any form of the key id or secret (e.g. an upstream echoing its config). */
export function assertNoSecrets(rendered: string, keys: TestKeys): Result<string> {
  for (const v of secretVariants(keys)) {
    if (rendered.includes(v)) {
      return err(
        "discover.secret_in_output",
        "refusing to write: discovered tool data contains the Razorpay key id or secret",
      );
    }
  }
  return ok(rendered);
}

/** Replace every occurrence of every form (`secretVariants`) of the keys with `[REDACTED]`. */
export function redactSecrets(text: string, keys: TestKeys): string {
  let out = text;
  for (const v of secretVariants(keys)) out = out.split(v).join("[REDACTED]");
  return out;
}
