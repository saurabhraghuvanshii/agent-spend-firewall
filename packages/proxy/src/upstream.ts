/**
 * Upstream connection to the Razorpay MCP server (T003).
 *
 * `Upstream` wraps an MCP SDK `Client`. The transport comes from an injectable factory (`UpstreamTransportFactory`):
 * production uses `dockerUpstreamFactory` (hardened `docker run` over stdio), tests use in-memory transports.
 *
 * Connection lifecycle:
 * - `connect()` tries up to `maxAttempts` times with bounded exponential backoff (default 3 attempts, 250 ms → 2 s).
 *   Concurrent callers share one in-flight attempt cycle.
 * - When the transport closes or errors, the connection is dropped (and its container force-removed); the NEXT
 *   `listTools` / `callTool` reconnects lazily. A call that was in flight when the connection dropped is NOT retried:
 *   its outcome is unknown (it may have reached Razorpay), so it fails with `forwarded: true`. Never blindly retry a
 *   money call (T010 adds verify-before-retry).
 * - `generation` increments on every successful connect, so callers can tell a reconnect happened (e.g. re-list).
 *   `listTools` reports the generation it listed on, and `callTool({ expectedGeneration })` refuses to send (and never
 *   reconnects) unless the live connection is still that generation.
 * - Late responses: when a call times out or is cancelled, upstream may still answer. The SDK then reports
 *   "unknown message ID" with the FULL response body; we never log that body. Instead a tap on the transport emits a
 *   payload-free `LateResponse` event (`onLateResponse`) so T010 can reconcile. The event carries only `isError`
 *   (JSON-RPC error, or a result with `isError: true`) and a bounded failure classification (`upstream-failure.ts`:
 *   definite Razorpay rejection vs ambiguous), computed while the response is delivered; the body is never kept.
 *
 * Nothing upstream-controlled is trusted for output: error messages go through `redact` (key id / secret in every
 * known encoding) and are length-capped; callers escape before printing to a terminal.
 */
import { execFile } from "node:child_process";
import { err, ok, type Result } from "@asf/core";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolResultSchema,
  ErrorCode,
  isJSONRPCErrorResponse,
  isJSONRPCRequest,
  isJSONRPCResultResponse,
  McpError,
  ToolListChangedNotificationSchema,
  type CallToolResult,
  type JSONRPCMessage,
  type MessageExtraInfo,
  type RequestId,
} from "@modelcontextprotocol/sdk/types.js";
import type { TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";
import { escapeForTerminal } from "./cli/audit-verify.js";
import { classifyToolResultFailure, type UpstreamFailure } from "./upstream-failure.js";
import {
  discoverTools,
  errorText,
  type DiscoveredTool,
  type ToolLister,
} from "./tool-discovery.js";

export const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;
/**
 * T010: per-call timeout for MONEY tools (`ASF_MONEY_CALL_TIMEOUT_MS`), shorter than reads so a hung refund is
 * verified (verify-before-retry) while the agent still waits. Reads keep `DEFAULT_UPSTREAM_TIMEOUT_MS`.
 */
export const DEFAULT_MONEY_CALL_TIMEOUT_MS = 10_000;
export const MIN_MONEY_CALL_TIMEOUT_MS = 1_000;
export const MAX_MONEY_CALL_TIMEOUT_MS = 120_000;
export const DEFAULT_CONNECT_TIMEOUT_MS = 20_000;
export const DEFAULT_RECONNECT_ATTEMPTS = 3;
export const DEFAULT_BACKOFF_INITIAL_MS = 250;
export const DEFAULT_BACKOFF_MAX_MS = 2_000;
/** Upper bound for `docker rm -f`. */
export const DOCKER_RM_TIMEOUT_MS = 15_000;
const MAX_MESSAGE_CHARS = 500;
const CODE_REQUEST_TIMEOUT: number = ErrorCode.RequestTimeout;
const CODE_CONNECTION_CLOSED: number = ErrorCode.ConnectionClosed;

/** One line of operator log output. Implementations write to STDERR only (stdout is the MCP channel). */
export type Logger = (line: string) => void;
export type Redactor = (text: string) => string;

export const noRedact: Redactor = (s) => s;

// ---------------------------------------------------------------------------------------------------------------
// Transport factory
// ---------------------------------------------------------------------------------------------------------------

export interface UpstreamConnection {
  readonly transport: Transport;
  /** Release resources after the client is closed (e.g. `docker rm -f`). Must not throw. */
  dispose(): Promise<void>;
  /** Diagnostic text to log when connecting fails (e.g. the redacted stderr tail). Raw: caller escapes. */
  diagnostics?(): string;
}

/** Creates a FRESH connection per attempt (a stdio transport can't be restarted). */
export type UpstreamTransportFactory = () => UpstreamConnection;

// ---------------------------------------------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------------------------------------------

export type UpstreamErrorKind =
  | "upstream_unavailable"
  | "upstream_timeout"
  | "upstream_error"
  /** The agent cancelled the request (`notifications/cancelled`), not an upstream fault. */
  | "cancelled";

export type UpstreamCallOutcome =
  | { readonly kind: "ok"; readonly result: CallToolResult }
  | {
      readonly kind: "error";
      readonly error: UpstreamErrorKind;
      /** Secret-free, length-capped. Not terminal-escaped. */
      readonly message: string;
      /**
       * `false`: the request certainly never reached upstream. `true`: it was sent; upstream MAY have acted on it
       * (timeout, connection lost mid-call, protocol error).
       */
      readonly forwarded: boolean;
      /**
       * JSON-RPC id the request was sent with, when it was sent and the id could be observed. Matches
       * `LateResponse.requestId` (same `generation`) if upstream answers after we gave up.
       */
      readonly requestId?: RequestId;
      readonly generation?: number;
    };

export interface CallOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  /**
   * Only send on this connection generation. If the live connection is a different generation, or there is none,
   * the call is NOT sent (`upstream_unavailable`, `forwarded: false`) and no reconnect is attempted.
   */
  readonly expectedGeneration?: number;
}

export interface ListedTools {
  readonly tools: readonly DiscoveredTool[];
  /** Connection generation the list was obtained on. */
  readonly generation: number;
}

/**
 * Upstream answered a request we no longer wait for (timed out / cancelled / unknown id). Metadata only: the
 * response body is never kept or logged (it may hold PII). T010 reconciles money calls from these.
 */
export interface LateResponse {
  readonly requestId: RequestId;
  /** Tool name if the id belongs to a `tools/call` we sent on this connection; otherwise `undefined`. */
  readonly tool: string | undefined;
  readonly generation: number;
  /** Epoch ms the request was sent, if known. */
  readonly sentAt: number | undefined;
  readonly receivedAt: number;
  /** JSON-RPC level: a `result` or an `error` response. */
  readonly responseType: "result" | "error";
  /**
   * T010: true iff the response reports a failure — a JSON-RPC `error` response, or a `result` whose `isError` is
   * exactly `true`. Only this boolean is read from the body (nothing else is kept). A `result` without
   * `isError: true` is `false` (success, or a body we can't interpret as a failure).
   */
  readonly isError: boolean;
  /**
   * T010 (security review): what the failure proves (`upstream-failure.ts`). `none` iff `isError` is false; a JSON-RPC
   * error is always `ambiguous`; an `isError: true` result is `definite_rejection` only for a recognised Razorpay
   * client rejection. Classified while the response is delivered; the body itself is never kept.
   */
  readonly failure: UpstreamFailure;
}

export interface UpstreamOptions {
  readonly factory: UpstreamTransportFactory;
  readonly logger?: Logger;
  readonly redact?: Redactor;
  readonly clientInfo?: { readonly name: string; readonly version: string };
  readonly maxAttempts?: number;
  readonly backoffInitialMs?: number;
  readonly backoffMaxMs?: number;
  readonly connectTimeoutMs?: number;
  readonly callTimeoutMs?: number;
  /** Injected for tests. Resolves after `ms`, or early when `signal` aborts. */
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** Injected for tests. Epoch ms. */
  readonly now?: () => number;
}

/** The surface the proxy server needs; `Upstream` implements it. */
export interface UpstreamPort {
  connect(): Promise<Result<null>>;
  isConnected(): boolean;
  readonly generation: number;
  listTools(): Promise<Result<ListedTools>>;
  callTool(
    name: string,
    args: Record<string, unknown>,
    opts?: CallOptions,
  ): Promise<UpstreamCallOutcome>;
  /** Upstream sent `notifications/tools/list_changed`. Returns an unsubscribe function. */
  onToolListChanged(listener: () => void): () => void;
  /** Upstream answered a request after we stopped waiting. Returns an unsubscribe function. */
  onLateResponse(listener: (e: LateResponse) => void): () => void;
  close(): Promise<void>;
}

interface Live {
  readonly client: Client;
  readonly conn: UpstreamConnection;
  readonly tap: TappedTransport;
  readonly generation: number;
}

/** Max outstanding `tools/call` ids remembered per connection (oldest evicted). */
const MAX_TRACKED_REQUESTS = 1024;

interface Outbound {
  readonly tool: string;
  readonly sentAt: number;
}

interface Delivering {
  readonly id: RequestId;
  readonly outbound: Outbound | undefined;
  readonly responseType: "result" | "error";
  readonly isError: boolean;
  readonly failure: UpstreamFailure;
}

/**
 * Failure classification of a JSON-RPC response (only the enum is kept): an `error` response ⇒ ambiguous; a
 * `result` ⇒ `classifyToolResultFailure` (`none` unless `isError === true`).
 */
export function responseFailure(message: JSONRPCMessage): UpstreamFailure {
  if (!isJSONRPCResultResponse(message)) return "ambiguous";
  return classifyToolResultFailure(message.result);
}

/**
 * Transparent wrapper around the upstream transport that records outgoing `tools/call` ids (id → tool, time) and
 * marks which response is being delivered, so an SDK "unknown message ID" error raised synchronously while that
 * response is processed can be attributed to it WITHOUT reading the error text (which contains the full body).
 */
export class TappedTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;
  /** Set only while an inbound response is being handed to the SDK. */
  delivering: Delivering | undefined;
  private lastToolCall: { readonly id: RequestId; readonly tool: string } | undefined;
  private readonly outbound = new Map<RequestId, Outbound>();

  constructor(
    private readonly inner: Transport,
    private readonly now: () => number,
  ) {
    inner.onclose = () => {
      this.outbound.clear();
      this.onclose?.();
    };
    inner.onerror = (e: Error) => {
      this.onerror?.(e);
    };
    inner.onmessage = <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => {
      this.receive(message, extra);
    };
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  close(): Promise<void> {
    return this.inner.close();
  }

  /** Returns and clears the last `tools/call` sent (read synchronously right after `client.request`). */
  takeLastToolCall(): { readonly id: RequestId; readonly tool: string } | undefined {
    const last = this.lastToolCall;
    this.lastToolCall = undefined;
    return last;
  }

  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }

  send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    if (isJSONRPCRequest(message) && message.method === "tools/call") {
      const params = message.params;
      const tool = params !== undefined && typeof params["name"] === "string" ? params["name"] : "";
      if (this.outbound.size >= MAX_TRACKED_REQUESTS) {
        const oldest = this.outbound.keys().next();
        if (oldest.done !== true) this.outbound.delete(oldest.value);
      }
      this.outbound.set(message.id, { tool, sentAt: this.now() });
      this.lastToolCall = { id: message.id, tool };
    }
    return this.inner.send(message, options);
  }

  private receive(message: JSONRPCMessage, extra: MessageExtraInfo | undefined): void {
    const isResult = isJSONRPCResultResponse(message);
    if (!isResult && !isJSONRPCErrorResponse(message)) {
      this.onmessage?.(message, extra);
      return;
    }
    const id = message.id;
    // JSON-RPC error responses may carry a null id; nothing to correlate then.
    if (id === undefined || id === null) {
      this.onmessage?.(message, extra);
      return;
    }
    const failure = responseFailure(message);
    this.delivering = {
      id,
      outbound: this.outbound.get(id),
      responseType: isResult ? "result" : "error",
      isError: failure !== "none",
      failure,
    };
    try {
      this.onmessage?.(message, extra);
    } finally {
      this.delivering = undefined;
      this.outbound.delete(id);
    }
  }
}

const SAFE_ERROR_NAME = /^[A-Za-z$][A-Za-z0-9_$]{0,40}$/;
const SAFE_ERROR_CODE = /^[A-Z][A-Z0-9_]{0,31}$/;

/**
 * Payload-free description of a transport / protocol error for the log: error class + a FIXED category (+ a Node
 * system error code such as `ENOENT` when present). The error message is never included: SDK messages embed whole
 * JSON-RPC messages (tool results, i.e. PII) and parse errors embed input snippets.
 */
export function describeTransportError(e: unknown, category?: string): string {
  const name = e instanceof Error && SAFE_ERROR_NAME.test(e.name) ? e.name : "Error";
  let cat = category;
  if (cat === undefined) {
    if (name === "SyntaxError" || name === "ZodError" || name === "$ZodError") cat = "parse error";
    else if (e instanceof McpError) cat = `protocol error (code ${String(e.code)})`;
    else cat = "transport error";
  }
  const code =
    e instanceof Error && "code" in e && typeof e.code === "string" && SAFE_ERROR_CODE.test(e.code)
      ? ` [${e.code}]`
      : "";
  return `${name}: ${cat}${code}`;
}

/** Backoff before attempt `n` (1-based; attempt 1 has none): initial·4^(n-2), capped. */
export function backoffDelayMs(attempt: number, initialMs: number, maxMs: number): number {
  if (attempt <= 1) return 0;
  return Math.min(initialMs * 4 ** (attempt - 2), maxMs);
}

function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const t = setTimeout(done, ms);
    function done(): void {
      clearTimeout(t);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });
}

export class Upstream implements UpstreamPort {
  private live: Live | undefined;
  private connecting: Promise<Result<null>> | undefined;
  private closed = false;
  private readonly closing = new AbortController();
  private readonly listListeners = new Set<() => void>();
  private readonly lateListeners = new Set<(e: LateResponse) => void>();
  private gen = 0;

  private readonly log: Logger;
  private readonly redact: Redactor;
  private readonly maxAttempts: number;
  private readonly backoffInitialMs: number;
  private readonly backoffMaxMs: number;
  private readonly connectTimeoutMs: number;
  private readonly callTimeoutMs: number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;
  private readonly now: () => number;

  constructor(private readonly opts: UpstreamOptions) {
    this.log = opts.logger ?? (() => undefined);
    this.redact = opts.redact ?? noRedact;
    this.maxAttempts = Math.max(1, opts.maxAttempts ?? DEFAULT_RECONNECT_ATTEMPTS);
    this.backoffInitialMs = opts.backoffInitialMs ?? DEFAULT_BACKOFF_INITIAL_MS;
    this.backoffMaxMs = opts.backoffMaxMs ?? DEFAULT_BACKOFF_MAX_MS;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.callTimeoutMs = opts.callTimeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
    this.sleep = opts.sleep ?? defaultSleep;
    this.now = opts.now ?? Date.now;
  }

  get generation(): number {
    return this.gen;
  }

  isConnected(): boolean {
    return this.live !== undefined;
  }

  onToolListChanged(listener: () => void): () => void {
    this.listListeners.add(listener);
    return () => {
      this.listListeners.delete(listener);
    };
  }

  onLateResponse(listener: (e: LateResponse) => void): () => void {
    this.lateListeners.add(listener);
    return () => {
      this.lateListeners.delete(listener);
    };
  }

  /** Connect if not connected (bounded retries). Concurrent callers share the in-flight attempt. */
  connect(): Promise<Result<null>> {
    if (this.closed)
      return Promise.resolve(err("upstream.closed", "upstream connection is shut down"));
    if (this.live !== undefined) return Promise.resolve(ok(null));
    if (this.connecting === undefined) {
      this.connecting = this.connectWithRetry().finally(() => {
        this.connecting = undefined;
      });
    }
    return this.connecting;
  }

  private async connectWithRetry(): Promise<Result<null>> {
    let lastMessage = "no attempt made";
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      const delay = backoffDelayMs(attempt, this.backoffInitialMs, this.backoffMaxMs);
      if (delay > 0) await this.sleep(delay, this.closing.signal);
      if (this.closed) return err("upstream.closed", "upstream connection is shut down");
      const r = await this.connectOnce();
      if (r.ok) {
        this.log(`upstream connected (attempt ${String(attempt)}/${String(this.maxAttempts)})`);
        return ok(null);
      }
      lastMessage = r.error.message;
      this.log(
        `upstream connect attempt ${String(attempt)}/${String(this.maxAttempts)} failed: ${escapeForTerminal(lastMessage)}`,
      );
    }
    return err(
      "upstream.unavailable",
      `could not connect to the upstream Razorpay MCP server after ${String(this.maxAttempts)} attempts: ${lastMessage}`,
    );
  }

  private async connectOnce(): Promise<Result<null>> {
    let conn: UpstreamConnection;
    try {
      conn = this.opts.factory();
    } catch (e: unknown) {
      return err("upstream.connect_failed", this.safe(errorText(e)));
    }
    const client = new Client(this.opts.clientInfo ?? { name: "asf-proxy", version: "0.0.0" }, {
      capabilities: {},
    });
    const tap = new TappedTransport(conn.transport, this.now);
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      if (this.live?.client !== client) return;
      for (const l of [...this.listListeners]) l();
    });
    client.onerror = (e: Error) => {
      // NEVER log `e.message`: e.g. "Received a response for an unknown message ID: <full JSON response>".
      const d = tap.delivering;
      if (d !== undefined) {
        this.log(
          `upstream sent a response we no longer wait for (${describeTransportError(e, "late/unknown response id")})`,
        );
        this.emitLate(d, this.live?.client === client ? this.live.generation : this.gen);
        return;
      }
      this.log(`upstream ${describeTransportError(e)}`);
    };
    client.onclose = () => {
      if (this.live?.client !== client) return;
      this.live = undefined;
      if (!this.closed) this.log("upstream connection closed; will reconnect on next use");
      void conn.dispose();
    };
    try {
      await client.connect(tap, {
        timeout: this.connectTimeoutMs,
        signal: this.closing.signal,
      });
    } catch (e: unknown) {
      await this.discard(client, conn);
      const diag = conn.diagnostics?.() ?? "";
      if (diag.trim() !== "") this.log(`upstream diagnostics:\n${diag}`);
      return err("upstream.connect_failed", this.safe(errorText(e)));
    }
    if (this.closed) {
      await this.discard(client, conn);
      return err("upstream.closed", "upstream connection is shut down");
    }
    // Bump the generation in the same synchronous step that publishes the connection.
    this.gen++;
    this.live = { client, conn, tap, generation: this.gen };
    return ok(null);
  }

  private emitLate(d: Delivering, generation: number): void {
    const e: LateResponse = {
      requestId: d.id,
      tool: d.outbound?.tool,
      generation,
      sentAt: d.outbound?.sentAt,
      receivedAt: this.now(),
      responseType: d.responseType,
      isError: d.isError,
      failure: d.failure,
    };
    for (const l of [...this.lateListeners]) {
      try {
        l(e);
      } catch (err: unknown) {
        this.log(`late-response listener failed (${describeTransportError(err)})`);
      }
    }
  }

  private async discard(client: Client, conn: UpstreamConnection): Promise<void> {
    try {
      await client.close();
    } catch (e: unknown) {
      this.log(`closing upstream client failed: ${escapeForTerminal(this.safe(errorText(e)))}`);
    }
    await conn.dispose();
  }

  /** All pages of `tools/list`, validated (names, duplicates, pagination loops) like discovery. */
  async listTools(): Promise<Result<ListedTools>> {
    const c = await this.connect();
    if (!c.ok) return c;
    const live = this.live;
    if (live === undefined) return err("upstream.unavailable", "upstream connection was lost");
    let listSignal: AbortSignal | undefined;
    const lister: ToolLister = {
      listTools: (cursor) =>
        live.client.listTools(cursor === undefined ? undefined : { cursor }, {
          ...(listSignal === undefined ? {} : { signal: listSignal }),
          timeout: this.callTimeoutMs,
        }),
      serverInfo: () => {
        const v = live.client.getServerVersion();
        return v === undefined ? undefined : { name: v.name, version: v.version };
      },
      // The connection outlives the listing.
      close: () => Promise.resolve(),
    };
    const r = await discoverTools({
      connect: (signal) => {
        listSignal = signal;
        return Promise.resolve(lister);
      },
      timeoutMs: this.callTimeoutMs,
      signal: this.closing.signal,
    });
    if (!r.ok) return err("upstream.list_failed", this.safe(r.error.message));
    return ok({ tools: r.value.tools, generation: live.generation });
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
    opts: CallOptions = {},
  ): Promise<UpstreamCallOutcome> {
    if (opts.expectedGeneration === undefined) {
      const c = await this.connect();
      if (!c.ok) {
        return {
          kind: "error",
          error: "upstream_unavailable",
          message: c.error.message,
          forwarded: false,
        };
      }
    } else if (this.closed) {
      return {
        kind: "error",
        error: "upstream_unavailable",
        message: "upstream connection is shut down",
        forwarded: false,
      };
    }
    const live = this.live;
    if (live === undefined) {
      return {
        kind: "error",
        error: "upstream_unavailable",
        message: "upstream connection was lost before the call was sent",
        forwarded: false,
      };
    }
    if (opts.expectedGeneration !== undefined && live.generation !== opts.expectedGeneration) {
      return {
        kind: "error",
        error: "upstream_unavailable",
        message: "upstream reconnected since the tool list was checked; the call was not sent",
        forwarded: false,
      };
    }
    if (opts.signal?.aborted === true) {
      return {
        kind: "error",
        error: "cancelled",
        message: "call was cancelled by the client before it was sent",
        forwarded: false,
      };
    }
    const timeout = opts.timeoutMs ?? this.callTimeoutMs;
    live.tap.takeLastToolCall();
    const pending = live.client.request(
      { method: "tools/call", params: { name, arguments: args } },
      CallToolResultSchema,
      {
        ...(opts.signal === undefined ? {} : { signal: opts.signal }),
        timeout,
        maxTotalTimeout: timeout,
      },
    );
    // The SDK sends synchronously inside `request`; if that ever changes the id is simply unknown.
    const sent = live.tap.takeLastToolCall();
    const ids =
      sent !== undefined && sent.tool === name
        ? { requestId: sent.id, generation: live.generation }
        : { generation: live.generation };
    try {
      const result = await pending;
      return { kind: "ok", result };
    } catch (e: unknown) {
      return { ...this.classifyCallError(e, timeout, opts.signal), ...ids };
    }
  }

  private classifyCallError(
    e: unknown,
    timeoutMs: number,
    signal: AbortSignal | undefined,
  ): UpstreamCallOutcome {
    // First: the SDK reports an agent abort as McpError(RequestTimeout), which must not read as an upstream timeout.
    if (signal?.aborted === true) {
      return {
        kind: "error",
        error: "cancelled",
        message:
          "call was cancelled by the client after it was sent; the outcome is unknown — check the resource status before retrying",
        forwarded: true,
      };
    }
    if (e instanceof McpError && e.code === CODE_REQUEST_TIMEOUT) {
      return {
        kind: "error",
        error: "upstream_timeout",
        message: `upstream did not answer within ${String(timeoutMs)} ms; the outcome is unknown — check the resource status before retrying`,
        forwarded: true,
      };
    }
    if (e instanceof McpError && e.code === CODE_CONNECTION_CLOSED) {
      return {
        kind: "error",
        error: "upstream_error",
        message:
          "upstream connection closed during the call; the outcome is unknown — check the resource status before retrying",
        forwarded: true,
      };
    }
    return {
      kind: "error",
      error: "upstream_error",
      message: `upstream returned an error: ${this.safe(errorText(e))}`,
      forwarded: true,
    };
  }

  /** Close the client and dispose the connection (docker rm -f). Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.closing.abort();
    const pending = this.connecting;
    if (pending !== undefined) await pending;
    const live = this.live;
    this.live = undefined;
    if (live !== undefined) await this.discard(live.client, live.conn);
  }

  private safe(text: string): string {
    return capLength(this.redact(text));
  }
}

function capLength(s: string): string {
  return s.length > MAX_MESSAGE_CHARS ? `${s.slice(0, MAX_MESSAGE_CHARS)}…` : s;
}

// ---------------------------------------------------------------------------------------------------------------
// Docker transport (production)
// ---------------------------------------------------------------------------------------------------------------

const UPSTREAM_CONTAINER_NAME = /^asf-upstream-[a-f0-9]{8,32}$/;

/** `asf-upstream-<hex>`; `hex` must be 8–32 lowercase hex chars. */
export function upstreamContainerName(hex: string): Result<string> {
  const name = `asf-upstream-${hex}`;
  return UPSTREAM_CONTAINER_NAME.test(name)
    ? ok(name)
    : err("upstream.bad_container_name", "container name suffix must be 8-32 lowercase hex chars");
}

/**
 * Hardened `docker run` argv for the live upstream. Same hardening as discovery (D-018) EXCEPT the network: the
 * server must reach the Razorpay test API, so there is no `--network none`.
 * - `-e NAME` (no `=value`): the real keys are copied from docker's (child) environment, never put in argv / `ps`.
 * - `--pull=never`: the human `docker pull`s the pinned image; nothing is fetched implicitly.
 * - `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--init`, `--rm`, `--name` for cleanup.
 * - `--memory 512m`, `--pids-limit 256`; `--user 65534:65534` (nobody; verified: the pinned image lists its tools
 *   as this user).
 * Caveat: the image's entrypoint passes the keys to the server as `--key/--secret` argv INSIDE the container, so they
 * are visible in the host's process list and via `docker inspect` to anyone with docker access (see the docs).
 */
export function upstreamDockerRunArgs(image: string, containerName: string): string[] {
  if (!UPSTREAM_CONTAINER_NAME.test(containerName)) {
    throw new Error("upstreamDockerRunArgs: invalid container name");
  }
  return [
    "run",
    "-i",
    "--rm",
    "--init",
    "--name",
    containerName,
    "--pull=never",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "512m",
    "--pids-limit",
    "256",
    "--user",
    "65534:65534",
    "-e",
    "RAZORPAY_KEY_ID",
    "-e",
    "RAZORPAY_KEY_SECRET",
    image,
  ];
}

export function upstreamDockerRmArgs(containerName: string): string[] {
  if (!UPSTREAM_CONTAINER_NAME.test(containerName)) {
    throw new Error("upstreamDockerRmArgs: invalid container name");
  }
  return ["rm", "-f", containerName];
}

/** Bounded `docker rm -f`. Never throws; "no such container" is success; docker's stderr is never echoed. */
export function removeUpstreamContainer(
  name: string,
  env: Readonly<Record<string, string>>,
): Promise<Result<null>> {
  return new Promise((done) => {
    let args: string[];
    try {
      args = upstreamDockerRmArgs(name);
    } catch (e: unknown) {
      done(err("upstream.cleanup_failed", `container cleanup refused: ${errorText(e)}`));
      return;
    }
    execFile(
      "docker",
      args,
      { env: { ...env }, timeout: DOCKER_RM_TIMEOUT_MS },
      (error, _o, stderr) => {
        if (error === null || /no such container|already in progress/i.test(stderr))
          return done(ok(null));
        done(
          err(
            "upstream.cleanup_failed",
            `docker rm -f ${name} failed (${error.killed ? "timed out" : `exit ${String(error.code)}`})`,
          ),
        );
      },
    );
  });
}

const STDERR_TAIL_CHARS = 4_000;
const STDERR_TAIL_LINES = 20;

/**
 * Last lines of upstream stderr for diagnostics: redacted, terminal-escaped, line- and length-capped. Upstream stderr
 * is NOT streamed to the log (it may contain request data); it is only shown when connecting fails.
 */
export function formatStderrTail(raw: string, redact: Redactor): string {
  const tail = raw.length > STDERR_TAIL_CHARS ? raw.slice(-STDERR_TAIL_CHARS) : raw;
  const lines = redact(tail)
    .split("\n")
    .filter((l) => l.trim() !== "")
    .slice(-STDERR_TAIL_LINES)
    .map((l) => `  ${escapeForTerminal(l)}`);
  if (/no such image|unable to find image/i.test(tail)) {
    lines.push(
      "  hint: the image is not present locally (runs with --pull=never): docker pull <image>",
    );
  }
  return lines.join("\n");
}

export interface DockerUpstreamOptions {
  readonly image: string;
  /** Full child env incl. RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET (see `buildChildEnv`). */
  readonly childEnv: Readonly<Record<string, string>>;
  /** Env for `docker rm -f` (no Razorpay keys). */
  readonly dockerEnv: Readonly<Record<string, string>>;
  readonly randomHex: () => string;
  readonly redact: Redactor;
  readonly logger: Logger;
  /** Injected for tests. */
  readonly removeContainer?: (
    name: string,
    env: Readonly<Record<string, string>>,
  ) => Promise<Result<null>>;
}

/** Spawn description for one attempt; exported for tests (argv carries names only, never values). */
export interface DockerSpawn {
  readonly command: "docker";
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly containerName: string;
}

export function dockerSpawnFor(
  opts: Pick<DockerUpstreamOptions, "image" | "childEnv" | "randomHex">,
): DockerSpawn {
  const name = upstreamContainerName(opts.randomHex());
  if (!name.ok) throw new Error(name.error.message);
  return {
    command: "docker",
    args: upstreamDockerRunArgs(opts.image, name.value),
    env: { ...opts.childEnv },
    containerName: name.value,
  };
}

/** Production factory: each attempt spawns a fresh hardened container and force-removes it on dispose. */
export function dockerUpstreamFactory(opts: DockerUpstreamOptions): UpstreamTransportFactory {
  const remove = opts.removeContainer ?? removeUpstreamContainer;
  return () => {
    const spawn = dockerSpawnFor(opts);
    let stderrBuf = "";
    const transport = new StdioClientTransport({
      command: spawn.command,
      args: [...spawn.args],
      env: { ...spawn.env },
      stderr: "pipe",
    });
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      stderrBuf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (stderrBuf.length > STDERR_TAIL_CHARS * 4)
        stderrBuf = stderrBuf.slice(-STDERR_TAIL_CHARS * 2);
    });
    let disposed = false;
    return {
      transport,
      diagnostics: () => formatStderrTail(stderrBuf, opts.redact),
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        try {
          await transport.close();
        } catch (e: unknown) {
          opts.logger(
            `closing upstream transport failed: ${escapeForTerminal(opts.redact(errorText(e)))}`,
          );
        }
        const r = await remove(spawn.containerName, opts.dockerEnv);
        if (!r.ok) {
          opts.logger(
            `warning: ${escapeForTerminal(r.error.message)} (remove it manually: docker rm -f ${spawn.containerName})`,
          );
        }
      },
    };
  };
}
