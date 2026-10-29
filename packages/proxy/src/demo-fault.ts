/**
 * DEMO-ONLY fault injection (T015, D-039): delay the FIRST `create_refund` response from upstream.
 *
 * Roadmap demo scenario 3 needs a real "upstream timeout mid-refund" against Razorpay TEST mode. Razorpay can't be
 * asked to be slow, so this wraps the upstream TRANSPORT: the `tools/call` request is sent at once (the refund
 * really happens upstream), but the matching response is held back for `ASF_DEMO_DELAY_REFUND_MS` before it is
 * handed to the MCP client. With a delay longer than `ASF_MONEY_CALL_TIMEOUT_MS` the firewall's money call times
 * out, the late answer is attributed by `TappedTransport` like any real late response, and T010 verify-before-retry
 * runs for real (marker lookup ⇒ `verifiedAfterTimeout`, never a blind retry).
 *
 * Constraints:
 * - Enabled ONLY by the SHELL env var `ASF_DEMO_DELAY_REFUND_MS` (never `.env`), integer ms 1000..120000; any other
 *   value ⇒ the proxy refuses to start (exit 2). Unset / empty ⇒ disabled (no wrapper at all).
 * - Affects exactly ONE response per proxy process: the first `create_refund` request ever sent (across reconnects).
 *   If sending that request fails (the transport rejects it), the fault is re-armed for the next one.
 *   Every other message passes through untouched and in order.
 * - Nothing is read from or logged about the message bodies.
 * - A delayed response whose transport closes before the delay ends is dropped (the connection is gone anyway).
 */
import { err, ok, type Result } from "@asf/core";
import type {
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  isJSONRPCErrorResponse,
  isJSONRPCRequest,
  isJSONRPCResultResponse,
  type JSONRPCMessage,
  type MessageExtraInfo,
  type RequestId,
} from "@modelcontextprotocol/sdk/types.js";
import type { UpstreamTransportFactory } from "./upstream.js";

export const DEMO_DELAY_ENV = "ASF_DEMO_DELAY_REFUND_MS";
export const MIN_DEMO_DELAY_MS = 1_000;
export const MAX_DEMO_DELAY_MS = 120_000;
/** The only tool whose response is ever delayed. */
export const DEMO_DELAYED_TOOL = "create_refund";

/** `ASF_DEMO_DELAY_REFUND_MS`: unset / empty ⇒ `ok(undefined)` (disabled); else an integer in range or `err`. */
export function parseDemoDelayMs(raw: string | undefined): Result<number | undefined> {
  if (raw === undefined || raw === "") return ok(undefined);
  if (!/^[0-9]{1,9}$/.test(raw)) {
    return err(
      "proxy.bad_demo_delay",
      `${DEMO_DELAY_ENV} must be an integer number of milliseconds`,
    );
  }
  const n = Number(raw);
  if (n < MIN_DEMO_DELAY_MS || n > MAX_DEMO_DELAY_MS) {
    return err(
      "proxy.bad_demo_delay",
      `${DEMO_DELAY_ENV} must be between ${String(MIN_DEMO_DELAY_MS)} and ${String(MAX_DEMO_DELAY_MS)}`,
    );
  }
  return ok(n);
}

/**
 * Loud startup warning lines (stderr). `moneyCallTimeoutMs` tells whether the delay will actually cause a timeout;
 * `verifyWaitMs` whether the late answer arrives while the firewall is still waiting for it (after the money call
 * times out, verify-before-retry waits up to `verifyWaitMs` for it). A delay past BOTH misses the verify window, so a
 * refund that Razorpay rejected can't be proven not executed: the outcome is `unknown` and flagged for a human.
 */
export function demoFaultWarnings(
  delayMs: number,
  moneyCallTimeoutMs: number,
  verifyWaitMs: number,
): string[] {
  const lines = [
    `WARNING: DEMO FAULT INJECTION IS ON (${DEMO_DELAY_ENV}=${String(delayMs)}): the FIRST ${DEMO_DELAYED_TOOL} response from Razorpay will be delayed ${String(delayMs)} ms (the refund itself is sent at once). For demos only; unset it for real use.`,
  ];
  if (delayMs <= moneyCallTimeoutMs) {
    lines.push(
      `WARNING: ${DEMO_DELAY_ENV} (${String(delayMs)} ms) is not longer than ASF_MONEY_CALL_TIMEOUT_MS (${String(moneyCallTimeoutMs)} ms): the delayed refund will be slow but will NOT time out`,
    );
  } else if (delayMs > moneyCallTimeoutMs + verifyWaitMs) {
    lines.push(
      `WARNING: ${DEMO_DELAY_ENV} (${String(delayMs)} ms) is longer than ASF_MONEY_CALL_TIMEOUT_MS + ASF_VERIFY_WAIT_MS (${String(moneyCallTimeoutMs)} + ${String(verifyWaitMs)} ms): the late answer will MISS THE VERIFY WINDOW, so the refund's outcome can only be decided from the refund list; if that can't prove it, the outcome is UNKNOWN and flagged for a human. Use a delay between the two for the demo`,
    );
  }
  return lines;
}

export interface DemoFaultOptions {
  readonly delayMs: number;
  /** Injected for tests. Must return a cancel function. */
  readonly schedule?: (fn: () => void, ms: number) => () => void;
  /** Called once when the delayed response is held (no payload). */
  readonly onDelayed?: () => void;
}

function defaultSchedule(fn: () => void, ms: number): () => void {
  const t = setTimeout(fn, ms);
  return () => {
    clearTimeout(t);
  };
}

/** Shared across every connection the factory creates: the fault fires at most once per process. */
interface FaultState {
  armed: boolean;
}

class DelayFirstRefundTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;
  private target: RequestId | undefined;
  private readonly pending = new Set<() => void>();
  private closed = false;

  constructor(
    private readonly inner: Transport,
    private readonly state: FaultState,
    private readonly opts: DemoFaultOptions,
  ) {
    inner.onclose = () => {
      this.closed = true;
      for (const cancel of this.pending) cancel();
      this.pending.clear();
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

  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }

  send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    if (
      this.state.armed &&
      isJSONRPCRequest(message) &&
      message.method === "tools/call" &&
      message.params !== undefined &&
      message.params["name"] === DEMO_DELAYED_TOOL
    ) {
      this.state.armed = false;
      this.target = message.id;
      const id = message.id;
      // The request may never have left (send rejected): re-arm so the fault still fires on a later refund.
      return this.inner.send(message, options).catch((e: unknown) => {
        if (this.target === id) {
          this.target = undefined;
          this.state.armed = true;
        }
        throw e;
      });
    }
    return this.inner.send(message, options);
  }

  private receive(message: JSONRPCMessage, extra: MessageExtraInfo | undefined): void {
    const target = this.target;
    if (
      target !== undefined &&
      (isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) &&
      message.id === target
    ) {
      this.target = undefined;
      this.opts.onDelayed?.();
      const cancel = (this.opts.schedule ?? defaultSchedule)(() => {
        this.pending.delete(cancel);
        if (!this.closed) this.onmessage?.(message, extra);
      }, this.opts.delayMs);
      this.pending.add(cancel);
      return;
    }
    this.onmessage?.(message, extra);
  }
}

/**
 * Wrap an upstream transport factory so the first `create_refund` response (process-wide) arrives `delayMs` late.
 * The request itself is never delayed or altered.
 */
export function demoFaultFactory(
  inner: UpstreamTransportFactory,
  opts: DemoFaultOptions,
): UpstreamTransportFactory {
  if (
    !Number.isSafeInteger(opts.delayMs) ||
    opts.delayMs < MIN_DEMO_DELAY_MS ||
    opts.delayMs > MAX_DEMO_DELAY_MS
  ) {
    throw new Error("demoFaultFactory: delayMs out of range");
  }
  const state: FaultState = { armed: true };
  return () => {
    const conn = inner();
    const diagnostics = conn.diagnostics?.bind(conn);
    return {
      transport: new DelayFirstRefundTransport(conn.transport, state, opts),
      dispose: () => conn.dispose(),
      ...(diagnostics === undefined ? {} : { diagnostics }),
    };
  };
}
