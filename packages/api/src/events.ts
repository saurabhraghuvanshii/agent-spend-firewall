/**
 * Live events for `GET /events` (T013): while at least one client is connected, poll the audit log for records after
 * the last seen seq and the pending-approval set, and fan them out. Polling (not hooks into the money path) keeps the
 * API strictly read-only towards the pipeline; a mode change is itself an audit `mode` record, so it arrives as an
 * `audit` event too.
 *
 * Bounded: at most `maxSubscribers` listeners (more ⇒ `err`), at most `pageRows` records per poll, and the timer only
 * runs while someone listens. A read failure is reported once per failure streak as an `error` event (never as an
 * empty success).
 */
import { err, ok, type Result } from "@asf/core";
import type { ApprovalsPort, AuditPort } from "./ports.js";
import { recordView, type RecordView } from "./views.js";

export type ApiEvent =
  | { readonly type: "audit"; readonly records: RecordView[] }
  | { readonly type: "approvals"; readonly pending: string[] }
  | { readonly type: "error"; readonly code: string }
  | { readonly type: "close" };

export interface Ticker {
  start(fn: () => void, ms: number): () => void;
}

export const systemTicker: Ticker = {
  start(fn, ms) {
    const h = setInterval(fn, ms);
    h.unref();
    return () => {
      clearInterval(h);
    };
  },
};

export interface EventHubOptions {
  readonly audit: Pick<AuditPort, "readPage">;
  readonly approvals?: Pick<ApprovalsPort, "listPending">;
  readonly maxSubscribers: number;
  /** Default 1000 ms. */
  readonly intervalMs?: number;
  /** Default 200. */
  readonly pageRows?: number;
  readonly ticker?: Ticker;
  readonly logger?: (line: string) => void;
}

export interface EventHub {
  /** `err` `api.too_many_streams` when full. The returned function unsubscribes (idempotent). */
  subscribe(listener: (e: ApiEvent) => void): Result<() => void>;
  /** One poll now (the timer calls it; the API calls it after a mutation so clients see it at once). */
  poll(): void;
  readonly size: number;
  /** Send `close` to everyone and stop. */
  close(): void;
}

export function createEventHub(o: EventHubOptions): EventHub {
  const listeners = new Set<(e: ApiEvent) => void>();
  const ticker = o.ticker ?? systemTicker;
  const intervalMs = o.intervalMs ?? 1000;
  const pageRows = o.pageRows ?? 200;
  const log = o.logger ?? (() => undefined);
  let stop: (() => void) | undefined;
  let lastSeq: number | undefined;
  let lastPending: string | undefined;
  let failing = false;
  let closed = false;

  const emit = (e: ApiEvent): void => {
    for (const l of [...listeners]) {
      try {
        l(e);
      } catch (x: unknown) {
        log(`event listener threw ${x instanceof Error ? x.name : typeof x}`);
        listeners.delete(l);
      }
    }
  };

  const fail = (code: string): void => {
    if (!failing) emit({ type: "error", code });
    failing = true;
  };

  const pollAudit = (): boolean => {
    if (lastSeq === undefined) {
      const head = o.audit.readPage({ limit: 1 });
      if (!head.ok) {
        fail(head.error.code);
        return false;
      }
      lastSeq = head.value[0]?.seq ?? 0;
      return true;
    }
    const page = o.audit.readPage({ afterSeq: lastSeq, limit: pageRows });
    if (!page.ok) {
      fail(page.error.code);
      return false;
    }
    if (page.value.length > 0) {
      lastSeq = Math.max(lastSeq, ...page.value.map((r) => r.seq));
      emit({ type: "audit", records: page.value.map(recordView) });
    }
    return true;
  };

  const pollApprovals = (): boolean => {
    if (o.approvals === undefined) return true;
    const rows = o.approvals.listPending(1000);
    if (!rows.ok) {
      fail(rows.error.code);
      return false;
    }
    const ids = rows.value.map((r) => r.approvalId).sort();
    const sig = ids.join(",");
    if (lastPending !== undefined && sig !== lastPending) emit({ type: "approvals", pending: ids });
    lastPending = sig;
    return true;
  };

  const poll = (): void => {
    if (closed || listeners.size === 0) return;
    let healthy: boolean;
    try {
      const a = pollAudit();
      const b = pollApprovals();
      healthy = a && b;
    } catch (e: unknown) {
      log(`event poll threw ${e instanceof Error ? e.name : typeof e}`);
      fail("api.internal_error");
      healthy = false;
    }
    if (healthy) failing = false;
  };

  return {
    subscribe(listener) {
      if (closed) return err("api.closed", "the API is shutting down");
      if (listeners.size >= o.maxSubscribers) {
        return err("api.too_many_streams", "too many open event streams");
      }
      listeners.add(listener);
      if (stop === undefined) {
        // Baseline (head seq, pending set) so a new stream only gets what happens from now on.
        lastSeq = undefined;
        lastPending = undefined;
        poll();
        stop = ticker.start(poll, intervalMs);
      }
      let done = false;
      return ok(() => {
        if (done) return;
        done = true;
        listeners.delete(listener);
        if (listeners.size === 0 && stop !== undefined) {
          stop();
          stop = undefined;
        }
      });
    },
    poll,
    get size() {
      return listeners.size;
    },
    close() {
      if (closed) return;
      emit({ type: "close" });
      closed = true;
      listeners.clear();
      stop?.();
      stop = undefined;
    },
  };
}
