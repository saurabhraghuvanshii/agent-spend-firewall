/**
 * Server-Sent Events over `fetch` streaming. `EventSource` cannot send the `x-admin-token` header and the API never
 * accepts the token in the URL (D-036), so the stream is read with a `ReadableStream` reader and parsed here.
 *
 * - `createSseParser`: incremental parser (WHATWG event-stream rules) that copes with any chunk split: mid-line,
 *   mid-field, between `\r` and `\n`. Bounded: a line over `MAX_LINE_CHARS` throws (the connection is dropped).
 * - `runEventStream`: connect → read → on end / error reconnect with exponential backoff, until aborted. 401 / 403
 *   stop for good (a new token is needed); a successful `ready` event resets the backoff.
 */
import { ADMIN_TOKEN_HEADER, type FetchLike } from "../api/client";

export interface SseEvent {
  readonly event: string;
  readonly data: string;
  readonly id?: string;
}

export const MAX_LINE_CHARS = 1_000_000;
/** Cap on one event's total data (sum of its `data:` lines); beyond it the connection is dropped. */
export const MAX_EVENT_CHARS = 2_000_000;

export interface SseParser {
  feed(chunk: string): void;
}

export function createSseParser(onEvent: (e: SseEvent) => void): SseParser {
  let buf = "";
  let skipLeadingLf = false;
  let data: string[] = [];
  let dataChars = 0;
  let event = "";
  let id: string | undefined;
  let lastId: string | undefined;

  const dispatch = (): void => {
    if (id !== undefined) lastId = id;
    if (data.length > 0) {
      onEvent({
        event: event === "" ? "message" : event,
        data: data.join("\n"),
        ...(lastId === undefined ? {} : { id: lastId }),
      });
    }
    data = [];
    dataChars = 0;
    event = "";
    id = undefined;
  };

  const line = (l: string): void => {
    if (l === "") {
      dispatch();
      return;
    }
    if (l.startsWith(":")) return; // comment
    const colon = l.indexOf(":");
    const field = colon === -1 ? l : l.slice(0, colon);
    let value = colon === -1 ? "" : l.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "data":
        dataChars += value.length + 1;
        if (dataChars > MAX_EVENT_CHARS) {
          data = [];
          dataChars = 0;
          throw new Error("event stream event too large");
        }
        data.push(value);
        break;
      case "event":
        event = value;
        break;
      case "id":
        if (!value.includes("\u0000")) id = value;
        break;
      default:
      // `retry` and unknown fields are ignored (reconnect timing is ours).
    }
  };

  return {
    feed(chunk) {
      let c = chunk;
      if (skipLeadingLf && c.startsWith("\n")) c = c.slice(1);
      if (c !== "") skipLeadingLf = false;
      buf += c;
      const re = /\r\n|\r|\n/g;
      let last = 0;
      for (let m = re.exec(buf); m !== null; m = re.exec(buf)) {
        line(buf.slice(last, m.index));
        last = re.lastIndex;
        // A `\r` at the very end may be the first half of a `\r\n` split across chunks.
        if (m[0] === "\r" && last === buf.length) skipLeadingLf = true;
      }
      buf = buf.slice(last);
      if (buf.length > MAX_LINE_CHARS) {
        buf = "";
        throw new Error("event stream line too long");
      }
    },
  };
}

export type StreamStatus =
  | { readonly state: "connecting" }
  | { readonly state: "open" }
  | { readonly state: "reconnecting"; readonly delayMs: number; readonly reason: string }
  | { readonly state: "unauthorized"; readonly status: number }
  | { readonly state: "stopped" };

export interface Backoff {
  readonly initialMs: number;
  readonly maxMs: number;
}

export const DEFAULT_BACKOFF: Backoff = { initialMs: 1000, maxMs: 30_000 };

/** `initialMs · 2^attempt`, capped at `maxMs`. */
export function backoffDelay(attempt: number, b: Backoff = DEFAULT_BACKOFF): number {
  return Math.min(b.maxMs, b.initialMs * 2 ** Math.min(attempt, 30));
}

/** Resolves after `ms` or as soon as `signal` aborts. */
export function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const t = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(t);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export interface EventStreamOptions {
  readonly url: string;
  readonly token: string;
  readonly signal: AbortSignal;
  readonly onEvent: (e: SseEvent) => void;
  readonly onStatus: (s: StreamStatus) => void;
  readonly fetchImpl?: FetchLike;
  readonly backoff?: Backoff;
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

const reasonOf = (e: unknown): string => (e instanceof Error ? e.message : "connection failed");

export async function runEventStream(o: EventStreamOptions): Promise<void> {
  const fetchImpl: FetchLike = o.fetchImpl ?? ((input, init) => fetch(input, init));
  const sleep = o.sleep ?? abortableSleep;
  let attempt = 0;
  while (!o.signal.aborted) {
    o.onStatus({ state: "connecting" });
    let reason: string;
    try {
      const res = await fetchImpl(o.url, {
        method: "GET",
        headers: { [ADMIN_TOKEN_HEADER]: o.token, accept: "text/event-stream" },
        signal: o.signal,
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        redirect: "error",
      });
      if (res.status === 401 || res.status === 403) {
        await res.body?.cancel();
        o.onStatus({ state: "unauthorized", status: res.status });
        return;
      }
      if (!res.ok || res.body === null) {
        await res.body?.cancel();
        reason = `HTTP ${String(res.status)}`;
      } else {
        const parser = createSseParser((e) => {
          if (e.event === "ready") {
            attempt = 0;
            o.onStatus({ state: "open" });
          }
          o.onEvent(e);
        });
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            parser.feed(decoder.decode(value, { stream: true }));
          }
          parser.feed(decoder.decode());
        } catch (e: unknown) {
          // Drop the connection (e.g. a line over the limit); a cancel failure is reported, then the read error wins.
          await reader.cancel().catch((x: unknown) => {
            console.warn(`asf: could not cancel the event stream (${reasonOf(x)})`);
          });
          throw e;
        }
        reason = "stream ended";
      }
    } catch (e: unknown) {
      if (o.signal.aborted) break;
      reason = reasonOf(e);
    }
    if (o.signal.aborted) break;
    const delayMs = backoffDelay(attempt, o.backoff);
    attempt += 1;
    o.onStatus({ state: "reconnecting", delayMs, reason });
    await sleep(delayMs, o.signal);
  }
  o.onStatus({ state: "stopped" });
}
