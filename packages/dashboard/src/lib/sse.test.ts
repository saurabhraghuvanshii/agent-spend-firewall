import { describe, expect, it, vi } from "vitest";
import {
  backoffDelay,
  createSseParser,
  runEventStream,
  type SseEvent,
  type StreamStatus,
} from "./sse";
import { TOKEN } from "../test/fixtures";

function parseAll(chunks: string[]): SseEvent[] {
  const out: SseEvent[] = [];
  const p = createSseParser((e) => out.push(e));
  for (const c of chunks) p.feed(c);
  return out;
}

const STREAM = 'event: ready\ndata: {"type":"ready"}\n\nevent: audit\ndata: {"a":1}\n\n';

describe("createSseParser", () => {
  it("parses whole events", () => {
    expect(parseAll([STREAM])).toEqual([
      { event: "ready", data: '{"type":"ready"}' },
      { event: "audit", data: '{"a":1}' },
    ]);
  });

  it("gives the same result for every possible two-way chunk split", () => {
    const whole = parseAll([STREAM]);
    for (let i = 1; i < STREAM.length; i++) {
      expect(parseAll([STREAM.slice(0, i), STREAM.slice(i)])).toEqual(whole);
    }
  });

  it("handles one character per chunk", () => {
    expect(parseAll([...STREAM])).toEqual(parseAll([STREAM]));
  });

  it("handles CRLF and CR line endings, including a CRLF split across chunks", () => {
    const crlf = STREAM.replaceAll("\n", "\r\n");
    expect(parseAll([crlf])).toEqual(parseAll([STREAM]));
    expect(parseAll([STREAM.replaceAll("\n", "\r")])).toEqual(parseAll([STREAM]));
    const cut = crlf.indexOf("\r\n") + 1;
    expect(parseAll([crlf.slice(0, cut), crlf.slice(cut)])).toEqual(parseAll([STREAM]));
  });

  it("joins multi-line data, ignores comments, defaults the event name, keeps ids", () => {
    expect(parseAll([": hi\nid: 7\ndata: a\ndata:b\n\n"])).toEqual([
      { event: "message", data: "a\nb", id: "7" },
    ]);
  });

  it("does not dispatch an event without data", () => {
    expect(parseAll(["event: ping\n\n"])).toEqual([]);
  });

  it("throws on an unbounded line", () => {
    const p = createSseParser(() => undefined);
    expect(() => {
      p.feed("data: " + "x".repeat(1_000_001));
    }).toThrow(/too long/);
  });
});

function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(c) {
      for (const x of chunks) c.enqueue(x);
      c.close();
    },
  });
}

describe("runEventStream", () => {
  it("sends the token as a header (never in the URL), decodes split UTF-8 and reconnects with backoff", async () => {
    const ctrl = new AbortController();
    const bytes = new TextEncoder().encode('event: ready\ndata: {}\n\nevent: audit\ndata: "₹"\n\n');
    const rupee = Array.from(bytes).findIndex((b) => b === 0xe2);
    const fetchImpl = vi.fn((url: string, init: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:8787/events");
      expect(url).not.toContain(TOKEN);
      expect((init.headers as Record<string, string>)["x-admin-token"]).toBe(TOKEN);
      return Promise.resolve(
        new Response(streamOf([bytes.slice(0, rupee + 1), bytes.slice(rupee + 1)]), {
          status: 200,
        }),
      );
    });
    const events: SseEvent[] = [];
    const statuses: StreamStatus[] = [];
    const sleeps: number[] = [];
    await runEventStream({
      url: "http://127.0.0.1:8787/events",
      token: TOKEN,
      signal: ctrl.signal,
      fetchImpl,
      onEvent: (e) => events.push(e),
      onStatus: (s) => statuses.push(s),
      sleep: (ms) => {
        sleeps.push(ms);
        if (sleeps.length === 2) ctrl.abort();
        return Promise.resolve();
      },
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(events.filter((e) => e.event === "audit").map((e) => e.data)).toEqual(['"₹"', '"₹"']);
    // `ready` resets the backoff each time, so both reconnects wait the initial delay.
    expect(sleeps).toEqual([1000, 1000]);
    expect(statuses.map((s) => s.state)).toContain("open");
    expect(statuses.at(-1)).toEqual({ state: "stopped" });
  });

  it("backs off exponentially on repeated failures, capped", async () => {
    const ctrl = new AbortController();
    const sleeps: number[] = [];
    await runEventStream({
      url: "http://x/events",
      token: TOKEN,
      signal: ctrl.signal,
      fetchImpl: () => Promise.reject(new TypeError("Failed to fetch")),
      onEvent: () => undefined,
      onStatus: () => undefined,
      backoff: { initialMs: 100, maxMs: 500 },
      sleep: (ms) => {
        sleeps.push(ms);
        if (sleeps.length === 5) ctrl.abort();
        return Promise.resolve();
      },
    });
    expect(sleeps).toEqual([100, 200, 400, 500, 500]);
    expect(backoffDelay(3, { initialMs: 1000, maxMs: 30_000 })).toBe(8000);
  });

  it("stops for good on 401 (needs a new token)", async () => {
    const statuses: StreamStatus[] = [];
    const fetchImpl = vi.fn(() => Promise.resolve(new Response("{}", { status: 401 })));
    await runEventStream({
      url: "http://x/events",
      token: TOKEN,
      signal: new AbortController().signal,
      fetchImpl,
      onEvent: () => undefined,
      onStatus: (s) => statuses.push(s),
      sleep: () => Promise.reject(new Error("must not retry")),
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(statuses.at(-1)).toEqual({ state: "unauthorized", status: 401 });
  });

  it("retries a 503 (too many streams) and stops promptly when aborted mid-stream", async () => {
    const ctrl = new AbortController();
    let calls = 0;
    const fetchImpl = vi.fn((_u: string, init: RequestInit) => {
      calls += 1;
      if (calls === 1) return Promise.resolve(new Response("{}", { status: 503 }));
      // Open stream that never ends; abort while reading.
      // Like a real fetch body: errors with AbortError when the request signal aborts.
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new TextEncoder().encode("event: ready\ndata: {}\n\n"));
          init.signal?.addEventListener("abort", () => {
            c.error(new DOMException("aborted", "AbortError"));
          });
        },
      });
      return Promise.resolve(new Response(body, { status: 200 }));
    });
    const statuses: StreamStatus[] = [];
    const done = runEventStream({
      url: "http://x/events",
      token: TOKEN,
      signal: ctrl.signal,
      fetchImpl,
      onEvent: (e) => {
        if (e.event === "ready") ctrl.abort();
      },
      onStatus: (s) => statuses.push(s),
      sleep: () => Promise.resolve(),
    });
    await done;
    expect(calls).toBe(2);
    expect(statuses).toContainEqual({ state: "reconnecting", delayMs: 1000, reason: "HTTP 503" });
    expect(statuses.at(-1)).toEqual({ state: "stopped" });
  });
});
