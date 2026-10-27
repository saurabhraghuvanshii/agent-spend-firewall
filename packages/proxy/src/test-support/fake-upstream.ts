/**
 * Test-only fake of the Razorpay MCP server: a low-level SDK `Server` over `InMemoryTransport`, plus a transport
 * factory for `Upstream` that can be made to fail, and helpers to drop the connection. Not part of the build.
 */
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolRequestSchema,
  isJSONRPCRequest,
  LATEST_PROTOCOL_VERSION,
  ListToolsRequestSchema,
  type CallToolResult,
  type JSONRPCMessage,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { UpstreamTransportFactory } from "../upstream.js";

export const FAKE_TOOLS: Tool[] = [
  {
    name: "fetch_payment",
    description: "Fetch a payment by id",
    inputSchema: {
      type: "object",
      properties: { payment_id: { type: "string", description: "pay_ id" } },
      required: ["payment_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "create_refund",
    description: "Create a refund",
    inputSchema: {
      type: "object",
      properties: {
        payment_id: { type: "string" },
        amount: { type: "number", description: "paise" },
        notes: { type: "object", additionalProperties: { type: "string" } },
      },
      required: ["payment_id", "amount"],
    },
  },
  {
    name: "fetch_all_payments",
    description: "List payments",
    inputSchema: { type: "object", properties: { count: { type: "number" } } },
  },
];

export interface ReceivedCall {
  readonly name: string;
  readonly args: Record<string, unknown> | undefined;
}

export type FakeHandler = (
  name: string,
  args: Record<string, unknown> | undefined,
  signal: AbortSignal,
) => Promise<CallToolResult>;

export interface FakeUpstream {
  readonly factory: UpstreamTransportFactory;
  readonly calls: ReceivedCall[];
  /** Number of factory invocations (connection attempts). */
  attempts(): number;
  /** Number of `dispose()` calls on connections. */
  disposed(): number;
  /** When true, every new connection attempt fails. */
  setFailing(failing: boolean): void;
  setTools(tools: Tool[]): void;
  /** When true, `tools/list` fails (connecting still works). */
  setListFailing(failing: boolean): void;
  setHandler(handler: FakeHandler): void;
  /** Drop the current connection from the server side (like the container dying). */
  dropConnection(): Promise<void>;
  /** Send `notifications/tools/list_changed` from the current server. */
  notifyListChanged(): Promise<void>;
  /** Page size for `tools/list` (cursor-based pagination). */
  setPageSize(n: number): void;
}

const echo: FakeHandler = (name, args) =>
  Promise.resolve({
    content: [{ type: "text", text: JSON.stringify({ tool: name, args: args ?? {} }) }],
  });

/** A transport whose `start` rejects, like a docker process that fails to spawn. */
export function deadTransport(): Transport {
  return {
    start: () => Promise.reject(new Error("spawn docker ENOENT")),
    send: () => Promise.reject(new Error("not connected")),
    close: () => Promise.resolve(),
  };
}

export function fakeUpstream(
  initial: { tools?: Tool[]; handler?: FakeHandler } = {},
): FakeUpstream {
  let tools = initial.tools ?? FAKE_TOOLS;
  let handler = initial.handler ?? echo;
  let failing = false;
  let listFailing = false;
  let attempts = 0;
  let disposed = 0;
  let pageSize = 1000;
  let current: { server: Server; transport: InMemoryTransport } | undefined;
  const calls: ReceivedCall[] = [];

  const factory: UpstreamTransportFactory = () => {
    attempts++;
    if (failing) return { transport: deadTransport(), dispose: () => Promise.resolve() };
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const server = new Server(
      { name: "razorpay-mcp-server", version: "1.0.0" },
      { capabilities: { tools: { listChanged: true } } },
    );
    server.setRequestHandler(ListToolsRequestSchema, (req) => {
      if (listFailing) throw new Error("tools/list failed");
      const start = req.params?.cursor === undefined ? 0 : Number(req.params.cursor);
      const page = tools.slice(start, start + pageSize);
      const next = start + pageSize;
      return next < tools.length ? { tools: page, nextCursor: String(next) } : { tools: page };
    });
    server.setRequestHandler(CallToolRequestSchema, (req, extra) => {
      calls.push({ name: req.params.name, args: req.params.arguments });
      return handler(req.params.name, req.params.arguments, extra.signal);
    });
    const ready = server.connect(serverSide);
    current = { server, transport: serverSide };
    // `server.connect` only starts the in-memory transport (synchronous in practice); surface failures loudly.
    ready.catch((e: unknown) => {
      throw e;
    });
    return {
      transport: clientSide,
      dispose: async () => {
        disposed++;
        await clientSide.close();
      },
    };
  };

  return {
    factory,
    calls,
    attempts: () => attempts,
    disposed: () => disposed,
    setFailing: (f) => {
      failing = f;
    },
    setTools: (t) => {
      tools = t;
    },
    setListFailing: (f) => {
      listFailing = f;
    },
    setHandler: (h) => {
      handler = h;
    },
    setPageSize: (n) => {
      pageSize = n;
    },
    dropConnection: async () => {
      const c = current;
      current = undefined;
      if (c !== undefined) await c.transport.close();
    },
    notifyListChanged: async () => {
      if (current !== undefined) await current.server.sendToolListChanged();
    },
  };
}

/** Never resolves until `signal` aborts (then rejects), for timeout tests. */
export function hang(signal: AbortSignal): Promise<CallToolResult> {
  return new Promise((_resolve, reject) => {
    signal.addEventListener(
      "abort",
      () => {
        reject(new Error("aborted"));
      },
      { once: true },
    );
  });
}

export function textOf(result: unknown): string {
  if (typeof result !== "object" || result === null || !("content" in result)) return "";
  const content = result.content;
  if (!Array.isArray(content)) return "";
  const first: unknown = content[0];
  if (typeof first !== "object" || first === null || !("text" in first)) return "";
  const text = first.text;
  return typeof text === "string" ? text : "";
}

export function jsonOf(result: unknown): Record<string, unknown> {
  const parsed: unknown = JSON.parse(textOf(result));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("result body is not a JSON object");
  }
  return parsed as Record<string, unknown>;
}

export interface LateUpstream {
  readonly factory: UpstreamTransportFactory;
  /** Ids of `tools/call` requests received. */
  readonly callIds: (string | number)[];
  /** Deliver an error to the CLIENT side transport's `onerror` (like a stdio parse error). */
  emitClientError(e: Error): void;
}

/**
 * Raw JSON-RPC fake (no SDK Server): answers `tools/call` after `delayMs` with `result`, IGNORING cancellation —
 * like a real server whose work completed after the client gave up. Used to provoke the SDK's "unknown message ID".
 */
export function lateUpstream(opts: { delayMs: number; result: CallToolResult }): LateUpstream {
  const callIds: (string | number)[] = [];
  let client: InMemoryTransport | undefined;
  const factory: UpstreamTransportFactory = () => {
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    client = clientSide;
    const reply = (m: JSONRPCMessage): void => {
      void serverSide.send(m);
    };
    serverSide.onmessage = (m) => {
      if (!isJSONRPCRequest(m)) return;
      if (m.method === "initialize") {
        reply({
          jsonrpc: "2.0",
          id: m.id,
          result: {
            protocolVersion: LATEST_PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: "late-fake", version: "1.0.0" },
          },
        });
      } else if (m.method === "tools/list") {
        reply({ jsonrpc: "2.0", id: m.id, result: { tools: FAKE_TOOLS } });
      } else if (m.method === "tools/call") {
        callIds.push(m.id);
        setTimeout(() => {
          reply({ jsonrpc: "2.0", id: m.id, result: { ...opts.result } });
        }, opts.delayMs);
      }
    };
    void serverSide.start();
    return {
      transport: clientSide,
      dispose: async () => {
        await clientSide.close();
      },
    };
  };
  return {
    factory,
    callIds,
    emitClientError: (e) => {
      client?.onerror?.(e);
    },
  };
}

/** What a scripted upstream does with one `tools/call`. */
export interface ScriptedReply {
  /** Answer after this many ms (default 0). */
  readonly delayMs?: number;
  /** JSON-RPC result (a `CallToolResult`). */
  readonly result?: CallToolResult;
  /** JSON-RPC error response instead of a result. */
  readonly error?: { readonly code: number; readonly message: string };
  /** Never answer. */
  readonly never?: true;
}

export type ScriptedHandler = (name: string, args: Record<string, unknown>) => ScriptedReply;

export interface ScriptedUpstream {
  readonly factory: UpstreamTransportFactory;
  readonly calls: ReceivedCall[];
  /** Number of `notifications/cancelled` received. */
  cancellations(): number;
  setHandler(h: ScriptedHandler): void;
}

/**
 * Raw JSON-RPC fake (no SDK Server) for T010: answers each `tools/call` as the handler scripts it — possibly AFTER the
 * client gave up, and IGNORING `notifications/cancelled` (like a Razorpay call that completed or failed late).
 */
export function scriptedUpstream(opts: {
  readonly tools: Tool[];
  readonly handler: ScriptedHandler;
}): ScriptedUpstream {
  let handler = opts.handler;
  let cancellations = 0;
  const calls: ReceivedCall[] = [];
  const factory: UpstreamTransportFactory = () => {
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const reply = (m: JSONRPCMessage): void => {
      void serverSide.send(m).catch(() => undefined);
    };
    serverSide.onmessage = (m) => {
      if (!isJSONRPCRequest(m)) {
        if ("method" in m && m.method === "notifications/cancelled") cancellations++;
        return;
      }
      if (m.method === "initialize") {
        reply({
          jsonrpc: "2.0",
          id: m.id,
          result: {
            protocolVersion: LATEST_PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: "scripted-fake", version: "1.0.0" },
          },
        });
      } else if (m.method === "tools/list") {
        reply({ jsonrpc: "2.0", id: m.id, result: { tools: opts.tools } });
      } else if (m.method === "tools/call") {
        const params = m.params ?? {};
        const name = typeof params["name"] === "string" ? params["name"] : "";
        const rawArgs: unknown = params["arguments"];
        const args =
          typeof rawArgs === "object" && rawArgs !== null && !Array.isArray(rawArgs)
            ? (rawArgs as Record<string, unknown>)
            : {};
        calls.push({ name, args });
        const r = handler(name, args);
        if (r.never === true) return;
        const send = (): void => {
          if (r.error !== undefined) reply({ jsonrpc: "2.0", id: m.id, error: { ...r.error } });
          else reply({ jsonrpc: "2.0", id: m.id, result: { ...(r.result ?? { content: [] }) } });
        };
        if ((r.delayMs ?? 0) <= 0) send();
        else setTimeout(send, r.delayMs);
      }
    };
    void serverSide.start();
    return {
      transport: clientSide,
      dispose: async () => {
        await clientSide.close();
      },
    };
  };
  return {
    factory,
    calls,
    cancellations: () => cancellations,
    setHandler: (h) => {
      handler = h;
    },
  };
}
