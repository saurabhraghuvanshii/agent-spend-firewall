import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import {
  assertNoSecrets,
  buildChildEnv,
  buildToolsFile,
  checkTestKeys,
  DEFAULT_RAZORPAY_MCP_IMAGE,
  DISCOVERY_PLACEHOLDER_KEYS,
  discoverTools,
  discoveryContainerName,
  dockerRmArgs,
  dockerRunArgs,
  listerFromClient,
  redactSecrets,
  renderToolsFile,
  secretVariants,
  toolsFileSchema,
  validateImageRef,
  type ConnectLister,
  type ToolLister,
} from "./tool-discovery.js";

const KEY_ID = "rzp_test_AbC123xyz";
const KEY_SECRET = "s3cr3tValue_DoNotPrint";
const KEYS = { keyId: KEY_ID, keySecret: KEY_SECRET };

interface FakeTool {
  name: string;
  description?: string;
  inputSchema: { type: "object"; properties?: Record<string, object>; required?: string[] };
}

function tool(name: string, extra: Partial<FakeTool> = {}): FakeTool {
  return {
    name,
    description: `desc ${name}`,
    inputSchema: { type: "object", properties: {} },
    ...extra,
  };
}

/** A real MCP server + client pair over the SDK's in-memory transport, paginated by `pages`. */
function inMemoryUpstream(pages: Record<string, { tools: FakeTool[]; nextCursor?: string }>): {
  connect: ConnectLister;
  closed: () => boolean;
} {
  let closed = false;
  const connect: ConnectLister = async (signal) => {
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const server = new Server(
      { name: "fake-razorpay", version: "9.9.9" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, (req) => {
      const page = pages[req.params?.cursor ?? ""];
      if (page === undefined) throw new Error("unknown cursor");
      return page.nextCursor === undefined
        ? { tools: page.tools }
        : { tools: page.tools, nextCursor: page.nextCursor };
    });
    await server.connect(serverT);
    const client = new Client({ name: "test", version: "0.0.0" });
    await client.connect(clientT);
    const inner = listerFromClient(client, signal);
    return {
      listTools: (c) => inner.listTools(c),
      serverInfo: () => inner.serverInfo(),
      close: async () => {
        closed = true;
        await inner.close();
        await server.close();
      },
    };
  };
  return { connect, closed: () => closed };
}

function fakeLister(
  pages: unknown[],
  info: unknown = { name: "s", version: "1" },
): {
  connect: ConnectLister;
  closed: () => boolean;
  calls: (string | undefined)[];
} {
  let closed = false;
  const calls: (string | undefined)[] = [];
  const lister: ToolLister = {
    listTools: (cursor) => {
      calls.push(cursor);
      return Promise.resolve(pages[calls.length - 1]);
    },
    serverInfo: () => info as { name: string; version: string },
    close: () => {
      closed = true;
      return Promise.resolve();
    },
  };
  return { connect: () => Promise.resolve(lister), closed: () => closed, calls };
}

describe("checkTestKeys", () => {
  it("accepts rzp_test_ keys with a secret", () => {
    const r = checkTestKeys({ RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: KEY_SECRET });
    expect(r).toEqual({ ok: true, value: KEYS });
  });

  it.each([
    ["missing", undefined, "discover.missing_key_id"],
    ["empty", "", "discover.missing_key_id"],
    ["live", "rzp_live_AbC123", "discover.live_key"],
    ["rzp_testX", "rzp_testX123", "discover.not_test_key"],
    ["bare prefix", "rzp_test_", "discover.not_test_key"],
    ["trailing space", "rzp_test_abc ", "discover.not_test_key"],
    ["newline", "rzp_test_abc\nx", "discover.not_test_key"],
    ["uppercase", "RZP_TEST_abc", "discover.not_test_key"],
  ])("refuses a %s key id", (_label, keyId, code) => {
    const r = checkTestKeys({ RAZORPAY_KEY_ID: keyId, RAZORPAY_KEY_SECRET: KEY_SECRET });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe(code);
      // The bare prefix legitimately appears in the help text; every other value must not be echoed.
      if (keyId !== undefined && keyId !== "" && keyId !== "rzp_test_") {
        expect(r.error.message).not.toContain(keyId);
      }
      expect(r.error.message).not.toContain(KEY_SECRET);
    }
  });

  it("refuses a missing or empty secret", () => {
    for (const secret of [undefined, ""]) {
      const r = checkTestKeys({ RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: secret });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("discover.missing_key_secret");
        expect(r.error.message).not.toContain(KEY_ID);
      }
    }
  });

  it("refuses a live key in ANY environment variable, naming the variable but not the value", () => {
    const live = "rzp_live_Zz9";
    const r = checkTestKeys({
      RAZORPAY_KEY_ID: KEY_ID,
      RAZORPAY_KEY_SECRET: KEY_SECRET,
      OTHER_RAZORPAY_KEY: `prefix-${live}`,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("discover.live_key");
      expect(r.error.message).toContain("OTHER_RAZORPAY_KEY");
      expect(r.error.message).not.toContain(live);
      expect(r.error.message).not.toContain(KEY_SECRET);
    }
  });

  it.each(["RZP_LIVE_Abc", "Rzp_Live_x", "token=rZp_LiVe_9"])(
    "live-key check is case-insensitive (%s)",
    (value) => {
      const r = checkTestKeys({
        RAZORPAY_KEY_ID: KEY_ID,
        RAZORPAY_KEY_SECRET: KEY_SECRET,
        X: value,
      });
      expect(r.ok ? "ok" : r.error.code).toBe("discover.live_key");
      if (!r.ok) expect(r.error.message).not.toContain(value);
    },
  );

  it("placeholder keys are themselves valid TEST keys", () => {
    expect(
      checkTestKeys({
        RAZORPAY_KEY_ID: DISCOVERY_PLACEHOLDER_KEYS.keyId,
        RAZORPAY_KEY_SECRET: DISCOVERY_PLACEHOLDER_KEYS.keySecret,
      }).ok,
    ).toBe(true);
  });

  it("does not echo a weird variable name", () => {
    const r = checkTestKeys({ "X\u001b[2J": "rzp_live_1" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).not.toContain("\u001b");
  });
});

describe("docker invocation", () => {
  const NAME = "asf-discover-0123456789abcdef";

  it("hardened argv; passes variable NAMES only, never values; image last", () => {
    const args = dockerRunArgs("razorpay/mcp", NAME);
    expect(args).toEqual([
      "run",
      "-i",
      "--rm",
      "--name",
      NAME,
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
      "razorpay/mcp",
    ]);
    expect(args.filter((a) => a.includes("=") && a !== "--pull=never")).toEqual([]);
    expect(args.at(-1)).toBe("razorpay/mcp");
  });

  it("default image is pinned by digest and valid", () => {
    expect(DEFAULT_RAZORPAY_MCP_IMAGE).toMatch(/^razorpay\/mcp@sha256:[a-f0-9]{64}$/);
    expect(validateImageRef(DEFAULT_RAZORPAY_MCP_IMAGE).ok).toBe(true);
  });

  it("container names: asf-discover-<8..32 hex>, validated everywhere", () => {
    expect(discoveryContainerName("0123456789abcdef")).toEqual({ ok: true, value: NAME });
    for (const bad of ["", "abc", "XYZ12345", "01234567;rm", "0".repeat(33), "--privileged"]) {
      expect(discoveryContainerName(bad).ok, bad).toBe(false);
    }
    expect(dockerRmArgs(NAME)).toEqual(["rm", "-f", NAME]);
    expect(() => dockerRmArgs("--all")).toThrow();
    expect(() => dockerRunArgs("razorpay/mcp", "other-name")).toThrow();
  });

  it("validates the image reference", () => {
    for (const ok of [
      "razorpay/mcp",
      "razorpay/mcp:latest",
      `razorpay/mcp@sha256:${"a".repeat(64)}`,
      "ghcr.io/x/y:1.2",
    ]) {
      expect(validateImageRef(ok).ok, ok).toBe(true);
    }
    for (const bad of [
      "--privileged",
      "-v",
      "",
      "razorpay/mcp;rm -rf /",
      "razorpay/mcp latest",
      "a\nb",
      "Razorpay/MCP",
    ]) {
      expect(validateImageRef(bad).ok, bad).toBe(false);
    }
  });

  it("child env is the SDK default set + shell DOCKER_* + the two (placeholder) Razorpay keys only", () => {
    const env = buildChildEnv(
      { PATH: "/usr/bin", HOME: "/home/u", RAZORPAY_KEY_ID: "stale" },
      {
        PATH: "/evil",
        DOCKER_HOST: "unix:///run/docker.sock",
        DOCKER_CONTEXT: "",
        ANTHROPIC_API_KEY: "sk-ant-x",
        TELEGRAM_BOT_TOKEN: "t",
        RAZORPAY_KEY_ID: KEY_ID,
        RAZORPAY_KEY_SECRET: KEY_SECRET,
        RAZORPAY_OTHER: "x",
      },
      DISCOVERY_PLACEHOLDER_KEYS,
    );
    expect(env).toEqual({
      PATH: "/usr/bin",
      HOME: "/home/u",
      DOCKER_HOST: "unix:///run/docker.sock",
      RAZORPAY_KEY_ID: DISCOVERY_PLACEHOLDER_KEYS.keyId,
      RAZORPAY_KEY_SECRET: DISCOVERY_PLACEHOLDER_KEYS.keySecret,
    });
    expect(Object.values(env)).not.toContain(KEY_SECRET);
    expect(Object.values(env)).not.toContain(KEY_ID);
  });
});

describe("discoverTools over a real MCP client/server (in-memory)", () => {
  it("lists, paginates and sorts tools by name", async () => {
    const up = inMemoryUpstream({
      "": { tools: [tool("fetch_payment"), tool("create_refund")], nextCursor: "p2" },
      p2: { tools: [tool("capture_payment")] },
    });
    const r = await discoverTools({ connect: up.connect, timeoutMs: 5000 });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.server).toEqual({ name: "fake-razorpay", version: "9.9.9" });
    expect(r.value.tools.map((t) => t.name)).toEqual([
      "capture_payment",
      "create_refund",
      "fetch_payment",
    ]);
    expect(r.value.tools[1]?.description).toBe("desc create_refund");
    expect(up.closed()).toBe(true);
  });

  it("duplicate names across pages ⇒ error", async () => {
    const up = inMemoryUpstream({
      "": { tools: [tool("create_refund")], nextCursor: "p2" },
      p2: { tools: [tool("create_refund")] },
    });
    const r = await discoverTools({ connect: up.connect, timeoutMs: 5000 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.duplicate_tool");
    expect(up.closed()).toBe(true);
  });

  it("empty list ⇒ error", async () => {
    const up = inMemoryUpstream({ "": { tools: [] } });
    const r = await discoverTools({ connect: up.connect, timeoutMs: 5000 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.empty");
  });

  it("server error on a page ⇒ list_failed", async () => {
    const up = inMemoryUpstream({ "": { tools: [tool("a")], nextCursor: "missing" } });
    const r = await discoverTools({ connect: up.connect, timeoutMs: 5000 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.list_failed");
    expect(up.closed()).toBe(true);
  });
});

describe("discoverTools failure paths", () => {
  const page = (names: string[], nextCursor?: string): unknown => ({
    tools: names.map((n) => tool(n)),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });

  it.each<[string, unknown]>([
    ["not an object", "nope"],
    ["tools missing", {}],
    ["tool without name", { tools: [{ inputSchema: { type: "object" } }] }],
    ["bad tool name", { tools: [tool("bad name")] }],
    ["inputSchema not object type", { tools: [{ name: "a", inputSchema: { type: "array" } }] }],
    ["numeric cursor", { tools: [tool("a")], nextCursor: 3 }],
  ])("malformed page (%s) ⇒ malformed_list", async (_l, raw) => {
    const f = fakeLister([raw]);
    const r = await discoverTools({ connect: f.connect, timeoutMs: 5000 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.malformed_list");
    expect(f.closed()).toBe(true);
  });

  it("malformed serverInfo ⇒ error", async () => {
    const f = fakeLister([page(["a"])], null);
    const r = await discoverTools({ connect: f.connect, timeoutMs: 5000 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.malformed_server_info");
  });

  it("repeated cursor ⇒ pagination_loop", async () => {
    const f = fakeLister([page(["a"], "c1"), page(["b"], "c2"), page(["c"], "c1")]);
    const r = await discoverTools({ connect: f.connect, timeoutMs: 5000 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.pagination_loop");
  });

  it("too many pages ⇒ error", async () => {
    const pages = Array.from({ length: 10 }, (_, i) => page([`t${String(i)}`], `c${String(i)}`));
    const f = fakeLister(pages);
    const r = await discoverTools({ connect: f.connect, timeoutMs: 5000, maxPages: 3 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.too_many_pages");
    expect(f.calls).toHaveLength(3);
  });

  it("connect throws ⇒ connect_failed", async () => {
    const r = await discoverTools({
      connect: () => Promise.reject(new Error("spawn docker ENOENT")),
      timeoutMs: 5000,
    });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.connect_failed");
    if (!r.ok) expect(r.error.message).toContain("ENOENT");
  });

  it("hung listTools ⇒ timeout, lister closed, signal aborted", async () => {
    let closed = false;
    let aborted = false;
    const connect: ConnectLister = (signal) => {
      signal.addEventListener("abort", () => {
        aborted = true;
      });
      return Promise.resolve({
        listTools: () => new Promise<unknown>(() => undefined),
        serverInfo: () => ({ name: "s", version: "1" }),
        close: () => {
          closed = true;
          return Promise.resolve();
        },
      });
    };
    const r = await discoverTools({ connect, timeoutMs: 30 });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.timeout");
    expect(closed).toBe(true);
    expect(aborted).toBe(true);
  });

  it("hung connect ⇒ timeout; a late lister is still closed", async () => {
    let resolveConnect: ((l: ToolLister) => void) | undefined;
    let closed = false;
    const connect: ConnectLister = () =>
      new Promise<ToolLister>((res) => {
        resolveConnect = res;
      });
    let fire: (() => void) | undefined;
    const r = await Promise.all([
      discoverTools({
        connect,
        timeoutMs: 1,
        setTimer: (fn) => {
          fire = fn;
          return () => undefined;
        },
      }),
      Promise.resolve().then(() => fire?.()),
    ]);
    expect(r[0].ok ? "ok" : r[0].error.code).toBe("discover.timeout");
    resolveConnect?.({
      listTools: () => Promise.resolve(page(["a"])),
      serverInfo: () => ({ name: "s", version: "1" }),
      close: () => {
        closed = true;
        return Promise.resolve();
      },
    });
    await new Promise((res) => setTimeout(res, 10));
    expect(closed).toBe(true);
  });

  it("external abort ⇒ discover.aborted, lister closed, inner signal aborted", async () => {
    let closed = false;
    let innerAborted = false;
    const ext = new AbortController();
    const connect: ConnectLister = (signal) => {
      signal.addEventListener("abort", () => {
        innerAborted = true;
      });
      return Promise.resolve({
        listTools: () => {
          ext.abort();
          return new Promise<unknown>(() => undefined);
        },
        serverInfo: () => ({ name: "s", version: "1" }),
        close: () => {
          closed = true;
          return Promise.resolve();
        },
      });
    };
    const r = await discoverTools({ connect, timeoutMs: 60_000, signal: ext.signal });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.aborted");
    expect(closed).toBe(true);
    expect(innerAborted).toBe(true);
  });

  it("already-aborted signal ⇒ discover.aborted without listing", async () => {
    const f = fakeLister([page(["a"])]);
    const ext = new AbortController();
    ext.abort();
    const r = await discoverTools({ connect: f.connect, timeoutMs: 60_000, signal: ext.signal });
    expect(r.ok ? "ok" : r.error.code).toBe("discover.aborted");
    expect(f.calls).toEqual([]);
  });

  it("close() failing does not change the result", async () => {
    const f = fakeLister([page(["a"])]);
    const connect: ConnectLister = async (s) => {
      const l = await f.connect(s);
      return { ...l, close: () => Promise.reject(new Error("boom")) };
    };
    const r = await discoverTools({ connect, timeoutMs: 5000 });
    expect(r.ok).toBe(true);
  });
});

describe("rendering", () => {
  const discovery = {
    server: { name: "razorpay-mcp-server", version: "1.0.0" },
    tools: [
      {
        name: "create_refund",
        description: "d",
        inputSchema: { type: "object", required: ["payment_id"], properties: { z: {}, a: {} } },
        annotations: { readOnlyHint: false },
      },
    ],
  };

  it("sorts keys recursively, 2-space indent, trailing newline, schema-valid", () => {
    const file = buildToolsFile({
      discovery,
      image: "razorpay/mcp",
      imageDigest: `razorpay/mcp@sha256:${"b".repeat(64)}`,
      discoveredAt: new Date("2026-10-23T00:00:00.000Z"),
    });
    const text = renderToolsFile(file);
    expect(text.endsWith("}\n")).toBe(true);
    expect(text.startsWith('{\n  "discoveredAt"')).toBe(true);
    expect(text.indexOf('"a"')).toBeLessThan(text.indexOf('"z"'));
    expect(toolsFileSchema.safeParse(JSON.parse(text)).success).toBe(true);
  });

  it("omits imageDigest when unknown", () => {
    const file = buildToolsFile({
      discovery,
      image: "razorpay/mcp",
      imageDigest: undefined,
      discoveredAt: new Date(0),
    });
    expect("imageDigest" in file).toBe(false);
  });

  it("keeps a __proto__ key from upstream as plain data", () => {
    const evil = JSON.parse(
      '{"type":"object","properties":{"__proto__":{"polluted":true}}}',
    ) as Record<string, unknown>;
    const file = buildToolsFile({
      discovery: {
        server: discovery.server,
        tools: [{ name: "x", description: "", inputSchema: evil }],
      },
      image: "razorpay/mcp",
      imageDigest: undefined,
      discoveredAt: new Date(0),
    });
    const text = renderToolsFile(file);
    expect(text).toContain('"__proto__"');
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  it("assertNoSecrets refuses output containing the key id or secret", () => {
    expect(assertNoSecrets("{}", KEYS).ok).toBe(true);
    expect(assertNoSecrets(`{"d":"${KEY_ID}"}`, KEYS).ok).toBe(false);
    const r = assertNoSecrets(`{"d":"x${KEY_SECRET}"}`, KEYS);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).not.toContain(KEY_SECRET);
    const quoteSecret = { keyId: KEY_ID, keySecret: 'ab"cd' };
    expect(assertNoSecrets(JSON.stringify({ d: 'ab"cd' }), quoteSecret).ok).toBe(false);
  });

  const basicStd = Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString("base64");
  const weird = { keyId: "rzp_test_W1", keySecret: "s/e+c=r?e t&" };
  const weirdBasic = Buffer.from(`${weird.keyId}:${weird.keySecret}`);

  it.each<[string, string, typeof KEYS]>([
    ["basic auth header (base64 id:secret)", `Authorization: Basic ${basicStd}`, KEYS],
    ["base64 without padding", basicStd.replace(/=+$/, ""), KEYS],
    ["base64url form", weirdBasic.toString("base64url"), weird],
    ["base64 std form (+ and /)", weirdBasic.toString("base64"), weird],
    ["URI-encoded secret", `?s=${encodeURIComponent(weird.keySecret)}`, weird],
    ["URI-encoded id", encodeURIComponent(weird.keyId), weird],
  ])("assertNoSecrets catches the %s", (_l, text, keys) => {
    expect(assertNoSecrets(JSON.stringify({ d: text }), keys).ok).toBe(false);
  });

  it("secretVariants: no empties, longest first, base64 only when both parts are set", () => {
    const v = secretVariants(KEYS);
    expect(v).not.toContain("");
    expect([...v].sort((a, b) => b.length - a.length)).toEqual(v);
    expect(v).toContain(basicStd.replace(/=+$/, ""));
    expect(secretVariants({ keyId: KEY_ID, keySecret: "" })).toEqual([KEY_ID]);
  });

  it("redactSecrets replaces every occurrence of every form", () => {
    expect(redactSecrets(`a ${KEY_SECRET} b ${KEY_SECRET} ${KEY_ID}`, KEYS)).toBe(
      "a [REDACTED] b [REDACTED] [REDACTED]",
    );
    const out = redactSecrets(
      `Basic ${weirdBasic.toString("base64")} q=${encodeURIComponent(weird.keySecret)}`,
      weird,
    );
    expect(out).toBe("Basic [REDACTED] q=[REDACTED]");
    expect(redactSecrets("nothing here", { keyId: "", keySecret: "" })).toBe("nothing here");
  });
});
