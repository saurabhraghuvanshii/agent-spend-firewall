import { afterEach, describe, expect, it, vi } from "vitest";
import { ok } from "@asf/core";
import {
  fakeUpstream,
  hang,
  lateUpstream,
  scriptedUpstream,
  type ScriptedReply,
} from "./test-support/fake-upstream.js";
import { DEFAULT_RAZORPAY_MCP_IMAGE, redactSecrets } from "./tool-discovery.js";
import {
  backoffDelayMs,
  describeTransportError,
  dockerSpawnFor,
  dockerUpstreamFactory,
  formatStderrTail,
  responseFailure,
  Upstream,
  upstreamContainerName,
  upstreamDockerRmArgs,
  upstreamDockerRunArgs,
  type LateResponse,
  type Redactor,
} from "./upstream.js";

const KEYS = { keyId: "rzp_test_Key123", keySecret: "TopSecretValue987" };
const redact: Redactor = (s) => redactSecrets(s, KEYS);
const HEX = "00112233aabbccdd";
const NAME = `asf-upstream-${HEX}`;

const open: Upstream[] = [];
afterEach(async () => {
  for (const u of open.splice(0)) await u.close();
});

function make(fake = fakeUpstream(), extra: { callTimeoutMs?: number; maxAttempts?: number } = {}) {
  const sleeps: number[] = [];
  const logs: string[] = [];
  const u = new Upstream({
    factory: fake.factory,
    redact,
    logger: (l) => logs.push(l),
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    ...extra,
  });
  open.push(u);
  return { u, fake, sleeps, logs };
}

describe("docker invocation", () => {
  it("container names are asf-upstream-<8..32 hex>", () => {
    expect(upstreamContainerName(HEX)).toEqual(ok(NAME));
    for (const bad of ["", "XYZ", "0011", "00112233aabbccdd; rm -rf /", "0".repeat(33)]) {
      expect(upstreamContainerName(bad).ok).toBe(false);
    }
  });

  it("argv is hardened, passes keys by name only, and keeps the network", () => {
    const args = upstreamDockerRunArgs(DEFAULT_RAZORPAY_MCP_IMAGE, NAME);
    expect(args).toEqual([
      "run",
      "-i",
      "--rm",
      "--init",
      "--name",
      NAME,
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
      DEFAULT_RAZORPAY_MCP_IMAGE,
    ]);
    expect(args).not.toContain("--network");
    expect(args.some((a) => a.includes("="))).toBe(args.includes("--pull=never")); // only the pull flag has '='
    expect(args.at(-1)).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    expect(() =>
      upstreamDockerRunArgs(DEFAULT_RAZORPAY_MCP_IMAGE, "asf-discover-00112233"),
    ).toThrow();
    expect(upstreamDockerRmArgs(NAME)).toEqual(["rm", "-f", NAME]);
    expect(() => upstreamDockerRmArgs("other")).toThrow();
  });

  it("the spawn carries real keys only in the child env, never in argv", () => {
    const childEnv = {
      PATH: "/usr/bin",
      RAZORPAY_KEY_ID: KEYS.keyId,
      RAZORPAY_KEY_SECRET: KEYS.keySecret,
    };
    const spawn = dockerSpawnFor({
      image: DEFAULT_RAZORPAY_MCP_IMAGE,
      childEnv,
      randomHex: () => HEX,
    });
    expect(spawn.command).toBe("docker");
    expect(spawn.containerName).toBe(NAME);
    expect(spawn.env).toEqual(childEnv);
    const argv = spawn.args.join(" ");
    expect(argv).not.toContain(KEYS.keyId);
    expect(argv).not.toContain(KEYS.keySecret);
    expect(() =>
      dockerSpawnFor({ image: DEFAULT_RAZORPAY_MCP_IMAGE, childEnv, randomHex: () => "nothex" }),
    ).toThrow();
  });

  it("dispose force-removes the container (with the key-free docker env), once", async () => {
    const removed: { name: string; env: Readonly<Record<string, string>> }[] = [];
    const factory = dockerUpstreamFactory({
      image: DEFAULT_RAZORPAY_MCP_IMAGE,
      childEnv: {
        PATH: "/usr/bin",
        RAZORPAY_KEY_ID: KEYS.keyId,
        RAZORPAY_KEY_SECRET: KEYS.keySecret,
      },
      dockerEnv: { PATH: "/usr/bin" },
      randomHex: () => HEX,
      redact,
      logger: () => undefined,
      removeContainer: (name, env) => {
        removed.push({ name, env });
        return Promise.resolve(ok(null));
      },
    });
    const conn = factory(); // the transport is created but not started: nothing is spawned
    await conn.dispose();
    await conn.dispose();
    expect(removed).toEqual([{ name: NAME, env: { PATH: "/usr/bin" } }]);
  });

  it("stderr tail is redacted, escaped, capped, and hints at a missing image", () => {
    const basic = Buffer.from(`${KEYS.keyId}:${KEYS.keySecret}`).toString("base64");
    const raw = [
      ...Array.from({ length: 30 }, (_, i) => `line ${String(i)}`),
      `auth ${KEYS.keyId} ${basic}`,
      "evil \u001b[2J",
      "Unable to find image 'razorpay/mcp' locally",
    ].join("\n");
    const out = formatStderrTail(raw, redact);
    expect(out).not.toContain(KEYS.keyId);
    expect(out).not.toContain(basic);
    expect(out).toContain("[REDACTED]");
    expect(out).not.toContain("\u001b");
    expect(out).toContain("\\u001b[2J");
    expect(out).not.toContain("line 0\n");
    expect(out).toMatch(/hint: .*docker pull/);
  });
});

describe("backoff", () => {
  it("is 0, 250, 1000, 2000, 2000 … (bounded)", () => {
    expect([1, 2, 3, 4, 5].map((n) => backoffDelayMs(n, 250, 2000))).toEqual([
      0, 250, 1000, 2000, 2000,
    ]);
  });
});

describe("Upstream", () => {
  it("connect retries with backoff and reports exhaustion without secrets", async () => {
    const fake = fakeUpstream();
    fake.setFailing(true);
    const { u, sleeps, logs } = make(fake);
    const r = await u.connect();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("upstream.unavailable");
      expect(r.error.message).toMatch(/after 3 attempts/);
    }
    expect(fake.attempts()).toBe(3);
    expect(sleeps).toEqual([250, 1000]);
    expect(logs.join("\n")).not.toContain(KEYS.keySecret);
  });

  it("succeeds on a later attempt", async () => {
    const fake = fakeUpstream();
    const failing = { n: 0 };
    const factory = () => {
      failing.n++;
      fake.setFailing(failing.n < 2);
      return fake.factory();
    };
    const sleeps: number[] = [];
    const u = new Upstream({
      factory,
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    });
    open.push(u);
    expect((await u.connect()).ok).toBe(true);
    expect(sleeps).toEqual([250]);
    expect(u.generation).toBe(1);
  });

  it("concurrent callers share one connection attempt", async () => {
    const { u, fake } = make();
    const [a, b] = await Promise.all([u.connect(), u.connect()]);
    expect(a.ok && b.ok).toBe(true);
    expect(fake.attempts()).toBe(1);
  });

  it("a factory that throws counts as a failed attempt", async () => {
    const u = new Upstream({
      factory: () => {
        throw new Error(`spawn failed ${KEYS.keySecret}`);
      },
      redact,
      maxAttempts: 1,
    });
    open.push(u);
    const r = await u.connect();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).not.toContain(KEYS.keySecret);
  });

  it("listTools returns every page, validated and sorted", async () => {
    const fake = fakeUpstream();
    fake.setPageSize(1);
    const { u } = make(fake);
    const r = await u.listTools();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.tools.map((t) => t.name)).toEqual([
        "create_refund",
        "fetch_all_payments",
        "fetch_payment",
      ]);
      expect(r.value.generation).toBe(1);
    }
  });

  it("listTools rejects a malformed upstream list (duplicate names)", async () => {
    const fake = fakeUpstream({
      tools: [
        { name: "fetch_payment", inputSchema: { type: "object" } },
        { name: "fetch_payment", inputSchema: { type: "object" } },
      ],
    });
    const { u } = make(fake);
    const r = await u.listTools();
    expect(r.ok).toBe(false);
  });

  it("callTool timeout ⇒ upstream_timeout, forwarded", async () => {
    const fake = fakeUpstream({ handler: (_n, _a, signal) => hang(signal) });
    const { u } = make(fake);
    const r = await u.callTool("fetch_payment", { payment_id: "pay_1" }, { timeoutMs: 30 });
    expect(r).toMatchObject({ kind: "error", error: "upstream_timeout", forwarded: true });
  });

  it("callTool with an already-aborted signal is not sent ⇒ cancelled, not forwarded", async () => {
    const { u, fake } = make();
    const c = new AbortController();
    c.abort();
    const r = await u.callTool("fetch_payment", {}, { signal: c.signal });
    expect(r).toMatchObject({ kind: "error", error: "cancelled", forwarded: false });
    expect(fake.calls).toEqual([]);
  });

  it("agent cancellation mid-call ⇒ cancelled (forwarded), not upstream_timeout", async () => {
    const fake = fakeUpstream({ handler: (_n, _a, signal) => hang(signal) });
    const { u } = make(fake);
    const c = new AbortController();
    const p = u.callTool(
      "create_refund",
      { payment_id: "pay_1", amount: 100 },
      { signal: c.signal },
    );
    await vi.waitFor(() => {
      expect(fake.calls).toHaveLength(1);
    });
    c.abort();
    const r = await p;
    expect(r).toMatchObject({ kind: "error", error: "cancelled", forwarded: true });
    if (r.kind === "error") expect(r.message).toMatch(/check the resource status/);
  });

  it("expectedGeneration: a different or missing connection ⇒ not sent and no reconnect", async () => {
    const { u, fake } = make();
    await u.connect();
    const wrong = await u.callTool("fetch_payment", {}, { expectedGeneration: 7 });
    expect(wrong).toMatchObject({ kind: "error", error: "upstream_unavailable", forwarded: false });
    await fake.dropConnection();
    const gone = await u.callTool("fetch_payment", {}, { expectedGeneration: 1 });
    expect(gone).toMatchObject({ kind: "error", error: "upstream_unavailable", forwarded: false });
    expect(fake.attempts()).toBe(1);
    expect(fake.calls).toEqual([]);
    const right = await u.callTool("fetch_payment", {}); // no pin ⇒ reconnects
    expect(right.kind).toBe("ok");
    expect(u.generation).toBe(2);
  });

  it("reconnects lazily after the transport closes and bumps the generation", async () => {
    const { u, fake } = make();
    await u.connect();
    await fake.dropConnection();
    expect(u.isConnected()).toBe(false);
    const r = await u.callTool("fetch_payment", { payment_id: "pay_1" });
    expect(r.kind).toBe("ok");
    expect(u.generation).toBe(2);
    expect(fake.disposed()).toBe(1);
  });

  it("forwards tools/list_changed notifications to listeners", async () => {
    const { u, fake } = make();
    await u.connect();
    const seen = new Promise<void>((resolve) => {
      u.onToolListChanged(resolve);
    });
    await fake.notifyListChanged();
    await seen;
  });

  it("close() disposes the connection and refuses further use", async () => {
    const { u, fake } = make();
    await u.connect();
    await u.close();
    await u.close();
    expect(fake.disposed()).toBe(1);
    expect(u.isConnected()).toBe(false);
    const r = await u.callTool("fetch_payment", {});
    expect(r).toMatchObject({ kind: "error", error: "upstream_unavailable", forwarded: false });
    expect((await u.connect()).ok).toBe(false);
  });
});

describe("late responses and transport errors (no payload in logs)", () => {
  const PII = {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({
          email: "alice@example.com",
          vpa: "alice@okbank",
          card: "4111111111111111",
        }),
      },
    ],
  };
  const PII_FRAGMENTS = [
    "alice@example.com",
    "alice@okbank",
    "4111111111111111",
    "email",
    '"result"',
  ];

  it("T010: late answers carry ONLY a failure boolean (JSON-RPC error, or result.isError === true)", async () => {
    const replies: ScriptedReply[] = [
      { delayMs: 40, result: { content: [{ type: "text", text: "ok" }] } },
      {
        delayMs: 40,
        result: { isError: true, content: [{ type: "text", text: "BAD 4111111111111111" }] },
      },
      { delayMs: 40, error: { code: -32603, message: "boom bob@example.com" } },
    ];
    const up = scriptedUpstream({ tools: [], handler: () => replies.shift() ?? { never: true } });
    const logs: string[] = [];
    const u = new Upstream({ factory: up.factory, logger: (l) => logs.push(l) });
    open.push(u);
    const events: LateResponse[] = [];
    u.onLateResponse((e) => events.push(e));
    for (let i = 0; i < 3; i++) {
      await u.callTool("create_refund", { amount: 100 }, { timeoutMs: 10 });
    }
    await vi.waitFor(() => {
      expect(events).toHaveLength(3);
    });
    expect(events.map((e) => [e.responseType, e.isError])).toEqual([
      ["result", false],
      ["result", true],
      ["error", true],
    ]);
    const all = logs.join("\n");
    expect(all).not.toContain("4111111111111111");
    expect(all).not.toContain("bob@example.com");
  });

  it("a response after timeout logs only a fixed category and emits payload-free metadata", async () => {
    const late = lateUpstream({ delayMs: 60, result: PII });
    const logs: string[] = [];
    let t = 1_000;
    const u = new Upstream({
      factory: late.factory,
      logger: (l) => logs.push(l),
      redact,
      now: () => t++,
    });
    open.push(u);
    const events: LateResponse[] = [];
    u.onLateResponse((e) => events.push(e));
    const r = await u.callTool(
      "create_refund",
      { payment_id: "pay_1", amount: 100 },
      { timeoutMs: 20 },
    );
    expect(r).toMatchObject({
      kind: "error",
      error: "upstream_timeout",
      forwarded: true,
      generation: 1,
    });
    await vi.waitFor(() => {
      expect(events).toHaveLength(1);
    });
    const e = events[0];
    expect(e).toMatchObject({ tool: "create_refund", generation: 1, responseType: "result" });
    expect(e?.requestId).toBe(late.callIds[0]);
    if (r.kind === "error") expect(r.requestId).toBe(e?.requestId);
    expect(typeof e?.sentAt).toBe("number");
    expect(e?.receivedAt).toBeGreaterThan(e?.sentAt ?? Infinity);
    expect(Object.keys(e ?? {}).sort()).toEqual(
      [
        "failure",
        "generation",
        "isError",
        "receivedAt",
        "requestId",
        "responseType",
        "sentAt",
        "tool",
      ].sort(),
    );
    const all = logs.join("\n");
    expect(all).toContain("late/unknown response id");
    for (const f of PII_FRAGMENTS) expect(all).not.toContain(f);
  });

  it.each([
    ["context canceled", "ambiguous"],
    ["BAD_REQUEST_ERROR: The refund amount is invalid", "definite_rejection"],
    ["BAD_REQUEST_ERROR then GATEWAY_ERROR", "ambiguous"],
  ] as const)(
    "a late isError result (%s) carries only its failure classification (%s)",
    async (text, failure) => {
      const late = lateUpstream({
        delayMs: 40,
        result: { isError: true, content: [{ type: "text", text }] },
      });
      const logs: string[] = [];
      const u = new Upstream({ factory: late.factory, logger: (l) => logs.push(l), redact });
      open.push(u);
      const events: LateResponse[] = [];
      u.onLateResponse((e) => events.push(e));
      await u.callTool("create_refund", { payment_id: "pay_1", amount: 100 }, { timeoutMs: 10 });
      await vi.waitFor(() => {
        expect(events).toHaveLength(1);
      });
      expect(events[0]).toMatchObject({ isError: true, failure, responseType: "result" });
      expect(JSON.stringify(events[0])).not.toContain(text);
      expect(logs.join("\n")).not.toContain(text);
    },
  );

  it("responseFailure: JSON-RPC error ⇒ ambiguous; success ⇒ none", () => {
    expect(
      responseFailure({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32603, message: "BAD_REQUEST_ERROR" },
      }),
    ).toBe("ambiguous");
    expect(
      responseFailure({
        jsonrpc: "2.0",
        id: 1,
        result: { content: [{ type: "text", text: "{}" }] },
      }),
    ).toBe("none");
    expect(
      responseFailure({
        jsonrpc: "2.0",
        id: 1,
        result: { isError: true, content: [{ type: "text", text: "BAD_REQUEST_ERROR" }] },
      }),
    ).toBe("definite_rejection");
  });

  it("a stdio parse error logs the class and category, never the message", async () => {
    const late = lateUpstream({ delayMs: 0, result: PII });
    const logs: string[] = [];
    const u = new Upstream({ factory: late.factory, logger: (l) => logs.push(l), redact });
    open.push(u);
    await u.connect();
    late.emitClientError(
      new SyntaxError(`Unexpected token in JSON at position 3: {"email":"alice@example.com"}`),
    );
    const all = logs.join("\n");
    expect(all).toContain("SyntaxError: parse error");
    expect(all).not.toContain("alice@example.com");
  });

  it("describeTransportError: class + fixed category + safe code only", () => {
    const enoent = Object.assign(new Error("spawn docker ENOENT /secret/path"), { code: "ENOENT" });
    expect(describeTransportError(enoent)).toBe("Error: transport error [ENOENT]");
    const zod = new Error(`bad ${KEYS.keySecret}`);
    zod.name = "ZodError";
    expect(describeTransportError(zod)).toBe("ZodError: parse error");
    const weird = new Error("x");
    weird.name = "Evil\u001b[2J name";
    expect(describeTransportError(weird, "late/unknown response id")).toBe(
      "Error: late/unknown response id",
    );
    expect(describeTransportError("not an error")).toBe("Error: transport error");
    const badCode = Object.assign(new Error("x"), { code: "alice@example.com" });
    expect(describeTransportError(badCode)).toBe("Error: transport error");
  });
});
