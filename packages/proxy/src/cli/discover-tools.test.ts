import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { err, ok } from "@asf/core";
import {
  DEFAULT_RAZORPAY_MCP_IMAGE,
  DISCOVERY_PLACEHOLDER_KEYS,
  toolsFileSchema,
  type ConnectLister,
  type ToolLister,
} from "../tool-discovery.js";
import {
  DEFAULT_TOOLS_OUT,
  findRepoRoot,
  dockerRemoveContainer,
  mergeEnv,
  pickRepoDigest,
  runDiscover,
  writeFileAtomic,
  type DiscoverDeps,
  type ImageInspection,
  type UpstreamSpawn,
} from "./discover-tools.js";

const KEY_ID = "rzp_test_Key123";
const KEY_SECRET = "TopSecretValue987";
const ROOT = "/repo";

interface Harness {
  deps: DiscoverDeps;
  writes: { path: string; content: string }[];
  spawns: UpstreamSpawn[];
  removed: { name: string; env: Readonly<Record<string, string>> }[];
  inspected: { image: string; env: Readonly<Record<string, string>> }[];
}

const HEX = "00112233aabbccdd";
const CONTAINER = `asf-discover-${HEX}`;

function listerOf(pages: unknown[], onClose: () => void = () => undefined): ConnectLister {
  let i = 0;
  const lister: ToolLister = {
    listTools: () => Promise.resolve(pages[i++]),
    serverInfo: () => ({ name: "razorpay-mcp-server", version: "1.0.0" }),
    close: () => {
      onClose();
      return Promise.resolve();
    },
  };
  return () => Promise.resolve(lister);
}

const GOOD_PAGE = {
  tools: [
    { name: "fetch_payment", description: "Read a payment", inputSchema: { type: "object" } },
    {
      name: "create_refund",
      description: "Make a refund\u001b[2J",
      inputSchema: { type: "object" },
    },
  ],
};

function harness(
  opts: {
    envFile?: string;
    connect?: ConnectLister;
    stderr?: string;
    digest?: string;
    inspection?: ImageInspection;
    writeThrows?: boolean;
    removeContainer?: DiscoverDeps["removeContainer"];
    signal?: AbortSignal;
  } = {},
): Harness {
  const writes: { path: string; content: string }[] = [];
  const spawns: UpstreamSpawn[] = [];
  const removed: Harness["removed"] = [];
  const inspected: Harness["inspected"] = [];
  const deps: DiscoverDeps = {
    cwd: `${ROOT}/packages/proxy`,
    readEnvFile: (p) => (p === `${ROOT}/.env` ? opts.envFile : undefined),
    isRepoRoot: (d) => d === ROOT,
    baseChildEnv: () => ({ PATH: "/usr/bin", HOME: "/home/u" }),
    upstream: (spawn) => {
      spawns.push(spawn);
      return { connect: opts.connect ?? listerOf([GOOD_PAGE]), stderr: () => opts.stderr ?? "" };
    },
    inspectImage: (image, env) => {
      inspected.push({ image, env });
      return Promise.resolve(opts.inspection ?? { kind: "present", digest: opts.digest });
    },
    removeContainer:
      opts.removeContainer ??
      ((name, env) => {
        removed.push({ name, env });
        return Promise.resolve(ok(null));
      }),
    randomHex: () => HEX,
    writeFileAtomic: (path, content) => {
      if (opts.writeThrows === true) throw new Error("EACCES: permission denied");
      writes.push({ path, content });
    },
    now: () => new Date("2026-10-23T10:00:00.000Z"),
    ...(opts.signal === undefined ? {} : { signal: opts.signal }),
  };
  return { deps, writes, spawns, removed, inspected };
}

const PLACEHOLDER_ENV = {
  RAZORPAY_KEY_ID: DISCOVERY_PLACEHOLDER_KEYS.keyId,
  RAZORPAY_KEY_SECRET: DISCOVERY_PLACEHOLDER_KEYS.keySecret,
};

const KEYS_ENV = { RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: KEY_SECRET };

function expectPrintable(output: string): void {
  for (const line of output.split("\n")) expect(line).toMatch(/^[\x20-\x7e]*$/);
}

describe("runDiscover exit 0", () => {
  it("writes sorted tools to <root>/docs/razorpay-tools.json and prints names only", async () => {
    const h = harness({ digest: `razorpay/mcp@sha256:${"c".repeat(64)}` });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(0);
    expect(h.writes).toHaveLength(1);
    const w = h.writes[0];
    expect(w?.path).toBe(join(ROOT, DEFAULT_TOOLS_OUT));
    const file = toolsFileSchema.parse(JSON.parse(w?.content ?? ""));
    expect(file.tools.map((t) => t.name)).toEqual(["create_refund", "fetch_payment"]);
    expect(file.imageDigest).toBe(`razorpay/mcp@sha256:${"c".repeat(64)}`);
    expect(file.discoveredAt).toBe("2026-10-23T10:00:00.000Z");
    expect(file.transport).toBe("docker-stdio");
    expect(r.output).toContain("OK: wrote 2 tools");
    expect(r.output).toContain("create_refund, fetch_payment");
    expect(r.output).not.toContain("Make a refund");
    expect(r.output).not.toContain(KEY_ID);
    expect(r.output).not.toContain(KEY_SECRET);
    expectPrintable(r.output);
    expect(h.removed.map((x) => x.name)).toEqual([CONTAINER]);
  });

  it("spawns hardened docker with the pinned default image, placeholder keys and an allowlisted env", async () => {
    const h = harness();
    const r = await runDiscover([], { ...KEYS_ENV, ANTHROPIC_API_KEY: "sk-ant-x" }, h.deps);
    expect(r.exitCode).toBe(0);
    const s = h.spawns[0];
    expect(s?.command).toBe("docker");
    expect(s?.args).toEqual(
      expect.arrayContaining([
        "--network",
        "none",
        "--pull=never",
        "--read-only",
        "--init",
        "--name",
        CONTAINER,
      ]),
    );
    expect(s?.args.at(-1)).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    // Real keys never reach the child: not in argv, not in env.
    expect(JSON.stringify(s)).not.toContain(KEY_SECRET);
    expect(JSON.stringify(s)).not.toContain(KEY_ID);
    expect(s?.env).toEqual({ PATH: "/usr/bin", HOME: "/home/u", ...PLACEHOLDER_ENV });
    // docker inspect / rm get no Razorpay variables at all.
    expect(h.inspected[0]?.image).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    expect(Object.keys(h.inspected[0]?.env ?? {})).toEqual(["PATH", "HOME"]);
    expect(Object.keys(h.removed[0]?.env ?? {})).toEqual(["PATH", "HOME"]);
  });

  it("image override and DOCKER_* come from the shell env", async () => {
    const h = harness();
    const r = await runDiscover(
      [],
      {
        ...KEYS_ENV,
        ANTHROPIC_API_KEY: "sk-ant-x",
        DOCKER_HOST: "unix:///d.sock",
        ASF_RAZORPAY_MCP_IMAGE: "razorpay/mcp:v1",
      },
      h.deps,
    );
    expect(r.exitCode).toBe(0);
    const s = h.spawns[0];
    expect(s?.args.at(-1)).toBe("razorpay/mcp:v1");
    expect(h.inspected[0]?.image).toBe("razorpay/mcp:v1");
    expect(s?.env).toEqual({
      PATH: "/usr/bin",
      HOME: "/home/u",
      DOCKER_HOST: "unix:///d.sock",
      ...PLACEHOLDER_ENV,
    });
    expect(h.removed[0]?.env["DOCKER_HOST"]).toBe("unix:///d.sock");
    expect(r.output).not.toContain("note:");
  });

  it("ASF_RAZORPAY_MCP_IMAGE and DOCKER_* in .env are ignored", async () => {
    const h = harness({
      envFile:
        "ASF_RAZORPAY_MCP_IMAGE=evil/image:latest\nDOCKER_HOST=tcp://attacker:2375\nDOCKER_CONTEXT=x\nDOCKER_CONFIG=/tmp/c\n",
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(0);
    const s = h.spawns[0];
    expect(s?.args.at(-1)).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    expect(s?.env).toEqual({ PATH: "/usr/bin", HOME: "/home/u", ...PLACEHOLDER_ENV });
    expect(h.inspected[0]?.env).toEqual({ PATH: "/usr/bin", HOME: "/home/u" });
    expect(r.output).toContain("note: ASF_RAZORPAY_MCP_IMAGE from .env is ignored");
  });

  it("validates keys from <root>/.env (found via INIT_CWD); shell values win; real keys not passed", async () => {
    const h = harness({
      envFile: "RAZORPAY_KEY_ID=not-a-test-key\nRAZORPAY_KEY_SECRET=fileSecret0000000\n",
    });
    const r = await runDiscover(
      [],
      { INIT_CWD: `${ROOT}/a/b`, RAZORPAY_KEY_ID: "rzp_test_FromShell" },
      h.deps,
    );
    expect(r.exitCode).toBe(0);
    expect(h.spawns[0]?.env).toMatchObject(PLACEHOLDER_ENV);
    expect(JSON.stringify(h.spawns[0])).not.toContain("fileSecret0000000");
  });

  it("an empty shell value does not blank out the .env value", async () => {
    const h = harness({
      envFile: `RAZORPAY_KEY_ID=${KEY_ID}\nRAZORPAY_KEY_SECRET=${KEY_SECRET}\n`,
    });
    const r = await runDiscover([], { RAZORPAY_KEY_ID: "", RAZORPAY_KEY_SECRET: "" }, h.deps);
    expect(r.exitCode).toBe(0);
  });

  it("--out resolves relative to the repo root; pnpm's -- separator is ignored", async () => {
    const h = harness();
    const r = await runDiscover(["--", "--out", "tmp/x.json", "--timeout=5000"], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(0);
    expect(h.writes[0]?.path).toBe(join(ROOT, "tmp/x.json"));
  });
});

describe("runDiscover exit 2 (refused)", () => {
  it.each<[string, Record<string, string>, string | undefined]>([
    ["no keys", {}, undefined],
    [
      "live key id",
      { RAZORPAY_KEY_ID: "rzp_live_Abc", RAZORPAY_KEY_SECRET: KEY_SECRET },
      undefined,
    ],
    ["rzp_testX", { RAZORPAY_KEY_ID: "rzp_testXabc", RAZORPAY_KEY_SECRET: KEY_SECRET }, undefined],
    ["missing secret", { RAZORPAY_KEY_ID: KEY_ID }, undefined],
    ["short secret", { RAZORPAY_KEY_ID: KEY_ID, RAZORPAY_KEY_SECRET: "short" }, undefined],
    ["live key elsewhere in .env", KEYS_ENV, "SOME_OTHER=rzp_live_Zzz\n"],
    ["live key id in .env", {}, "RAZORPAY_KEY_ID=rzp_live_Zzz\nRAZORPAY_KEY_SECRET=x\n"],
    ["upper-case live key in .env", KEYS_ENV, "OTHER=RZP_LIVE_Zzz\n"],
  ])("%s", async (_l, env, envFile) => {
    const h = harness(envFile === undefined ? {} : { envFile });
    const r = await runDiscover([], env, h.deps);
    expect(r.exitCode).toBe(2);
    expect(h.spawns).toHaveLength(0);
    expect(h.inspected).toHaveLength(0);
    expect(h.removed).toHaveLength(0);
    expect(h.writes).toHaveLength(0);
    expect(r.output).not.toContain("RZP_LIVE_Zzz");
    expect(r.output).not.toContain(KEY_SECRET);
    expect(r.output).not.toContain("rzp_live_Abc");
    expect(r.output).not.toContain("rzp_live_Zzz");
  });

  it.each([["--bogus"], ["--timeout"], ["--timeout", "abc"], ["--timeout", "10"], ["--out="]])(
    "bad usage %j",
    async (...argv) => {
      const h = harness();
      const r = await runDiscover(argv, KEYS_ENV, h.deps);
      expect(r.exitCode).toBe(2);
      expect(r.output).toContain("usage:");
      expect(h.spawns).toHaveLength(0);
    },
  );

  it("bad image reference", async () => {
    const h = harness();
    const r = await runDiscover(
      [],
      { ...KEYS_ENV, ASF_RAZORPAY_MCP_IMAGE: "--privileged" },
      h.deps,
    );
    expect(r.exitCode).toBe(2);
    expect(h.spawns).toHaveLength(0);
  });

  it("bad image reference in .env is irrelevant (ignored)", async () => {
    const h = harness({ envFile: "ASF_RAZORPAY_MCP_IMAGE=--privileged\n" });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(0);
  });

  it("bad container name suffix", async () => {
    const h = harness();
    const r = await runDiscover([], KEYS_ENV, { ...h.deps, randomHex: () => "nothex!" });
    expect(r.exitCode).toBe(2);
    expect(h.spawns).toHaveLength(0);
    expect(h.removed).toHaveLength(0);
  });

  it("no repo root", async () => {
    const h = harness();
    const r = await runDiscover([], KEYS_ENV, { ...h.deps, isRepoRoot: () => false });
    expect(r.exitCode).toBe(2);
  });
});

describe("runDiscover exit 1 (failed, nothing written)", () => {
  it("image not present locally ⇒ tells the human to docker pull it; nothing spawned", async () => {
    const h = harness({ inspection: { kind: "missing" } });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("--pull=never");
    expect(r.output).toContain(`docker pull ${DEFAULT_RAZORPAY_MCP_IMAGE}`);
    expect(h.spawns).toHaveLength(0);
    expect(h.removed).toHaveLength(0);
    expect(h.writes).toHaveLength(0);
  });

  it("docker image inspect error ⇒ exit 1, nothing spawned", async () => {
    const h = harness({
      inspection: { kind: "error", message: "docker image inspect failed (exit 1)" },
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("docker image inspect failed");
    expect(h.spawns).toHaveLength(0);
  });

  it("timeout ⇒ exit 1 and the container is force-removed", async () => {
    const connect: ConnectLister = () =>
      Promise.resolve({
        listTools: () => new Promise<unknown>(() => undefined),
        serverInfo: () => ({ name: "s", version: "1" }),
        close: () => Promise.resolve(),
      });
    const h = harness({ connect });
    const r = await runDiscover(["--timeout", "1000"], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("discover.timeout");
    expect(h.removed.map((x) => x.name)).toEqual([CONTAINER]);
  });

  it("abort (SIGINT) ⇒ exit 1 and the container is force-removed", async () => {
    const ctl = new AbortController();
    const connect: ConnectLister = () =>
      Promise.resolve({
        listTools: () => {
          ctl.abort();
          return new Promise<unknown>(() => undefined);
        },
        serverInfo: () => ({ name: "s", version: "1" }),
        close: () => Promise.resolve(),
      });
    const h = harness({ connect, signal: ctl.signal });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("discover.aborted");
    expect(h.removed.map((x) => x.name)).toEqual([CONTAINER]);
    expect(h.writes).toHaveLength(0);
  });

  it("cleanup failure ⇒ warning with manual command, exit code unchanged", async () => {
    const h = harness({
      removeContainer: () =>
        Promise.resolve(
          err("discover.cleanup_failed", `docker rm -f ${CONTAINER} failed (timed out)`),
        ),
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("warning: docker rm -f");
    expect(r.output).toContain(`docker rm -f ${CONTAINER}`);
    expectPrintable(r.output);
  });

  it("cleanup throwing ⇒ redacted warning, original failure kept", async () => {
    const h = harness({
      connect: listerOf([{ tools: [] }]),
      removeContainer: () => Promise.reject(new Error(`boom ${KEY_SECRET}`)),
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("discover.empty");
    expect(r.output).toContain("warning: container cleanup failed");
    expect(r.output).not.toContain(KEY_SECRET);
  });

  it("basic-auth / URI-encoded forms of the keys in upstream stderr are redacted", async () => {
    const basic = Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString("base64");
    const h = harness({
      connect: listerOf([{ tools: [] }]),
      stderr: `Authorization: Basic ${basic}\nkey=${encodeURIComponent(KEY_SECRET)}\n`,
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).not.toContain(basic.replace(/=+$/, ""));
    expect(r.output).toContain("Basic [REDACTED]");
  });

  it("empty tool list; upstream stderr shown redacted and escaped", async () => {
    const h = harness({
      connect: listerOf([{ tools: [] }]),
      stderr: `boot with key ${KEY_ID} secret ${KEY_SECRET}\n\u001b[2Jforged OK line\n`,
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(h.writes).toHaveLength(0);
    expect(r.output).toContain("discover.empty");
    expect(r.output).toContain("nothing written");
    expect(r.output).toContain("[REDACTED]");
    expect(r.output).not.toContain(KEY_ID);
    expect(r.output).not.toContain(KEY_SECRET);
    expectPrintable(r.output);
  });

  it("connect failure (docker missing)", async () => {
    const h = harness({ connect: () => Promise.reject(new Error("spawn docker ENOENT")) });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("discover.connect_failed");
    expect(h.writes).toHaveLength(0);
  });

  it("connect error text containing the secret is redacted", async () => {
    const h = harness({ connect: () => Promise.reject(new Error(`bad auth ${KEY_SECRET}`)) });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).not.toContain(KEY_SECRET);
  });

  it("upstream echoes the key id in a description ⇒ refuse to write", async () => {
    const h = harness({
      connect: listerOf([
        { tools: [{ name: "x", description: `uses ${KEY_ID}`, inputSchema: { type: "object" } }] },
      ]),
    });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("refusing to write");
    expect(r.output).not.toContain(KEY_ID);
    expect(h.writes).toHaveLength(0);
  });

  it("write failure", async () => {
    const h = harness({ writeThrows: true });
    const r = await runDiscover([], KEYS_ENV, h.deps);
    expect(r.exitCode).toBe(1);
    expect(r.output).toContain("EACCES");
    expect(h.removed.map((x) => x.name)).toEqual([CONTAINER]);
  });
});

describe("helpers", () => {
  it("findRepoRoot walks up", () => {
    expect(findRepoRoot("/repo/a/b/c", (d) => d === "/repo")).toBe("/repo");
    expect(findRepoRoot("/x/y", () => false)).toBeUndefined();
  });

  it("mergeEnv: shell wins, file fills gaps, undefined/empty shell values don't erase", () => {
    expect(
      mergeEnv({ A: "shell", C: undefined, D: "" }, "A=file\nB=file\nC=file\nD=file\n"),
    ).toEqual({
      A: "shell",
      B: "file",
      C: "file",
      D: "file",
    });
    expect(mergeEnv({ E: "" }, undefined)).toEqual({});
    expect(mergeEnv({ A: "1" }, undefined)).toEqual({ A: "1" });
  });
});

describe("dockerRemoveContainer", () => {
  it("refuses an invalid name without running docker (and does not throw)", async () => {
    const r = await dockerRemoveContainer("--all", {});
    expect(r.ok ? "ok" : r.error.code).toBe("discover.cleanup_failed");
  });
});

describe("pickRepoDigest", () => {
  const d = `razorpay/mcp@sha256:${"a".repeat(64)}`;
  it.each<[string, string | undefined]>([
    [JSON.stringify([d]), d],
    [JSON.stringify(["junk", d]), d],
    ["[]", undefined],
    ["null", undefined],
    ["not json", undefined],
    [JSON.stringify(["x@sha256:short"]), undefined],
  ])("%s", (stdout, expected) => {
    expect(pickRepoDigest(stdout)).toBe(expected);
  });
});

describe("writeFileAtomic", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "asf-discover-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("replaces the file and leaves no temp files", () => {
    const p = join(dir, "out.json");
    writeFileSync(p, "old");
    writeFileAtomic(p, "new\n");
    expect(readFileSync(p, "utf8")).toBe("new\n");
    expect(readdirSync(dir)).toEqual(["out.json"]);
  });

  it("temp write failure leaves nothing behind", () => {
    const p = join(dir, "missing-dir", "out.json");
    expect(() => writeFileAtomic(p, "x")).toThrow();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("rename failure leaves the existing target untouched and removes the temp file", () => {
    const target = join(dir, "out.json");
    mkdirSync(target); // renaming a file over a non-empty directory fails
    writeFileSync(join(target, "keep"), "old");
    expect(() => writeFileAtomic(target, "new")).toThrow();
    expect(readdirSync(dir)).toEqual(["out.json"]);
    expect(readFileSync(join(target, "keep"), "utf8")).toBe("old");
  });
});
