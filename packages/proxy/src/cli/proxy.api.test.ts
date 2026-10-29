/** T013 CLI wiring: ASF_API_* config, dashboard-only approvals, the in-process API server. */
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ADMIN_TOKEN_HEADER } from "@asf/api";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openAuditStore } from "../audit-store.js";
import { createModeStore } from "../modes.js";
import {
  openApprovals,
  parseApiConfig,
  readAdminTokenFile,
  resolveProxyConfig,
  startDashboardApi,
  type ConfigDeps,
} from "./proxy.js";

const ROOT = "/repo";
const SHELL = { RAZORPAY_KEY_ID: "rzp_test_Key123", RAZORPAY_KEY_SECRET: "TopSecretValue987" };
const ADMIN = "z".repeat(40);
/** Shell lookup over a plain object (what `resolveProxyConfig` passes). */
const shellOf =
  (env: Record<string, string>) =>
  (name: string): string | undefined =>
    env[name] === "" ? undefined : env[name];
const noShell = { shell: () => undefined };

function deps(files: Record<string, string> = {}): ConfigDeps {
  return {
    cwd: "/elsewhere",
    moduleDir: `${ROOT}/packages/proxy/src/cli`,
    isRepoRoot: (d) => d === ROOT,
    readFile: (p) => files[p],
    baseChildEnv: () => ({ PATH: "/usr/bin" }),
  };
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-cli-api-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("parseApiConfig", () => {
  it("no port ⇒ no API", () => {
    expect(parseApiConfig({ ASF_ADMIN_TOKEN: ADMIN }, noShell)).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it("defaults: 127.0.0.1, default origins, token kept", () => {
    const r = parseApiConfig({ ASF_API_PORT: "8787", ASF_ADMIN_TOKEN: ADMIN }, noShell);
    expect(r.ok && r.value).toMatchObject({ host: "127.0.0.1", port: 8787, adminToken: ADMIN });
    expect(r.ok && r.value?.allowedOrigins).toContain("http://localhost:5173");
  });

  it("weak / missing token ⇒ API config without a token (disabled), not an error", () => {
    for (const t of [undefined, "change-me", "short"]) {
      const r = parseApiConfig(
        {
          ASF_API_PORT: "8787",
          ...(t === undefined ? {} : { ASF_ADMIN_TOKEN: t }),
        },
        noShell,
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.value?.adminToken).toBeUndefined();
        expect(r.value?.tokenProblem).toBeDefined();
        expect(JSON.stringify(r.value)).not.toContain('change-me"');
      }
    }
  });

  it.each([
    [{ ASF_API_PORT: "80" }],
    [{ ASF_API_PORT: "abc" }],
    [{ ASF_API_PORT: "8787", ASF_API_HOST: "0.0.0.0" }],
    [{ ASF_API_PORT: "8787", ASF_API_ALLOWED_ORIGINS: "*" }],
  ])("bad %o ⇒ err (exit 2)", (env) => {
    expect(parseApiConfig(env, { shell: shellOf(env) }).ok).toBe(false);
    expect(resolveProxyConfig({ ...SHELL, ...env }, deps()).ok).toBe(false);
  });

  it("resolveProxyConfig reads the API settings (also from .env)", () => {
    const r = resolveProxyConfig(
      SHELL,
      deps({ [`${ROOT}/.env`]: `ASF_API_PORT=8790\nASF_ADMIN_TOKEN=${ADMIN}\n` }),
    );
    expect(r.ok && r.value.api).toMatchObject({ port: 8790, adminToken: ADMIN });
  });
});

describe("M1: ASF_API_APPROVALS and ASF_ADMIN_TOKEN_FILE", () => {
  it("ASF_API_APPROVALS: shell only, 0/1, default off", () => {
    const on = resolveProxyConfig(
      { ...SHELL, ASF_API_PORT: "8787", ASF_API_APPROVALS: "1" },
      deps(),
    );
    expect(on.ok && on.value.api?.approvalsEnabled).toBe(true);
    const fromFile = resolveProxyConfig(
      { ...SHELL, ASF_API_PORT: "8787" },
      deps({ [`${ROOT}/.env`]: "ASF_API_APPROVALS=1\n" }),
    );
    expect(fromFile.ok && fromFile.value.api?.approvalsEnabled).toBe(false);
    expect(fromFile.ok && fromFile.value.notes.join("\n")).toContain("ASF_API_APPROVALS");
    expect(
      parseApiConfig({ ASF_API_PORT: "8787" }, { shell: shellOf({ ASF_API_APPROVALS: "yes" }) }).ok,
    ).toBe(false);
  });

  it("L2: shell-only settings are read ONLY through the required shell source, never the merged env", () => {
    let fileReads = 0;
    const r = parseApiConfig(
      {
        ASF_API_PORT: "8787",
        ASF_ADMIN_TOKEN: ADMIN,
        ASF_API_APPROVALS: "1",
        ASF_ADMIN_TOKEN_FILE: "/secret/token",
      },
      {
        ...noShell,
        readTokenFile: () => {
          fileReads++;
          return { ok: true, value: "f".repeat(40) };
        },
      },
    );
    expect(r.ok && r.value).toMatchObject({ approvalsEnabled: false, adminToken: ADMIN });
    expect(fileReads).toBe(0);
  });

  it("token file wins over ASF_ADMIN_TOKEN; a bad file disables the API (no fallback)", () => {
    const good = parseApiConfig(
      {
        ASF_API_PORT: "8787",
        ASF_ADMIN_TOKEN_FILE: "/secret/token",
        ASF_ADMIN_TOKEN: "e".repeat(40),
      },
      {
        shell: shellOf({ ASF_ADMIN_TOKEN_FILE: "/secret/token" }),
        readTokenFile: () => ({ ok: true, value: ADMIN }),
      },
    );
    expect(good.ok && good.value?.adminToken).toBe(ADMIN);
    const bad = parseApiConfig(
      {
        ASF_API_PORT: "8787",
        ASF_ADMIN_TOKEN_FILE: "/secret/token",
        ASF_ADMIN_TOKEN: "e".repeat(40),
      },
      {
        shell: shellOf({ ASF_ADMIN_TOKEN_FILE: "/secret/token" }),
        readTokenFile: () => ({ ok: false, error: { code: "api.token_file", message: "nope" } }),
      },
    );
    expect(bad.ok && bad.value?.adminToken).toBeUndefined();
    expect(bad.ok && bad.value?.tokenProblem).toBe("nope");
    const fromDotEnv = resolveProxyConfig(
      { ...SHELL, ASF_API_PORT: "8787" },
      deps({ [`${ROOT}/.env`]: "ASF_ADMIN_TOKEN_FILE=/x\n" }),
    );
    expect(fromDotEnv.ok && fromDotEnv.value.api?.tokenProblem).toBeDefined();
  });

  it("readAdminTokenFile: 0600 owned file ok (trailing newline stripped); group/world readable, missing, relative, dir ⇒ err", () => {
    const f = join(dir, "token");
    writeFileSync(f, `${ADMIN}\n`, { mode: 0o600 });
    chmodSync(f, 0o600);
    expect(readAdminTokenFile(f)).toEqual({ ok: true, value: ADMIN });
    chmodSync(f, 0o640);
    expect(readAdminTokenFile(f).ok).toBe(false);
    chmodSync(f, 0o604);
    expect(readAdminTokenFile(f).ok).toBe(false);
    expect(readAdminTokenFile(join(dir, "missing")).ok).toBe(false);
    expect(readAdminTokenFile("relative/token").ok).toBe(false);
    expect(readAdminTokenFile(dir).ok).toBe(false);
  });

  it("L1: readAdminTokenFile refuses a symlink (O_NOFOLLOW) even to a valid 0600 file, and an oversize file", () => {
    const target = join(dir, "real-token");
    writeFileSync(target, ADMIN, { mode: 0o600 });
    chmodSync(target, 0o600);
    const link = join(dir, "link-token");
    symlinkSync(target, link);
    expect(readAdminTokenFile(target)).toEqual({ ok: true, value: ADMIN });
    const viaLink = readAdminTokenFile(link);
    expect(viaLink.ok).toBe(false);
    if (!viaLink.ok) expect(viaLink.error.message).toContain("ELOOP");
    const big = join(dir, "big-token");
    writeFileSync(big, "x".repeat(2048), { mode: 0o600 });
    chmodSync(big, 0o600);
    expect(readAdminTokenFile(big).ok).toBe(false);
  });
});

describe("dashboard-only approvals", () => {
  it("API without ASF_API_APPROVALS=1 ⇒ no dashboard-only approval wiring", () => {
    const r = resolveProxyConfig(
      { ...SHELL, ASF_API_PORT: "8787", ASF_ADMIN_TOKEN: ADMIN },
      deps(),
    );
    if (!r.ok) throw new Error(r.error.code);
    expect(r.value.api?.approvalsEnabled).toBe(false);
    expect(openApprovals(r.value, () => undefined)).toEqual({ ok: true, value: undefined });
  });

  it("API with a valid token, ASF_API_APPROVALS=1 and no Telegram ⇒ approval wiring without a notifier channel", () => {
    const r = resolveProxyConfig(
      { ...SHELL, ASF_API_PORT: "8787", ASF_ADMIN_TOKEN: ADMIN, ASF_API_APPROVALS: "1" },
      deps(),
    );
    if (!r.ok) throw new Error(r.error.code);
    const w = openApprovals(
      { ...r.value, auditDbPath: join(dir, "data", "audit.db") },
      () => undefined,
    );
    if (!w.ok || w.value === undefined) throw new Error("expected wiring");
    expect(w.value.telegram).toBeUndefined();
    expect(w.value.store.path).toBe(join(dir, "data", "approvals.db"));
    w.value.store.close();
  });

  it("API without a valid token ⇒ no approval wiring (nothing could ever approve)", () => {
    const r = resolveProxyConfig(
      { ...SHELL, ASF_API_PORT: "8787", ASF_ADMIN_TOKEN: "change-me", ASF_API_APPROVALS: "1" },
      deps(),
    );
    if (!r.ok) throw new Error(r.error.code);
    expect(openApprovals(r.value, () => undefined)).toEqual({ ok: true, value: undefined });
  });
});

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      const port = typeof a === "object" && a !== null ? a.port : 0;
      s.close(() => {
        resolve(port);
      });
    });
  });
}

describe("startDashboardApi", () => {
  it("serves the real stores on loopback; logs the URL, never the token; kill switch via HTTP", async () => {
    const store = openAuditStore({ path: ":memory:" });
    if (!store.ok) throw new Error("store");
    const port = await freePort();
    const logs: string[] = [];
    const modes = createModeStore(store.value);
    const r = await startDashboardApi(
      { host: "127.0.0.1", port, adminToken: ADMIN, allowedOrigins: [], approvalsEnabled: false },
      { audit: store.value, modes, logger: (l) => logs.push(l) },
    );
    if (!r.ok) throw new Error(r.error.message);
    try {
      const base = `http://127.0.0.1:${String(port)}`;
      const k = await fetch(`${base}/killswitch`, {
        method: "POST",
        headers: { [ADMIN_TOKEN_HEADER]: ADMIN, "content-type": "application/json" },
        body: JSON.stringify({ on: true }),
      });
      expect(k.status).toBe(200);
      const m = modes.read();
      expect(m.ok && m.value).toMatchObject({ killSwitch: true, actor: "dashboard:admin" });
      expect(
        (await fetch(`${base}/approvals`, { headers: { [ADMIN_TOKEN_HEADER]: ADMIN } })).status,
      ).toBe(503);
      expect(logs.join("\n")).toContain(`http://127.0.0.1:${String(port)}`);
      expect(logs.join("\n")).not.toContain(ADMIN);
    } finally {
      await r.value.close();
      store.value.close();
    }
  });

  it("no token ⇒ starts disabled with a loud warning", async () => {
    const store = openAuditStore({ path: ":memory:" });
    if (!store.ok) throw new Error("store");
    const port = await freePort();
    const logs: string[] = [];
    const r = await startDashboardApi(
      {
        host: "127.0.0.1",
        port,
        tokenProblem: "ASF_ADMIN_TOKEN is not set",
        allowedOrigins: [],
        approvalsEnabled: false,
      },
      { audit: store.value, modes: createModeStore(store.value), logger: (l) => logs.push(l) },
    );
    if (!r.ok) throw new Error(r.error.message);
    try {
      const res = await fetch(`http://127.0.0.1:${String(port)}/mode`, {
        headers: { [ADMIN_TOKEN_HEADER]: "" },
      });
      expect(res.status).toBe(503);
      expect(logs.join("\n")).toContain("DISABLED");
    } finally {
      await r.value.close();
      store.value.close();
    }
  });
});
