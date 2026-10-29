import { ok, type AuditRecord } from "@asf/core";
import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import { createApi, ADMIN_TOKEN_HEADER } from "./app.js";
import {
  parseAdminToken,
  parseAllowedOrigins,
  parseApiHost,
  parseApiPort,
  tokenMatches,
} from "./security.js";
import { startApiServer } from "./server.js";

describe("admin token", () => {
  it.each([
    [undefined],
    [""],
    ["change-me"],
    ["CHANGE-ME"],
    ["x".repeat(31)],
    ["x".repeat(257)],
    [`${"x".repeat(32)} y`],
  ])("rejects %s", (raw) => {
    expect(parseAdminToken(raw).ok).toBe(false);
  });
  it("accepts a 32+ char printable token", () => {
    expect(parseAdminToken("a".repeat(32))).toEqual(ok("a".repeat(32)));
  });
  it("constant-time compare works for different lengths", () => {
    expect(tokenMatches("abc", "abc")).toBe(true);
    expect(tokenMatches("abc", "abcd")).toBe(false);
    expect(tokenMatches("abc", "")).toBe(false);
    expect(tokenMatches("abc", undefined)).toBe(false);
  });
});

describe("listen config", () => {
  it("port", () => {
    expect(parseApiPort(undefined)).toEqual(ok(undefined));
    expect(parseApiPort("8787")).toEqual(ok(8787));
    for (const bad of ["0", "80", "65536", "8787x", "-1", " 8787"])
      expect(parseApiPort(bad).ok).toBe(false);
  });
  it("host is loopback only", () => {
    expect(parseApiHost(undefined)).toEqual(ok("127.0.0.1"));
    expect(parseApiHost("::1")).toEqual(ok("::1"));
    for (const bad of ["0.0.0.0", "192.168.1.2", "::", "example.com"])
      expect(parseApiHost(bad).ok).toBe(false);
  });
  it("origins are loopback only, no wildcard", () => {
    expect(parseAllowedOrigins(undefined, 8787).ok).toBe(true);
    expect(parseAllowedOrigins("http://localhost:3000, http://127.0.0.1:5173", 1)).toEqual(
      ok(["http://localhost:3000", "http://127.0.0.1:5173"]),
    );
    for (const bad of [
      "*",
      "https://evil.example",
      "http://localhost:5173/",
      "null",
      "http://localhost.evil.com",
    ]) {
      expect(parseAllowedOrigins(bad, 1).ok).toBe(false);
    }
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

function api(port: number) {
  return createApi({
    audit: {
      readPage: () => ok([] as AuditRecord[]),
      readSession: () => ok([]),
      readAttempt: () => ok(undefined),
      verify: () => ok({ ok: true, count: 0, headHash: "0".repeat(64), danglingAttempts: [] }),
    },
    modes: {
      read: () => ok({ killSwitch: false, shadow: false }),
      set: () => ok({ changed: false, mode: { killSwitch: false, shadow: false } }),
    },
    adminToken: "k".repeat(40),
    port,
  });
}

describe("startApiServer", () => {
  it("refuses a non-loopback bind address", async () => {
    const r = await startApiServer(api(9), "0.0.0.0", 9);
    expect(r.ok).toBe(false);
  });

  it("serves on 127.0.0.1, enforces the token, reports EADDRINUSE, closes", async () => {
    const port = await freePort();
    const running = await startApiServer(api(port), "127.0.0.1", port);
    if (!running.ok) throw new Error(running.error.message);
    try {
      const base = `http://127.0.0.1:${String(port)}`;
      expect((await fetch(`${base}/audit`)).status).toBe(401);
      const r = await fetch(`${base}/audit`, { headers: { [ADMIN_TOKEN_HEADER]: "k".repeat(40) } });
      expect(r.status).toBe(200);
      const again = await startApiServer(api(port), "127.0.0.1", port);
      expect(again.ok).toBe(false);
      if (!again.ok) expect(again.error.code).toBe("api.listen_failed");
    } finally {
      await running.value.close();
    }
  });
});
