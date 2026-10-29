import { describe, expect, it, vi } from "vitest";
import { attempt, HASH, jsonResponse, pending, TOKEN } from "../test/fixtures";
import { createApiClient, type FetchLike } from "./client";
import { auditPageSchema, recordViewSchema, verifySchema } from "./schemas";

const client = (fetchImpl: FetchLike) =>
  createApiClient({ baseUrl: "http://127.0.0.1:8787", token: TOKEN, fetchImpl });

describe("schemas reject malformed responses", () => {
  it("accepts a valid attempt view", () => {
    expect(recordViewSchema.safeParse(attempt()).success).toBe(true);
  });

  it.each([
    ["float amountPaise", { amountPaise: 12.5 }],
    ["negative amountPaise", { amountPaise: -1 }],
    ["unsafe amountPaise", { amountPaise: Number.MAX_SAFE_INTEGER + 1 }],
    ["string amountPaise", { amountPaise: "500" }],
    ["unknown decision", { decision: "maybe" }],
    ["reason not marked untrusted", { reason: { untrusted: false, label: "x", text: '"x"' } }],
    ["raw string reason", { reason: "hello" }],
    ["bad hash", { hash: "nothex" }],
  ])("rejects an attempt with %s", (_name, over) => {
    expect(recordViewSchema.safeParse({ ...attempt(), ...over }).success).toBe(false);
  });

  it("rejects an unknown record kind and a page without records", () => {
    expect(recordViewSchema.safeParse({ kind: "nope", seq: 1 }).success).toBe(false);
    expect(auditPageSchema.safeParse({ nextCursor: null }).success).toBe(false);
  });

  it("verify: ok and broken parse, an ambiguous shape does not", () => {
    expect(
      verifySchema.safeParse({ ok: true, count: 3, headHash: HASH, danglingAttempts: 0 }).success,
    ).toBe(true);
    expect(
      verifySchema.safeParse({
        ok: false,
        brokenAt: { index: 1, seq: 2, id: null, reason: "hash_mismatch" },
      }).success,
    ).toBe(true);
    expect(verifySchema.safeParse({ ok: true }).success).toBe(false);
    expect(
      verifySchema.safeParse({ ok: "yes", count: 1, headHash: HASH, danglingAttempts: 0 }).success,
    ).toBe(false);
  });
});

describe("createApiClient", () => {
  it("sends the token as x-admin-token, never in the URL, without cookies", async () => {
    const fetchImpl = vi.fn<FetchLike>(() =>
      Promise.resolve(jsonResponse(200, { records: [attempt()], nextCursor: null })),
    );
    const r = await client(fetchImpl).getAudit(50);
    expect(r.ok).toBe(true);
    const [url, init] = fetchImpl.mock.calls[0] ?? [];
    expect(url).toBe("http://127.0.0.1:8787/audit?limit=50");
    expect(url).not.toContain(TOKEN);
    expect((init?.headers as Record<string, string>)["x-admin-token"]).toBe(TOKEN);
    expect(init?.credentials).toBe("omit");
  });

  it("a malformed 200 body is a `malformed` error, not data", async () => {
    const bad = { records: [{ ...attempt(), amountPaise: 1.5 }], nextCursor: null };
    const r = await client(() => Promise.resolve(jsonResponse(200, bad))).getAudit(50);
    expect(r).toMatchObject({ ok: false, error: { kind: "malformed" } });
  });

  it("non-JSON 200 ⇒ malformed; non-JSON 502 ⇒ http error", async () => {
    const text = (status: number) => () =>
      Promise.resolve(new Response("<html>oops</html>", { status }));
    expect(await client(text(200)).verify()).toMatchObject({
      ok: false,
      error: { kind: "malformed" },
    });
    expect(await client(text(502)).verify()).toMatchObject({
      ok: false,
      error: { kind: "http", status: 502, code: "http_502" },
    });
  });

  it("maps API errors and network failures", async () => {
    const r = await client(() =>
      Promise.resolve(
        jsonResponse(403, { error: { code: "api.approvals_disabled", message: "off" } }),
      ),
    ).decide(pending().approvalId, "approve");
    expect(r).toEqual({
      ok: false,
      error: { kind: "http", status: 403, code: "api.approvals_disabled", message: "off" },
    });
    const n = await client(() => Promise.reject(new TypeError("Failed to fetch"))).getMode();
    expect(n).toEqual({ ok: false, error: { kind: "network", message: "Failed to fetch" } });
  });

  it("refuses invalid ids before any request", async () => {
    const fetchImpl = vi.fn<FetchLike>();
    const c = client(fetchImpl);
    expect((await c.decide("../killswitch", "approve")).ok).toBe(false);
    expect((await c.getSession("a/b")).ok).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("posts the documented bodies for mode and kill switch", async () => {
    const fetchImpl = vi.fn<FetchLike>(() =>
      Promise.resolve(
        jsonResponse(200, { changed: true, mode: { killSwitch: true, shadow: false } }),
      ),
    );
    const c = client(fetchImpl);
    expect(await c.setKillSwitch(true)).toEqual({
      ok: true,
      value: { killSwitch: true, shadow: false },
    });
    await c.setMode("shadow");
    expect(fetchImpl.mock.calls.map(([u, i]) => [u, i.method, i.body])).toEqual([
      ["http://127.0.0.1:8787/killswitch", "POST", '{"on":true}'],
      ["http://127.0.0.1:8787/mode", "POST", '{"mode":"shadow"}'],
    ]);
  });
});
