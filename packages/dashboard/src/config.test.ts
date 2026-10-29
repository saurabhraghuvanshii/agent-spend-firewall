import { describe, expect, it } from "vitest";
import { DEFAULT_API_URL, resolveApiBaseUrl } from "./config";

describe("resolveApiBaseUrl", () => {
  it("defaults to loopback 8787 and strips a trailing slash", () => {
    expect(resolveApiBaseUrl(undefined)).toEqual({ ok: true, value: DEFAULT_API_URL });
    expect(resolveApiBaseUrl("http://localhost:9000/")).toEqual({
      ok: true,
      value: "http://localhost:9000",
    });
  });

  it.each([
    "ftp://x",
    "not a url",
    "http://u:p@127.0.0.1:1",
    "http://127.0.0.1:1/?token=x",
    "javascript:alert(1)",
  ])("rejects %s", (raw) => {
    expect(resolveApiBaseUrl(raw).ok).toBe(false);
  });
});
