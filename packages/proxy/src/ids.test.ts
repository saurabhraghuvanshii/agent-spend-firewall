import { redactText } from "@asf/core";
import { describe, expect, it } from "vitest";
import { redactionSafeUuid } from "./ids.js";

const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("redactionSafeUuid", () => {
  it("returns v4 UUIDs that redactText leaves unchanged", () => {
    for (let i = 0; i < 2_000; i++) {
      const id = redactionSafeUuid();
      expect(id).toMatch(V4);
      expect(redactText(id)).toBe(id);
      const apr = redactionSafeUuid("apr_");
      expect(apr.startsWith("apr_")).toBe(true);
      expect(redactText(apr)).toBe(apr);
    }
  });

  it("redraws ids with a digit run", () => {
    const draws = ["12345678-1234-4234-8234-123456789012", "3f2a9c1e-7b4d-4e8a-9f0c-5d6e7a8b9c0d"];
    let n = 0;
    expect(redactionSafeUuid("", () => draws[n++] ?? "x")).toBe(draws[1]);
    expect(n).toBe(2);
  });

  it("gives up after a bounded number of draws (still returns an id)", () => {
    let n = 0;
    const bad = "12345678-1234-4234-8234-123456789012";
    expect(
      redactionSafeUuid("", () => {
        n++;
        return bad;
      }),
    ).toBe(bad);
    expect(n).toBe(64);
  });
});
