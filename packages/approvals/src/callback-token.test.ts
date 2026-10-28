import { describe, expect, it } from "vitest";
import { createCallbackSigner, newNonce } from "./callback-token.js";

const SECRET = new Uint8Array(32).fill(7);

describe("callback signer", () => {
  it("round-trips both actions within Telegram's 64-byte limit", () => {
    const s = createCallbackSigner(SECRET);
    const nonce = newNonce();
    const a = s.sign("approve", nonce);
    const r = s.sign("reject", nonce);
    expect(Buffer.byteLength(a)).toBeLessThanOrEqual(64);
    expect(s.verify(a)).toEqual({ action: "approve", nonce });
    expect(s.verify(r)).toEqual({ action: "reject", nonce });
  });

  it("rejects tampered data: flipped action, nonce or MAC characters", () => {
    const s = createCallbackSigner(SECRET);
    const nonce = newNonce();
    const r = s.sign("reject", nonce);
    expect(s.verify(r.replace("v1.r.", "v1.a."))).toBeUndefined();
    const other = newNonce();
    expect(s.verify(r.replace(nonce, other))).toBeUndefined();
    // Every single-character change of the MAC (incl. the last char's spare bits) is refused.
    const mac = r.slice(-22);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (let i = 0; i < 22; i++) {
      for (const c of alphabet) {
        if (c === mac[i]) continue;
        const forged = r.slice(0, -22) + mac.slice(0, i) + c + mac.slice(i + 1);
        expect(s.verify(forged)).toBeUndefined();
      }
    }
  });

  it("rejects data signed with another secret (e.g. an earlier proxy run)", () => {
    const nonce = newNonce();
    const old = createCallbackSigner(new Uint8Array(32).fill(1)).sign("approve", nonce);
    expect(createCallbackSigner(SECRET).verify(old)).toBeUndefined();
    // Default secrets are random per signer.
    expect(
      createCallbackSigner().verify(createCallbackSigner().sign("approve", nonce)),
    ).toBeUndefined();
  });

  it("rejects malformed data and refuses short secrets / bad nonces", () => {
    const s = createCallbackSigner(SECRET);
    for (const bad of [
      "",
      "approve",
      "v1.a.x.y",
      "v2.a." + "A".repeat(22) + "." + "A".repeat(22),
      "x".repeat(65),
    ]) {
      expect(s.verify(bad)).toBeUndefined();
    }
    expect(() => createCallbackSigner(new Uint8Array(16))).toThrow(RangeError);
    expect(() => s.sign("approve", "short")).toThrow(RangeError);
  });

  it("nonces are 22-char base64url and unique", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const n = newNonce();
      expect(n).toMatch(/^[A-Za-z0-9_-]{22}$/);
      seen.add(n);
    }
    expect(seen.size).toBe(200);
  });
});
