/**
 * Signed, unguessable Telegram callback data (T011).
 *
 * Format (≤ 64 bytes, Telegram's `callback_data` limit): `v1.<a|r>.<nonce>.<mac>`
 * - `nonce`: 16 random bytes (base64url, 22 chars), unique per approval (stored in the approval row);
 * - `mac`: the first 16 bytes of HMAC-SHA256(secret, `v1.<a|r>.<nonce>`), base64url (22 chars).
 *
 * The action letter is covered by the MAC, so a Reject button's data can't be turned into an Approve. The secret is
 * 32 random bytes generated per proxy process (approvals don't survive a restart, D-034), so buttons from an earlier
 * run fail verification. Comparison is constant-time.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { NONCE_RE } from "./store.js";

export type CallbackAction = "approve" | "reject";

export interface CallbackSigner {
  /** Callback data for `action` on the approval with `nonce`. */
  sign(action: CallbackAction, nonce: string): string;
  /** `{action, nonce}` iff `data` is well-formed and carries a valid MAC; `undefined` otherwise. */
  verify(data: string): { action: CallbackAction; nonce: string } | undefined;
}

export const CALLBACK_DATA_RE = /^v1\.([ar])\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{22})$/;
export const MIN_SECRET_BYTES = 32;

/** A fresh random nonce (16 bytes, base64url). */
export function newNonce(): string {
  return randomBytes(16).toString("base64url");
}

/** @throws RangeError if `secret` is shorter than `MIN_SECRET_BYTES` (configuration error). */
export function createCallbackSigner(
  secret: Uint8Array = randomBytes(MIN_SECRET_BYTES),
): CallbackSigner {
  if (secret.byteLength < MIN_SECRET_BYTES) {
    throw new RangeError(`callback secret must be at least ${String(MIN_SECRET_BYTES)} bytes`);
  }
  const key = Buffer.from(secret);
  const macOf = (payload: string): Buffer =>
    createHmac("sha256", key).update(payload, "utf8").digest().subarray(0, 16);
  return {
    sign(action, nonce) {
      if (!NONCE_RE.test(nonce)) throw new RangeError("invalid nonce");
      const payload = `v1.${action === "approve" ? "a" : "r"}.${nonce}`;
      return `${payload}.${macOf(payload).toString("base64url")}`;
    },
    verify(data) {
      if (typeof data !== "string" || data.length > 64) return undefined;
      const m = CALLBACK_DATA_RE.exec(data);
      if (m === null) return undefined;
      const [, letter, nonce, mac] = m;
      if (letter === undefined || nonce === undefined || mac === undefined) return undefined;
      // Compare the canonical encodings (base64url decoding ignores the last char's spare bits).
      const given = Buffer.from(mac, "utf8");
      const expected = Buffer.from(macOf(`v1.${letter}.${nonce}`).toString("base64url"), "utf8");
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) return undefined;
      return { action: letter === "a" ? "approve" : "reject", nonce };
    },
  };
}
