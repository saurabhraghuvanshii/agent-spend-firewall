/**
 * Request guards for the dashboard API (T013, D-036).
 *
 * - Admin token: `x-admin-token` must equal `ASF_ADMIN_TOKEN`, compared in constant time (SHA-256 of both sides, then
 *   `timingSafeEqual`, so neither the content nor the length leaks through timing). A missing / short / placeholder
 *   token disables every authenticated route (fail closed, 503).
 * - DNS rebinding: the `Host` header must be one of the loopback names for the bound port.
 * - CSRF / cross-origin: a request carrying an `Origin` must come from the allow-list (default: the API itself plus
 *   the Vite dev server on loopback). No wildcard CORS, ever.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { err, ok, type Result } from "@asf/core";

export const MIN_ADMIN_TOKEN_CHARS = 32;
export const MAX_ADMIN_TOKEN_CHARS = 256;
/** Placeholder values that must never work as a token (e.g. the `.env.example` value). */
export const PLACEHOLDER_TOKENS: ReadonlySet<string> = new Set(["change-me", "changeme", "admin"]);
const TOKEN_RE = /^[\x21-\x7e]+$/;

/** `ASF_ADMIN_TOKEN` ⇒ the token, or `err` (the API then refuses every authenticated route). */
export function parseAdminToken(raw: string | undefined): Result<string> {
  if (raw === undefined || raw === "")
    return err("api.admin_token_unset", "ASF_ADMIN_TOKEN is not set");
  if (PLACEHOLDER_TOKENS.has(raw.toLowerCase())) {
    return err("api.admin_token_weak", "ASF_ADMIN_TOKEN is a placeholder value");
  }
  if (raw.length < MIN_ADMIN_TOKEN_CHARS || raw.length > MAX_ADMIN_TOKEN_CHARS) {
    return err(
      "api.admin_token_weak",
      `ASF_ADMIN_TOKEN must be ${String(MIN_ADMIN_TOKEN_CHARS)}..${String(MAX_ADMIN_TOKEN_CHARS)} characters (e.g. openssl rand -hex 32)`,
    );
  }
  if (!TOKEN_RE.test(raw)) {
    return err("api.admin_token_weak", "ASF_ADMIN_TOKEN must be printable ASCII without spaces");
  }
  return ok(raw);
}

const digest = (s: string): Buffer => createHash("sha256").update(s, "utf8").digest();

/** Constant-time token check. `presented` undefined ⇒ false. */
export function tokenMatches(expected: string, presented: string | undefined): boolean {
  if (presented === undefined) return false;
  return timingSafeEqual(digest(expected), digest(presented));
}

export const LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "::1"] as const;
export type LoopbackHost = (typeof LOOPBACK_HOSTS)[number];

export function isLoopbackHost(h: string): h is LoopbackHost {
  return (LOOPBACK_HOSTS as readonly string[]).includes(h);
}

/** Exact `Host` header values accepted for an API bound to `port`. */
export function allowedHostHeaders(port: number): ReadonlySet<string> {
  const p = String(port);
  return new Set([`127.0.0.1:${p}`, `localhost:${p}`, `[::1]:${p}`]);
}

const ORIGIN_RE = /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?$/;

/** The API's own origins plus the Vite dev server default. */
export function defaultAllowedOrigins(port: number): string[] {
  const p = String(port);
  return [
    `http://127.0.0.1:${p}`,
    `http://localhost:${p}`,
    "http://127.0.0.1:5173",
    "http://localhost:5173",
  ];
}

/**
 * `ASF_API_ALLOWED_ORIGINS`: comma-separated loopback origins (`http(s)://127.0.0.1|localhost|[::1][:port]`), exact
 * match. Unset ⇒ `defaultAllowedOrigins`. Any other origin (or `*`) ⇒ `err` (refuse to start).
 */
export function parseAllowedOrigins(raw: string | undefined, port: number): Result<string[]> {
  if (raw === undefined || raw.trim() === "") return ok(defaultAllowedOrigins(port));
  const out: string[] = [];
  for (const part of raw.split(",")) {
    const o = part.trim();
    if (!ORIGIN_RE.test(o)) {
      return err(
        "api.bad_origins",
        "ASF_API_ALLOWED_ORIGINS must list loopback origins like http://localhost:5173 (no wildcards)",
      );
    }
    out.push(o);
  }
  return ok(out);
}

export const MIN_API_PORT = 1024;
export const MAX_API_PORT = 65535;

export function parseApiPort(raw: string | undefined): Result<number | undefined> {
  if (raw === undefined || raw === "") return ok(undefined);
  if (!/^[0-9]{1,5}$/.test(raw)) return err("api.bad_port", "ASF_API_PORT must be an integer port");
  const n = Number(raw);
  if (n < MIN_API_PORT || n > MAX_API_PORT) {
    return err(
      "api.bad_port",
      `ASF_API_PORT must be between ${String(MIN_API_PORT)} and ${String(MAX_API_PORT)}`,
    );
  }
  return ok(n);
}

/** `ASF_API_HOST`: loopback only (default `127.0.0.1`). */
export function parseApiHost(raw: string | undefined): Result<LoopbackHost> {
  if (raw === undefined || raw === "") return ok("127.0.0.1");
  if (!isLoopbackHost(raw)) {
    return err(
      "api.bad_host",
      "ASF_API_HOST must be a loopback address (127.0.0.1, localhost or ::1); the API is not meant to be exposed",
    );
  }
  return ok(raw);
}
