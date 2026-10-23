/**
 * Typed results for crossing package boundaries without throwing (see AGENTS.md).
 * `FirewallError` is JSON-friendly so it can be logged or returned to an agent as-is.
 */
export type FirewallErrorDetail = string | number | boolean | null;

export interface FirewallError {
  /** Stable machine-readable code, e.g. `"canonical_json.non_integer"`. */
  readonly code: string;
  /** Human-readable explanation. Must never contain secrets. */
  readonly message: string;
  /** Optional flat, JSON-safe context (paths, indexes, …). */
  readonly details?: Readonly<Record<string, FirewallErrorDetail>>;
}

export type Result<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: FirewallError };

export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

export function err<T = never>(
  code: string,
  message: string,
  details?: Readonly<Record<string, FirewallErrorDetail>>,
): Result<T> {
  const error: FirewallError =
    details === undefined ? { code, message } : { code, message, details };
  return { ok: false, error };
}
