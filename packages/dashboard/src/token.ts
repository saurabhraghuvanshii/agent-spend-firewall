/**
 * The admin token (D-036 `x-admin-token`) is typed in by the human and kept in `sessionStorage` ONLY: it dies with the
 * tab, is never written to `localStorage`, never put in a URL and never logged.
 */
export const TOKEN_STORAGE_KEY = "asf.adminToken";

/** Printable ASCII without spaces (a valid header value), 32..512 chars like the API requires. */
export const TOKEN_RE = /^[\x21-\x7E]{32,512}$/;

export type TokenResult = { ok: true; value: string | undefined } | { ok: false; error: string };

const describe = (e: unknown): string => (e instanceof Error ? e.name : "error");

export function readToken(storage: Storage = window.sessionStorage): TokenResult {
  try {
    const t = storage.getItem(TOKEN_STORAGE_KEY);
    return { ok: true, value: t !== null && TOKEN_RE.test(t) ? t : undefined };
  } catch (e: unknown) {
    return { ok: false, error: `session storage is unavailable (${describe(e)})` };
  }
}

export function saveToken(
  token: string,
  storage: Storage = window.sessionStorage,
): { ok: true } | { ok: false; error: string } {
  if (!TOKEN_RE.test(token)) {
    return {
      ok: false,
      error: "The admin token must be 32 to 512 printable characters, no spaces.",
    };
  }
  try {
    storage.setItem(TOKEN_STORAGE_KEY, token);
    return { ok: true };
  } catch (e: unknown) {
    return { ok: false, error: `could not store the token in session storage (${describe(e)})` };
  }
}

export function clearToken(storage: Storage = window.sessionStorage): void {
  try {
    storage.removeItem(TOKEN_STORAGE_KEY);
  } catch (e: unknown) {
    // Nothing else to do: the tab's session storage dies with the tab anyway. Report, don't swallow.
    console.warn(`asf: could not clear the admin token (${describe(e)})`);
  }
}
