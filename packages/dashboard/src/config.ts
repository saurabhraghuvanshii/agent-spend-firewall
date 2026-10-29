/**
 * API base URL: `VITE_ASF_API_URL` at build / dev time, default `http://127.0.0.1:8787`. Only an http(s) origin (plus
 * an optional path) is accepted: no credentials, query or fragment (the admin token never goes in a URL).
 */
export const DEFAULT_API_URL = "http://127.0.0.1:8787";

export type ConfigResult = { ok: true; value: string } | { ok: false; error: string };

export function resolveApiBaseUrl(raw: string | undefined): ConfigResult {
  const input = raw === undefined || raw.trim() === "" ? DEFAULT_API_URL : raw.trim();
  let url: URL;
  try {
    url = new URL(input);
  } catch (e: unknown) {
    return {
      ok: false,
      error: `VITE_ASF_API_URL is not a valid URL (${e instanceof Error ? e.name : "error"})`,
    };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "VITE_ASF_API_URL must be an http(s) URL" };
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    return {
      ok: false,
      error: "VITE_ASF_API_URL must not contain credentials, a query or a fragment",
    };
  }
  return { ok: true, value: `${url.origin}${url.pathname.replace(/\/+$/, "")}` };
}
