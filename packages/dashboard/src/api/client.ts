/**
 * Typed client for the dashboard API (T013, D-036). Every call:
 * - sends the admin token in the `x-admin-token` header (never in the URL), no cookies, no cache, no referrer;
 * - returns a `Result`, never throws: network failure, HTTP error (`{ error: { code, message } }`) and a response that
 *   fails zod validation (`malformed`) are distinct error kinds the UI shows as such.
 */
import type { z } from "zod";
import {
  approvalsSchema,
  auditPageSchema,
  decisionResponseSchema,
  errorBodySchema,
  modeResponseSchema,
  sessionSchema,
  setModeResponseSchema,
  verifySchema,
  type AuditPage,
  type DecisionResponse,
  type ModeState,
  type PendingApproval,
  type SessionView,
  type VerifyView,
} from "./schemas";

export const ADMIN_TOKEN_HEADER = "x-admin-token";
export const APPROVAL_ID_RE = /^apr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const SESSION_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

export type ApiError =
  | {
      readonly kind: "http";
      readonly status: number;
      readonly code: string;
      readonly message: string;
    }
  | { readonly kind: "network"; readonly message: string }
  | { readonly kind: "malformed"; readonly message: string }
  | { readonly kind: "invalid_input"; readonly message: string };

export type ApiResult<T> = { ok: true; value: T } | { ok: false; error: ApiError };

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface ApiClient {
  readonly baseUrl: string;
  readonly token: string;
  readonly fetchImpl: FetchLike;
  getAudit(limit: number): Promise<ApiResult<AuditPage>>;
  verify(): Promise<ApiResult<VerifyView>>;
  getSession(sessionId: string): Promise<ApiResult<SessionView>>;
  getApprovals(): Promise<ApiResult<PendingApproval[]>>;
  decide(approvalId: string, action: "approve" | "reject"): Promise<ApiResult<DecisionResponse>>;
  getMode(): Promise<ApiResult<ModeState>>;
  setKillSwitch(on: boolean): Promise<ApiResult<ModeState>>;
  setMode(mode: "enforce" | "shadow"): Promise<ApiResult<ModeState>>;
}

const MAX_RESPONSE_CHARS = 5_000_000;

export function describeError(e: ApiError): string {
  switch (e.kind) {
    case "http":
      return `${e.message} (HTTP ${String(e.status)}, ${e.code})`;
    case "network":
      return `Cannot reach the firewall API: ${e.message}`;
    case "malformed":
      return `The API sent an unexpected response: ${e.message}`;
    case "invalid_input":
      return e.message;
  }
}

function issuesOf(e: z.ZodError): string {
  return e.issues
    .slice(0, 3)
    .map((i) => `${i.path.length > 0 ? i.path.join(".") : "(root)"}: ${i.message}`)
    .join("; ");
}

export function createApiClient(o: {
  baseUrl: string;
  token: string;
  fetchImpl?: FetchLike;
}): ApiClient {
  const fetchImpl: FetchLike = o.fetchImpl ?? ((input, init) => fetch(input, init));

  async function request<T>(
    path: string,
    schema: z.ZodType<T>,
    init: { method: "GET" | "POST"; body?: unknown } = { method: "GET" },
  ): Promise<ApiResult<T>> {
    const headers: Record<string, string> = {
      [ADMIN_TOKEN_HEADER]: o.token,
      accept: "application/json",
    };
    if (init.body !== undefined) headers["content-type"] = "application/json";
    let res: Response;
    let text: string;
    try {
      res = await fetchImpl(`${o.baseUrl}${path}`, {
        method: init.method,
        headers,
        ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        redirect: "error",
      });
      text = await res.text();
    } catch (e: unknown) {
      return {
        ok: false,
        error: { kind: "network", message: e instanceof Error ? e.message : "request failed" },
      };
    }
    if (text.length > MAX_RESPONSE_CHARS) {
      return { ok: false, error: { kind: "malformed", message: "response too large" } };
    }
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch (e: unknown) {
      if (!res.ok) {
        return {
          ok: false,
          error: {
            kind: "http",
            status: res.status,
            code: `http_${String(res.status)}`,
            message: "request failed",
          },
        };
      }
      return {
        ok: false,
        error: {
          kind: "malformed",
          message: `not JSON (${e instanceof Error ? e.name : "parse error"})`,
        },
      };
    }
    if (!res.ok) {
      const err = errorBodySchema.safeParse(json);
      return {
        ok: false,
        error: err.success
          ? { kind: "http", status: res.status, ...err.data.error }
          : {
              kind: "http",
              status: res.status,
              code: `http_${String(res.status)}`,
              message: "request failed",
            },
      };
    }
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      return { ok: false, error: { kind: "malformed", message: issuesOf(parsed.error) } };
    }
    return { ok: true, value: parsed.data };
  }

  const map = async <A, B>(p: Promise<ApiResult<A>>, f: (a: A) => B): Promise<ApiResult<B>> => {
    const r = await p;
    return r.ok ? { ok: true, value: f(r.value) } : r;
  };

  return {
    baseUrl: o.baseUrl,
    token: o.token,
    fetchImpl,
    getAudit: (limit) => request(`/audit?limit=${String(limit)}`, auditPageSchema),
    verify: () => request("/audit/verify", verifySchema),
    getSession: (sessionId) => {
      if (!SESSION_ID_RE.test(sessionId)) {
        return Promise.resolve({
          ok: false,
          error: { kind: "invalid_input", message: "invalid session id" },
        });
      }
      return request(`/sessions/${encodeURIComponent(sessionId)}`, sessionSchema);
    },
    getApprovals: () =>
      map(request("/approvals?status=pending", approvalsSchema), (v) => v.approvals),
    decide: (approvalId, action) => {
      if (!APPROVAL_ID_RE.test(approvalId)) {
        return Promise.resolve({
          ok: false,
          error: { kind: "invalid_input", message: "invalid approval id" },
        });
      }
      return request(
        `/approvals/${encodeURIComponent(approvalId)}/${action}`,
        decisionResponseSchema,
        {
          method: "POST",
          body: {},
        },
      );
    },
    getMode: () => map(request("/mode", modeResponseSchema), (v) => v.mode),
    setKillSwitch: (on) =>
      map(
        request("/killswitch", setModeResponseSchema, { method: "POST", body: { on } }),
        (v) => v.mode,
      ),
    setMode: (mode) =>
      map(
        request("/mode", setModeResponseSchema, { method: "POST", body: { mode } }),
        (v) => v.mode,
      ),
  };
}
