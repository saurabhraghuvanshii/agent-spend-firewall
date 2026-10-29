import { vi } from "vitest";
import type { ApiClient, ApiResult } from "../api/client";
import type { AttemptView, PendingApproval } from "../api/schemas";

export const HASH = "a".repeat(64);
export const TOKEN = "t".repeat(40);

export function attempt(over: Partial<AttemptView> = {}): AttemptView {
  return {
    kind: "attempt",
    seq: 1,
    id: "att-1",
    ts: "2026-10-29T10:00:00.000Z",
    hash: HASH,
    sessionId: "sess-1",
    tool: "create_refund",
    decision: "allow",
    matchedRules: [],
    argsRedacted: { payment_id: "pay_1", amount: 50000 },
    amountPaise: 50000,
    reason: {
      untrusted: true,
      label: "Agent-supplied reason (untrusted)",
      text: '"duplicate charge"',
    },
    untrustedFields: ["reason", "argsRedacted", "originalArgsRedacted"],
    ...over,
  };
}

export function pending(over: Partial<PendingApproval> = {}): PendingApproval {
  return {
    approvalId: "apr_12345678-1234-1234-1234-123456789abc",
    attemptId: "att-1",
    sessionId: "sess-1",
    tool: "create_refund",
    ruleId: "big-refund-needs-approval",
    state: "pending",
    createdAt: "2026-10-29T10:00:00.000Z",
    expiresAt: "2026-10-29T10:15:00.000Z",
    argsRedacted: { payment_id: "pay_1", amount: 600000 },
    amountPaise: 600000,
    reason: {
      untrusted: true,
      label: "Agent-supplied reason (untrusted)",
      text: '"customer asked"',
    },
    untrustedFields: ["reason", "argsRedacted"],
    ...over,
  };
}

const notCalled = <T>(): Promise<ApiResult<T>> =>
  Promise.resolve({ ok: false, error: { kind: "network", message: "not stubbed" } });

export function fakeClient(over: Partial<ApiClient> = {}): ApiClient {
  return {
    baseUrl: "http://127.0.0.1:8787",
    token: TOKEN,
    fetchImpl: vi.fn(() => Promise.reject(new Error("no fetch in this test"))),
    getAudit: vi.fn(notCalled),
    verify: vi.fn(notCalled),
    getSession: vi.fn(notCalled),
    getApprovals: vi.fn(notCalled),
    decide: vi.fn(notCalled),
    getMode: vi.fn(notCalled),
    setKillSwitch: vi.fn(notCalled),
    setMode: vi.fn(notCalled),
    ...over,
  } as ApiClient;
}

export const jsonResponse = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
