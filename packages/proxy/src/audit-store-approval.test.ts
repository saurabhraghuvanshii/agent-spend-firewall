import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Result } from "@asf/core";
import {
  openAuditStore,
  type AuditStore,
  type RecordApprovalInput,
  type RecordAttemptInput,
} from "./audit-store.js";

let dir: string;
const opened: AuditStore[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-audit-approval-"));
});

afterEach(() => {
  for (const s of opened.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r.value;
}

function codeOf(r: Result<unknown>): string | undefined {
  return r.ok ? undefined : r.error.code;
}

function open(): AuditStore {
  let n = 0;
  const s = unwrap(
    openAuditStore({
      path: join(dir, "audit.db"),
      clock: () => new Date("2026-10-23T10:00:00.000Z"),
      idGen: () => `gen-${String(++n)}`,
    }),
  );
  opened.push(s);
  return s;
}

const attempt = (over: Partial<RecordAttemptInput> = {}): RecordAttemptInput => ({
  sessionId: "sess-1",
  tool: "create_refund",
  args: { payment_id: "pay_123", amount: 300_000 },
  reason: "customer reported a duplicate charge",
  decision: "require_approval",
  matchedRules: ["refund.approval"],
  id: "att-1",
  ...over,
});

const approval = (over: Partial<RecordApprovalInput> = {}): RecordApprovalInput => ({
  attemptId: "att-1",
  approvalId: "apr_1",
  decision: "approved",
  approver: "telegram:42",
  ...over,
});

function verifyOk(s: AuditStore): void {
  const v = unwrap(s.verify());
  if (!v.ok) throw new Error(`chain broken at seq ${String(v.brokenAt.seq)}: ${v.brokenAt.reason}`);
}

describe("recordApproval (T011)", () => {
  it("records approved ⇒ success and the chain verifies", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt()));
    const rec = unwrap(s.recordApproval(approval()));
    expect(rec).toMatchObject({ kind: "approval", decision: "approved", approver: "telegram:42" });
    unwrap(s.recordOutcome({ attemptId: "att-1", outcome: "success", latencyMs: 5 }));
    verifyOk(s);
  });

  it("refuses a sent outcome without an approved record", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt()));
    for (const outcome of ["success", "upstream_error", "timeout"] as const) {
      expect(codeOf(s.recordOutcome({ attemptId: "att-1", outcome, latencyMs: 1 }))).toBe(
        "audit.inconsistent_outcome",
      );
    }
    // Nothing sent (approval service unavailable) needs no approval.
    unwrap(s.recordOutcome({ attemptId: "att-1", outcome: "not_forwarded", latencyMs: 0 }));
    verifyOk(s);
  });

  it("rejected / expired ⇒ only a not_forwarded outcome", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordAttempt(attempt({ id: "att-2" })));
    unwrap(s.recordApproval(approval({ decision: "rejected" })));
    const expired = approval({ attemptId: "att-2", approvalId: "apr_2", decision: "expired" });
    delete expired.approver;
    unwrap(s.recordApproval(expired));
    for (const outcome of ["success", "timeout", "denied"] as const) {
      expect(codeOf(s.recordOutcome({ attemptId: "att-1", outcome, latencyMs: 0 }))).toBe(
        "audit.inconsistent_outcome",
      );
    }
    unwrap(
      s.recordOutcome({
        attemptId: "att-1",
        outcome: "not_forwarded",
        errorCode: "approval.rejected",
        latencyMs: 0,
      }),
    );
    unwrap(
      s.recordOutcome({
        attemptId: "att-2",
        outcome: "not_forwarded",
        errorCode: "approval.expired",
        latencyMs: 0,
      }),
    );
    verifyOk(s);
  });

  it("is single-use and only for open, non-retry require_approval attempts", () => {
    const s = open();
    expect(codeOf(s.recordApproval(approval()))).toBe("audit.invalid_approval");
    unwrap(s.recordAttempt(attempt({ id: "allow-1", decision: "allow" })));
    expect(codeOf(s.recordApproval(approval({ attemptId: "allow-1" })))).toBe(
      "audit.invalid_approval",
    );
    unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordApproval(approval()));
    expect(codeOf(s.recordApproval(approval({ approvalId: "apr_x" })))).toBe(
      "audit.invalid_approval",
    );
    unwrap(s.recordAttempt(attempt({ id: "att-3" })));
    unwrap(s.recordOutcome({ attemptId: "att-3", outcome: "not_forwarded", latencyMs: 0 }));
    expect(codeOf(s.recordApproval(approval({ attemptId: "att-3" })))).toBe(
      "audit.invalid_approval",
    );
    verifyOk(s);
  });

  it("validates its input (approver required unless expired, never PII)", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt()));
    const noApprover = approval();
    delete noApprover.approver;
    expect(codeOf(s.recordApproval(noApprover))).toBe("audit.invalid_input");
    expect(codeOf(s.recordApproval(approval({ decision: "expired" })))).toBe("audit.invalid_input");
    expect(codeOf(s.recordApproval(approval({ approver: "bob@example.com" })))).toBe(
      "audit.invalid_input",
    );
    expect(codeOf(s.recordApproval(approval({ approvalId: "bad id!" })))).toBe(
      "audit.invalid_input",
    );
  });

  it("a retry of an approved attempt may succeed (inherits the approval)", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordApproval(approval()));
    unwrap(s.recordOutcome({ attemptId: "att-1", outcome: "timeout", latencyMs: 10 }));
    unwrap(
      s.recordVerification({
        attemptId: "att-1",
        trigger: "timeout",
        result: "not_happened",
        method: "refund_notes_marker",
        needsHuman: false,
      }),
    );
    unwrap(s.recordAttempt(attempt({ id: "att-r", retryOf: "att-1" })));
    expect(codeOf(s.recordApproval(approval({ attemptId: "att-r" })))).toBe(
      "audit.invalid_approval",
    );
    unwrap(s.recordOutcome({ attemptId: "att-r", outcome: "success", latencyMs: 3 }));
    verifyOk(s);
  });
});

describe("readAttempt / activity / unsettled with approvals (T011)", () => {
  it("readAttempt joins outcome, verification and approval", () => {
    const s = open();
    expect(unwrap(s.readAttempt("nope"))).toBeUndefined();
    expect(codeOf(s.readAttempt("bad id!"))).toBe("audit.invalid_input");
    unwrap(s.recordAttempt(attempt()));
    expect(unwrap(s.readAttempt("att-1"))).toMatchObject({ attempt: { id: "att-1" } });
    unwrap(s.recordApproval(approval()));
    unwrap(s.recordOutcome({ attemptId: "att-1", outcome: "timeout", latencyMs: 10 }));
    const a = unwrap(s.readAttempt("att-1"));
    expect(a?.approval?.decision).toBe("approved");
    expect(a?.outcome?.outcome).toBe("timeout");
    expect(a?.verification).toBeUndefined();
  });

  it("readActivitySince and readUnsettled carry the approval", () => {
    const s = open();
    unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordApproval(approval()));
    unwrap(s.recordAttempt(attempt({ id: "att-pending" })));
    unwrap(s.recordAttempt(attempt({ id: "att-rejected" })));
    unwrap(
      s.recordApproval(
        approval({ attemptId: "att-rejected", approvalId: "apr_r", decision: "rejected" }),
      ),
    );
    const rows = unwrap(s.readActivitySince(0));
    expect(rows.map((r) => [r.attempt.id, r.approval?.decision])).toEqual([
      ["att-1", "approved"],
      ["att-pending", undefined],
      ["att-rejected", "rejected"],
    ]);
    const u = unwrap(s.readUnsettled());
    expect(u.open.map((a) => a.attempt.id)).toEqual(["att-1"]);
    expect(u.staleApprovals.map((a) => a.attempt.id)).toEqual(["att-pending", "att-rejected"]);
  });

  it("readActivitySince finds an approval written before the window for an attempt in it", () => {
    let now = Date.parse("2026-10-23T10:00:00.000Z");
    const s = unwrap(openAuditStore({ path: join(dir, "w.db"), clock: () => new Date(now) }));
    opened.push(s);
    unwrap(s.recordAttempt(attempt()));
    unwrap(s.recordApproval(approval()));
    now += 60 * 60 * 1000;
    unwrap(s.recordOutcome({ attemptId: "att-1", outcome: "success", latencyMs: 1 }));
    const rows = unwrap(s.readActivitySince(now - 1000));
    expect(rows[0]?.approval?.decision).toBe("approved");
  });
});
