import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import type { Result } from "@asf/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { newNonce } from "./callback-token.js";
import { openApprovalStore, type ApprovalStore, type CreateApprovalInput } from "./store.js";

let dir: string;
const opened: ApprovalStore[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-approvals-"));
});
afterEach(() => {
  for (const s of opened.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}
const codeOf = (r: Result<unknown>): string | undefined => (r.ok ? undefined : r.error.code);

const T0 = 1_000_000;
const MIN = 60_000;

function open(path = join(dir, "nested", "approvals.db")): ApprovalStore {
  const s = unwrap(openApprovalStore({ path }));
  opened.push(s);
  return s;
}

const input = (over: Partial<CreateApprovalInput> = {}): CreateApprovalInput => ({
  approvalId: "apr_1",
  attemptId: "att-1",
  sessionId: "sess",
  tool: "create_refund",
  argsHash: "a".repeat(64),
  ruleId: "refund.approval",
  callbackNonce: newNonce(),
  createdAtMs: T0,
  expiresAtMs: T0 + 30 * MIN,
  ...over,
});

describe("approval store", () => {
  it("creates a pending approval and reads it by id, nonce and attempt", () => {
    const s = open();
    const row = unwrap(s.create(input()));
    expect(row).toMatchObject({
      approvalId: "apr_1",
      state: "pending",
      expiresAtMs: T0 + 30 * MIN,
    });
    expect(unwrap(s.get("apr_1"))?.attemptId).toBe("att-1");
    expect(unwrap(s.getByNonce(row.callbackNonce))?.approvalId).toBe("apr_1");
    expect(unwrap(s.getByAttempt("att-1"))?.approvalId).toBe("apr_1");
    expect(unwrap(s.get("apr_missing"))).toBeUndefined();
    expect(unwrap(s.getByNonce("not a nonce"))).toBeUndefined();
  });

  it("rejects invalid input and duplicate ids / attempts / nonces", () => {
    const s = open();
    expect(codeOf(s.create(input({ approvalId: "bad id!" })))).toBe("approval.invalid_input");
    expect(codeOf(s.create(input({ argsHash: "x" })))).toBe("approval.invalid_input");
    expect(codeOf(s.create(input({ expiresAtMs: T0 })))).toBe("approval.invalid_input");
    expect(codeOf(s.create(input({ createdAtMs: 1.5 })))).toBe("approval.invalid_input");
    const first = unwrap(s.create(input()));
    expect(codeOf(s.create(input()))).toBe("approval.store_failed");
    expect(codeOf(s.create(input({ approvalId: "apr_2" })))).toBe("approval.store_failed");
    expect(
      codeOf(
        s.create(
          input({ approvalId: "apr_3", attemptId: "att-3", callbackNonce: first.callbackNonce }),
        ),
      ),
    ).toBe("approval.store_failed");
  });

  it("decide is single-use: a double approve (or approve then reject) only wins once", () => {
    const s = open();
    unwrap(s.create(input()));
    const a = unwrap(s.decide("apr_1", "approved", "telegram:42", T0 + MIN));
    expect(a.won).toBe(true);
    expect(a.row).toMatchObject({
      state: "approved",
      decidedBy: "telegram:42",
      decidedAtMs: T0 + MIN,
    });
    const again = unwrap(s.decide("apr_1", "approved", "telegram:42", T0 + MIN));
    expect(again.won).toBe(false);
    const reject = unwrap(s.decide("apr_1", "rejected", "telegram:42", T0 + MIN));
    expect(reject).toMatchObject({ won: false, row: { state: "approved" } });
    expect(unwrap(s.expire("apr_1", T0 + 60 * MIN, true)).won).toBe(false);
  });

  it("an expired approval can't be approved; it can only expire", () => {
    const s = open();
    unwrap(s.create(input()));
    const late = unwrap(s.decide("apr_1", "approved", "telegram:42", T0 + 30 * MIN));
    expect(late).toMatchObject({ won: false, row: { state: "pending" } });
    expect(unwrap(s.expire("apr_1", T0 + 29 * MIN)).won).toBe(false); // not due yet
    const e = unwrap(s.expire("apr_1", T0 + 30 * MIN));
    expect(e).toMatchObject({ won: true, row: { state: "expired" } });
    expect(unwrap(s.decide("apr_1", "approved", "telegram:42", T0)).won).toBe(false);
  });

  it("force-expires a pending approval (restart / notification failure)", () => {
    const s = open();
    unwrap(s.create(input()));
    expect(unwrap(s.expire("apr_1", T0, true))).toMatchObject({
      won: true,
      row: { state: "expired" },
    });
  });

  it("decide validates its input and reports unknown approvals", () => {
    const s = open();
    unwrap(s.create(input()));
    expect(codeOf(s.decide("apr_1", "approved", "bob@example.com", T0))).toBe(
      "approval.invalid_input",
    );
    expect(codeOf(s.decide("apr_1", "maybe" as "approved", "telegram:1", T0))).toBe(
      "approval.invalid_input",
    );
    expect(codeOf(s.decide("apr_1", "approved", "telegram:1", -1))).toBe("approval.invalid_input");
    expect(codeOf(s.decide("apr_nope", "approved", "telegram:1", T0))).toBe("approval.not_found");
  });

  it("concurrent connections: exactly one decision wins", () => {
    const path = join(dir, "shared.db");
    const a = open(path);
    const b = open(path);
    unwrap(a.create(input()));
    const r1 = unwrap(a.decide("apr_1", "approved", "telegram:1", T0 + 1));
    const r2 = unwrap(b.decide("apr_1", "rejected", "telegram:2", T0 + 1));
    expect([r1.won, r2.won]).toEqual([true, false]);
    expect(r2.row.state).toBe("approved");
  });

  it("a final state can't be changed even by raw SQL; rows can't be deleted", () => {
    const path = join(dir, "raw.db");
    const s = open(path);
    unwrap(s.create(input()));
    unwrap(s.decide("apr_1", "rejected", "telegram:1", T0 + 1));
    const db = new Database(path);
    try {
      expect(() => db.prepare("UPDATE approvals SET state = 'approved'").run()).toThrow(/final/);
      expect(() => db.prepare("DELETE FROM approvals").run()).toThrow(/never deleted/);
    } finally {
      db.close();
    }
  });

  it("lists due and pending approvals", () => {
    const s = open();
    unwrap(s.create(input()));
    unwrap(
      s.create(
        input({
          approvalId: "apr_2",
          attemptId: "att-2",
          callbackNonce: newNonce(),
          expiresAtMs: T0 + MIN,
        }),
      ),
    );
    expect(unwrap(s.listDue(T0 + MIN)).map((r) => r.approvalId)).toEqual(["apr_2"]);
    expect(unwrap(s.listPending()).map((r) => r.approvalId)).toEqual(["apr_1", "apr_2"]);
    unwrap(s.decide("apr_1", "approved", "telegram:1", T0));
    expect(unwrap(s.listUnfinished()).map((r) => r.approvalId)).toEqual(["apr_1"]);
    unwrap(s.setExecution("apr_1", { status: "executed" }));
    expect(unwrap(s.listUnfinished())).toEqual([]);
    expect(codeOf(s.listDue(T0, 0))).toBe("approval.invalid_input");
  });

  it("records the message id once and the execution status only for approved rows", () => {
    const s = open();
    unwrap(s.create(input()));
    unwrap(s.setMessageId("apr_1", 77));
    unwrap(s.setMessageId("apr_1", 99)); // ignored: already set
    expect(unwrap(s.get("apr_1"))?.messageId).toBe(77);
    expect(codeOf(s.setMessageId("apr_1", 0))).toBe("approval.invalid_input");
    expect(codeOf(s.setExecution("apr_1", { status: "executing" }))).toBe("approval.not_approved");
    unwrap(s.decide("apr_1", "approved", "telegram:1", T0 + 1));
    unwrap(s.setExecution("apr_1", { status: "executed", upstreamRef: "rfnd_ABC" }));
    expect(unwrap(s.get("apr_1"))?.execution).toEqual({
      status: "executed",
      upstreamRef: "rfnd_ABC",
    });
    // A final status is never overwritten.
    expect(codeOf(s.setExecution("apr_1", { status: "unknown" }))).toBe("approval.not_approved");
    expect(codeOf(s.setExecution("apr_1", { status: "executed", code: "Bad Code" }))).toBe(
      "approval.invalid_input",
    );
  });

  it("fails closed once closed", () => {
    const s = open();
    s.close();
    expect(codeOf(s.get("apr_1"))).toBe("approval.store_closed");
    expect(codeOf(s.decide("apr_1", "approved", "telegram:1", T0))).toBe("approval.store_closed");
  });

  it("reports an open failure", () => {
    expect(codeOf(openApprovalStore({ path: join(dir, "\0bad") }))).toBe(
      "approval.store_open_failed",
    );
  });
});
