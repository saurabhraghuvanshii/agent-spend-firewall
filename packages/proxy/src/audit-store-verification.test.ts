/**
 * T010 audit store: verification records, attempt `retryOf`, latest verification in activity reads, the full scans
 * (`readUnsettled`, `listNeedsHuman`) and every new chain break reason (forced through raw inserts, since the store
 * itself refuses to write them).
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import {
  buildRecord,
  canonicalJson,
  type AuditBody,
  type AuditRecord,
  type Result,
  type VerifyBreakReason,
} from "@asf/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openAuditStore, type AuditStore, type RecordVerificationInput } from "./audit-store.js";
import { nodeHasher } from "./node-hasher.js";

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}
function code<T>(r: Result<T>): string {
  return r.ok ? "ok" : r.error.code;
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-verif-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const mem = (opts: { maxScanRows?: number } = {}): AuditStore =>
  unwrap(openAuditStore({ path: ":memory:", ...opts }));

function attempt(
  s: AuditStore,
  id: string,
  over: {
    tool?: string;
    decision?: "allow" | "deny" | "require_approval";
    retryOf?: string;
    ts?: string;
  } = {},
): Result<AuditRecord> {
  return s.recordAttempt({
    id,
    sessionId: "s",
    tool: over.tool ?? "create_refund",
    args: { payment_id: "pay_1", amount: 100 },
    reason: "reason long enough",
    decision: over.decision ?? "allow",
    matchedRules: ["r"],
    ...(over.retryOf === undefined ? {} : { retryOf: over.retryOf }),
    ...(over.ts === undefined ? {} : { ts: over.ts }),
  });
}
const outcome = (
  s: AuditStore,
  attemptId: string,
  o: "timeout" | "upstream_error" | "success" | "denied" = "timeout",
  ts?: string,
): Result<AuditRecord> =>
  s.recordOutcome({ attemptId, outcome: o, latencyMs: 1, ...(ts === undefined ? {} : { ts }) });
const verification = (
  s: AuditStore,
  attemptId: string,
  result: "happened" | "not_happened" | "unknown",
  over: Partial<RecordVerificationInput> = {},
): Result<AuditRecord> =>
  s.recordVerification({
    attemptId,
    trigger: "timeout",
    result,
    method: "refund_notes_marker",
    needsHuman: result === "unknown",
    ...over,
  });

describe("recordVerification", () => {
  it("requires an existing, non-deny attempt with an outcome; only `unknown` may be followed", () => {
    const s = mem();
    expect(code(verification(s, "nope", "unknown"))).toBe("audit.invalid_verification");
    unwrap(attempt(s, "d1", { decision: "deny" }));
    unwrap(outcome(s, "d1", "denied"));
    expect(code(verification(s, "d1", "unknown"))).toBe("audit.invalid_verification");
    unwrap(attempt(s, "a1"));
    expect(code(verification(s, "a1", "unknown"))).toBe("audit.invalid_verification");
    unwrap(outcome(s, "a1"));
    unwrap(verification(s, "a1", "unknown", { errorCode: "verify.not_found" }));
    unwrap(verification(s, "a1", "unknown", { trigger: "startup" }));
    unwrap(
      verification(s, "a1", "happened", {
        trigger: "late_response",
        upstreamRef: "rfnd_ABCdef1",
        needsHuman: false,
      }),
    );
    expect(code(verification(s, "a1", "not_happened"))).toBe("audit.invalid_verification");
    expect(code(verification(s, "a1", "unknown"))).toBe("audit.invalid_verification");
    const v = unwrap(s.verify());
    expect(v.ok).toBe(true);
    const rows = unwrap(s.readAll());
    expect(rows.at(-1)).toMatchObject({
      kind: "verification",
      attemptId: "a1",
      trigger: "late_response",
      result: "happened",
      method: "refund_notes_marker",
      needsHuman: false,
      upstreamRef: "rfnd_ABCdef1",
    });
  });

  it("a human verification needs a resolver; other triggers must not carry one; bad codes rejected", () => {
    const s = mem();
    unwrap(attempt(s, "a1"));
    unwrap(outcome(s, "a1"));
    expect(code(verification(s, "a1", "happened", { trigger: "human" }))).toBe(
      "audit.invalid_input",
    );
    expect(code(verification(s, "a1", "happened", { resolver: "telegram:42" }))).toBe(
      "audit.invalid_input",
    );
    expect(code(verification(s, "a1", "unknown", { errorCode: "Bad Code" }))).toBe(
      "audit.invalid_input",
    );
    expect(
      code(
        verification(s, "a1", "happened", { trigger: "human", resolver: "someone@example.com" }),
      ),
    ).toBe("audit.invalid_input");
    unwrap(
      verification(s, "a1", "not_happened", {
        trigger: "human",
        resolver: "telegram:42",
        method: "none",
      }),
    );
    expect(unwrap(s.verify()).ok).toBe(true);
  });
});

describe("attempt retryOf", () => {
  it("only after the original's latest verification is not_happened, same tool, once, never a retry of a retry", () => {
    const s = mem();
    expect(code(attempt(s, "r0", { retryOf: "missing" }))).toBe("audit.invalid_retry_of");
    unwrap(attempt(s, "o1"));
    unwrap(outcome(s, "o1"));
    expect(code(attempt(s, "r1", { retryOf: "o1" }))).toBe("audit.invalid_retry_of");
    unwrap(verification(s, "o1", "unknown"));
    expect(code(attempt(s, "r1", { retryOf: "o1" }))).toBe("audit.invalid_retry_of");
    unwrap(verification(s, "o1", "not_happened", { needsHuman: false }));
    expect(code(attempt(s, "r1", { retryOf: "o1", tool: "capture_payment" }))).toBe(
      "audit.invalid_retry_of",
    );
    const r1 = unwrap(attempt(s, "r1", { retryOf: "o1" }));
    expect(r1).toMatchObject({ kind: "attempt", retryOf: "o1" });
    expect(code(attempt(s, "r2", { retryOf: "o1" }))).toBe("audit.invalid_retry_of");
    unwrap(outcome(s, "r1"));
    unwrap(verification(s, "r1", "not_happened", { needsHuman: false }));
    expect(code(attempt(s, "r3", { retryOf: "r1" }))).toBe("audit.invalid_retry_of");
    expect(unwrap(s.verify()).ok).toBe(true);
    // Round trip.
    expect(unwrap(s.readAll()).find((r) => !("invalid" in r) && r.id === "r1")).toMatchObject({
      retryOf: "o1",
    });
  });

  it("legacy hashing unchanged: an attempt without retryOf has no such key", () => {
    const s = mem();
    const a = unwrap(attempt(s, "a1"));
    expect(Object.hasOwn(a, "retryOf")).toBe(false);
  });
});

describe("activity and scans", () => {
  const H = 3_600_000;
  const iso = (msAgo: number): string => new Date(Date.now() - msAgo).toISOString();

  it("readActivitySince carries the LATEST verification, also for an attempt older than the window", () => {
    const s = mem();
    unwrap(attempt(s, "old", { ts: iso(30 * H) }));
    unwrap(outcome(s, "old", "timeout", iso(30 * H)));
    unwrap(verification(s, "old", "unknown", { ts: iso(29 * H) }));
    unwrap(verification(s, "old", "happened", { ts: iso(H), needsHuman: false }));
    unwrap(attempt(s, "new"));
    const act = unwrap(s.readActivitySince(Date.now() - 2 * H));
    expect(act.map((a) => [a.attempt.id, a.outcome?.outcome, a.verification?.result])).toEqual([
      ["old", "timeout", "happened"],
      ["new", undefined, undefined],
    ]);
  });

  it("readUnsettled: open allow/transform, unsettled timeouts / upstream errors (incl. unknown); listNeedsHuman", () => {
    const s = mem();
    unwrap(attempt(s, "open"));
    unwrap(attempt(s, "pending", { decision: "require_approval" }));
    unwrap(attempt(s, "denied", { decision: "deny" }));
    unwrap(outcome(s, "denied", "denied"));
    unwrap(attempt(s, "t1"));
    unwrap(outcome(s, "t1", "timeout"));
    unwrap(attempt(s, "t2"));
    unwrap(outcome(s, "t2", "upstream_error"));
    unwrap(verification(s, "t2", "unknown"));
    unwrap(attempt(s, "t3"));
    unwrap(outcome(s, "t3", "timeout"));
    unwrap(verification(s, "t3", "not_happened", { needsHuman: false }));
    unwrap(attempt(s, "ok"));
    unwrap(outcome(s, "ok", "success"));
    const u = unwrap(s.readUnsettled());
    expect(u.open.map((a) => a.attempt.id)).toEqual(["open"]);
    expect(u.unsettled.map((a) => a.attempt.id)).toEqual(["t1", "t2"]);
    expect(unwrap(s.listNeedsHuman()).map((a) => a.attempt.id)).toEqual(["t2"]);
  });

  it("scans fail closed above the row cap", () => {
    const s = mem({ maxScanRows: 2 });
    unwrap(attempt(s, "a"));
    unwrap(outcome(s, "a"));
    unwrap(attempt(s, "b"));
    expect(code(s.readUnsettled())).toBe("audit.scan_too_large");
    expect(code(s.listNeedsHuman())).toBe("audit.scan_too_large");
  });
});

describe("chain break reasons (forced raw inserts)", () => {
  /** Append `body` bypassing the store's checks (correctly hashed and chained). */
  function forceAppend(path: string, body: AuditBody): void {
    const db = new Database(path);
    try {
      const head = db.prepare("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").get() as
        { seq: number; hash: string } | undefined;
      const rec = unwrap(buildRecord(nodeHasher, head ?? null, body));
      const canon = unwrap(canonicalJson(body));
      db.prepare(
        "INSERT INTO audit_log (seq, id, kind, body_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
      ).run(rec.seq, body.id, body.kind, canon, rec.prevHash, rec.hash);
    } finally {
      db.close();
    }
  }
  const ts = "2026-10-26T10:00:00.000Z";
  const vBody = (
    id: string,
    attemptId: string,
    result: "happened" | "not_happened" | "unknown",
  ): AuditBody => ({
    kind: "verification",
    id,
    attemptId,
    ts,
    trigger: "timeout",
    result,
    method: "refund_notes_marker",
    needsHuman: result === "unknown",
  });

  function brokenReason(setup: (s: AuditStore, path: string) => void): VerifyBreakReason | "ok" {
    const path = join(dir, `${String(Math.random()).slice(2)}.db`);
    const s = unwrap(openAuditStore({ path, clock: () => new Date(ts) }));
    try {
      setup(s, path);
      const v = unwrap(s.verify());
      return v.ok ? "ok" : v.brokenAt.reason;
    } finally {
      s.close();
    }
  }

  it("orphan_verification", () => {
    expect(brokenReason((_s, p) => forceAppend(p, vBody("v1", "ghost", "unknown")))).toBe(
      "orphan_verification",
    );
  });

  it("verification_before_outcome", () => {
    expect(
      brokenReason((s, p) => {
        unwrap(attempt(s, "a1"));
        forceAppend(p, vBody("v1", "a1", "unknown"));
      }),
    ).toBe("verification_before_outcome");
  });

  it("verification_after_settled", () => {
    expect(
      brokenReason((s, p) => {
        unwrap(attempt(s, "a1"));
        unwrap(outcome(s, "a1"));
        unwrap(verification(s, "a1", "happened", { needsHuman: false }));
        forceAppend(p, vBody("v2", "a1", "unknown"));
      }),
    ).toBe("verification_after_settled");
  });

  it("bad_retry_of (original not verified not_happened)", () => {
    expect(
      brokenReason((s, p) => {
        unwrap(attempt(s, "a1"));
        unwrap(outcome(s, "a1"));
        forceAppend(p, {
          kind: "attempt",
          id: "r1",
          ts,
          sessionId: "s",
          tool: "create_refund",
          argsRedacted: { amount: 100 },
          reason: "x",
          decision: "allow",
          matchedRules: [],
          retryOf: "a1",
        });
      }),
    ).toBe("bad_retry_of");
  });

  it("a valid verify-then-retry sequence written by the store verifies", () => {
    expect(
      brokenReason((s) => {
        unwrap(attempt(s, "a1"));
        unwrap(outcome(s, "a1"));
        unwrap(verification(s, "a1", "not_happened", { needsHuman: false }));
        unwrap(attempt(s, "r1", { retryOf: "a1" }));
        unwrap(outcome(s, "r1", "success"));
      }),
    ).toBe("ok");
  });
});
