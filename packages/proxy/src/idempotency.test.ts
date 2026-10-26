import { canonicalJson, redact, type JsonValue } from "@asf/core";
import { describe, expect, it } from "vitest";
import {
  openAuditStore,
  type AuditActivity,
  type AuditAttemptRecord,
  type AuditDecisionInput,
  type AuditOutcomeInput,
} from "./audit-store.js";
import {
  DUPLICATE_MESSAGES,
  findDuplicate,
  IDEMPOTENCY_FIELDS,
  IDEMPOTENCY_FREE_TEXT_FIELDS,
  IDEMPOTENCY_KEY_VERSION,
  idempotencyKey,
  idempotencyKeyFromRedacted,
  type FindDuplicateOpts,
} from "./idempotency.js";
import { nodeHasher } from "./node-hasher.js";

function key(tool: string, args: unknown): string {
  const k = idempotencyKey(tool, args);
  if (!k.ok) throw new Error(`key failed: ${k.error.code}`);
  return k.value;
}

describe("idempotencyKey", () => {
  it("is 64 lowercase hex and equals sha256(canonicalJson({v:1, tool, key}))", () => {
    const k = key("create_refund", { payment_id: "pay_A1", amount: 500 });
    expect(k).toMatch(/^[0-9a-f]{64}$/);
    const canon = canonicalJson({
      v: 1,
      tool: "create_refund",
      key: { payment_id: "pay_A1", amount: 500 },
    });
    expect(canon.ok && nodeHasher.sha256Hex(canon.value)).toBe(k);
  });

  it("is stable under key order", () => {
    expect(key("create_payment_link", { amount: 100, description: "x", currency: "INR" })).toBe(
      key("create_payment_link", { currency: "INR", description: "x", amount: 100 }),
    );
    expect(key("create_refund", { amount: 1, payment_id: "pay_A1" })).toBe(
      key("create_refund", { payment_id: "pay_A1", amount: 1 }),
    );
  });

  it("refund key ignores receipt / notes / speed / reason", () => {
    const base = key("create_refund", { payment_id: "pay_A1", amount: 500 });
    expect(
      key("create_refund", {
        payment_id: "pay_A1",
        amount: 500,
        receipt: "r-1",
        notes: { why: "dup", ratio: 1.5 },
        speed: "optimum",
        reason: "a long enough reason for the refund",
      }),
    ).toBe(base);
  });

  it("different amount or payment_id ⇒ different key; tool is part of the key", () => {
    const base = key("create_refund", { payment_id: "pay_A1", amount: 500 });
    expect(key("create_refund", { payment_id: "pay_A1", amount: 501 })).not.toBe(base);
    expect(key("create_refund", { payment_id: "pay_B2", amount: 500 })).not.toBe(base);
    expect(key("capture_payment", { payment_id: "pay_A1", amount: 500 })).not.toBe(base);
  });

  it("missing key field is still deterministic (absent)", () => {
    expect(key("create_refund", { payment_id: "pay_A1" })).toBe(
      key("create_refund", { payment_id: "pay_A1", notes: { a: "b" } }),
    );
    expect(key("create_refund", { payment_id: "pay_A1" })).not.toBe(
      key("create_refund", { payment_id: "pay_A1", amount: 1 }),
    );
  });

  it("create_instant_settlement keys on amount only; capture_payment on payment_id + amount", () => {
    expect(key("create_instant_settlement", { amount: 500, description: "a" })).toBe(
      key("create_instant_settlement", { amount: 500, settle_full_balance: false }),
    );
    expect(key("capture_payment", { payment_id: "pay_A1", amount: 5, currency: "INR" })).toBe(
      key("capture_payment", { payment_id: "pay_A1", amount: 5 }),
    );
    expect(Object.isFrozen(IDEMPOTENCY_FIELDS)).toBe(true);
  });

  it("unlisted tools use all args except the top-level free-text fields", () => {
    expect(Object.isFrozen(IDEMPOTENCY_FREE_TEXT_FIELDS)).toBe(true);
    expect([...IDEMPOTENCY_FREE_TEXT_FIELDS].sort()).toEqual([
      "description",
      "notes",
      "receipt",
      "reference_id",
    ]);
    for (const tool of ["create_payment_link", "initiate_payment", "create_qr_code", "x_new"]) {
      const base = key(tool, { amount: 100, currency: "INR" });
      for (const f of IDEMPOTENCY_FREE_TEXT_FIELDS) {
        expect(key(tool, { amount: 100, currency: "INR", [f]: "a" })).toBe(base);
        expect(key(tool, { amount: 100, currency: "INR", [f]: { k: "b" } })).toBe(base);
      }
      expect(key(tool, { amount: 101, currency: "INR", notes: "a" })).not.toBe(base);
    }
    // exact top-level names only: nested or case variants still count (unknown extra keys: T020)
    const c = key("create_payment_link", { amount: 100, meta: { description: "a" } });
    expect(key("create_payment_link", { amount: 100, meta: { description: "b" } })).not.toBe(c);
    expect(key("create_payment_link", { amount: 100, Notes: "a" })).not.toBe(
      key("create_payment_link", { amount: 100 }),
    );
    expect(key("brand_new_tool", { x: 1 })).not.toBe(key("brand_new_tool", { x: 2 }));
    // prototype names are not "listed" tools
    expect(key("toString", { x: 1 })).not.toBe(key("toString", { x: 2 }));
    expect(key("__proto__", { x: 1 })).not.toBe(key("__proto__", { x: 2 }));
  });

  it("errs on non-object args or non-JSON key material", () => {
    expect(idempotencyKey("create_refund", null).ok).toBe(false);
    expect(idempotencyKey("create_refund", [1]).ok).toBe(false);
    expect(idempotencyKey("create_refund", { payment_id: "pay_A1", amount: 1.5 }).ok).toBe(false);
    expect(idempotencyKey("brand_new_tool", { extra: { r: 0.5 } }).ok).toBe(false);
    const r = idempotencyKey("create_refund", "x");
    expect(!r.ok && r.error.code).toBe("idempotency.invalid_args");
  });

  it("is computed over REDACTED values (distinct PII collapses ⇒ over-deny only)", () => {
    expect(key("brand_new_tool", { amount: 1, email: "a@example.com" })).toBe(
      key("brand_new_tool", { amount: 1, email: "b@example.com" }),
    );
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Stored (redacted) args ⇒ same key
// ---------------------------------------------------------------------------------------------------------------

const PII_CASES: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
  ["create_refund", { payment_id: "pay_A1", amount: 500 }],
  [
    "create_refund",
    {
      payment_id: "pay_A1",
      amount: 500,
      notes: { email: "buyer@example.com", phone: "9876543210" },
      receipt: "card 4111 1111 1111 1111",
    },
  ],
  ["create_refund", { payment_id: "pay_A1", amount: 9_876_543_210 }],
  ["create_refund", { payment_id: "pay_A1", amount: 1_234_567_890_123 }],
  ["capture_payment", { payment_id: "pay_A1", amount: 7_000_000_000, currency: "INR" }],
  ["create_instant_settlement", { amount: 500, description: "acct 123456789012" }],
  [
    "create_payment_link",
    {
      amount: 100,
      currency: "INR",
      description: "for buyer@example.com, call +91 98765 43210",
      customer: { name: "Asha", email: "asha@example.com", contact: "9876543210" },
      notes: { "buyer@example.com": "x", vpa: "asha@okhdfc", account_number: "123456789012" },
      reference_id: "ref 4111111111111111",
    },
  ],
  [
    "initiate_payment",
    {
      "buyer@example.com": 1,
      "[REDACTED_KEY_0]": 2,
      amount: 100,
      notes: { phone: "9876543210" },
      receipt: "r 4111111111111111",
    },
  ],
  [
    "brand_new_tool",
    {
      "user@example.com": 1,
      "9876543210": "phone as key",
      key_secret: "abcdefghijklmnopqrstuvwxyz123456",
      nested: [{ card: { number: "4111111111111111" } }, "rzp_test_ABC"],
      acc: 123456789,
      __proto__value: "x",
    },
  ],
];

describe("key recomputed from stored argsRedacted equals the live key", () => {
  it.each(PII_CASES)("%s %j", (tool, args) => {
    const store = openAuditStore({ path: ":memory:" });
    if (!store.ok) throw new Error("store");
    try {
      const rec = store.value.recordAttempt({
        sessionId: "s",
        tool,
        args,
        reason: "r",
        decision: "allow",
        matchedRules: ["x"],
      });
      if (!rec.ok) throw new Error(`record: ${rec.error.code}`);
      const rows = store.value.readActivitySince(0);
      if (!rows.ok) throw new Error("read");
      const stored = rows.value[0]?.attempt.argsRedacted;
      const recomputed = idempotencyKeyFromRedacted(tool, stored);
      expect(recomputed).toEqual({ ok: true, value: key(tool, args) });
    } finally {
      store.value.close();
    }
  });

  it("also equals recomputing from redact(json(args)) directly (no reliance on redact idempotence)", () => {
    for (const [tool, args] of PII_CASES) {
      const canon = canonicalJson(args);
      if (!canon.ok) throw new Error("canon");
      const stored = redact(JSON.parse(canon.value) as JsonValue);
      expect(idempotencyKeyFromRedacted(tool, stored)).toEqual({
        ok: true,
        value: key(tool, args),
      });
    }
  });

  it("errs for a non-object stored value", () => {
    expect(idempotencyKeyFromRedacted("create_refund", null).ok).toBe(false);
    expect(idempotencyKeyFromRedacted("create_refund", "x").ok).toBe(false);
    expect(idempotencyKeyFromRedacted("create_refund", [1]).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// findDuplicate
// ---------------------------------------------------------------------------------------------------------------

const NOW = Date.parse("2026-10-26T12:00:00.000Z");
const MIN = 60_000;
const OPTS: FindDuplicateOpts = { nowMs: NOW, windowMs: 10 * MIN, openLookbackMs: 24 * 60 * MIN };
const ARGS = { payment_id: "pay_A1", amount: 500 };
const K = key("create_refund", ARGS);
const KEYS = new Set([K]);

let seq = 0;

interface RowSpec {
  tool?: string;
  args?: JsonValue;
  originalArgs?: JsonValue;
  storedKey?: string;
  decision?: AuditDecisionInput;
  outcome?: AuditOutcomeInput;
  upstreamRef?: string;
  /** Minutes before NOW of the attempt. */
  attemptAgoMin?: number;
  /** Minutes before NOW of the outcome. */
  outcomeAgoMin?: number;
  attemptTs?: string;
  id?: string;
}

function row(s: RowSpec = {}): AuditActivity {
  seq += 2;
  const attempt: AuditAttemptRecord = {
    kind: "attempt",
    id: s.id ?? `att-${String(seq)}`,
    ts: s.attemptTs ?? new Date(NOW - (s.attemptAgoMin ?? 1) * MIN).toISOString(),
    sessionId: "s",
    tool: s.tool ?? "create_refund",
    argsRedacted: s.args ?? ARGS,
    reason: "r",
    decision: s.decision ?? "allow",
    matchedRules: [],
    seq,
    prevHash: "0".repeat(64),
    hash: "1".repeat(64),
  };
  if (s.originalArgs !== undefined) attempt.originalArgsRedacted = s.originalArgs;
  if (s.storedKey !== undefined) attempt.idempotencyKey = s.storedKey;
  if (s.outcome === undefined) return { attempt };
  return {
    attempt,
    outcome: {
      kind: "outcome",
      id: `out-${String(seq)}`,
      attemptId: attempt.id,
      ts: new Date(NOW - (s.outcomeAgoMin ?? s.attemptAgoMin ?? 1) * MIN).toISOString(),
      outcome: s.outcome,
      latencyMs: 1,
      ...(s.upstreamRef === undefined ? {} : { upstreamRef: s.upstreamRef }),
      seq: seq + 1,
      prevHash: "0".repeat(64),
      hash: "2".repeat(64),
    },
  };
}

function find(rows: AuditActivity[], keys = KEYS, opts: Partial<FindDuplicateOpts> = {}) {
  const r = findDuplicate(rows, "create_refund", keys, { ...OPTS, ...opts });
  if (!r.ok) throw new Error(r.error.code);
  return r.value;
}

describe("findDuplicate", () => {
  it("status mapping", () => {
    const ok = row({ outcome: "success", upstreamRef: "rfnd_ABC123" });
    expect(find([ok])).toEqual({
      attemptId: ok.attempt.id,
      status: "executed",
      upstreamRef: "rfnd_ABC123",
    });
    const noRef = row({ outcome: "success" });
    expect(find([noRef])).toEqual({ attemptId: noRef.attempt.id, status: "executed" });
    expect(find([row({ outcome: "timeout" })])?.status).toBe("may_have_executed");
    expect(find([row({ outcome: "upstream_error" })])?.status).toBe("may_have_executed");
    expect(find([row({ decision: "require_approval" })])?.status).toBe("pending_approval");
    expect(find([row({ decision: "allow" })])?.status).toBe("in_flight");
    expect(find([row({ decision: "transform" })])?.status).toBe("in_flight");
    // a may-have-executed row never reports an upstreamRef
    expect(find([row({ outcome: "timeout", upstreamRef: "rfnd_X12345" })])).not.toHaveProperty(
      "upstreamRef",
    );
  });

  it("deny decisions and denied / not_forwarded outcomes are not counted", () => {
    expect(find([row({ decision: "deny" })])).toBeUndefined();
    expect(find([row({ decision: "deny", outcome: "denied" })])).toBeUndefined();
    expect(find([row({ outcome: "denied" })])).toBeUndefined();
    expect(find([row({ outcome: "not_forwarded" })])).toBeUndefined();
    expect(find([row({ decision: "require_approval", outcome: "denied" })])).toBeUndefined();
  });

  it("other-tool rows are ignored (even with the same stored key)", () => {
    expect(
      find([row({ tool: "capture_payment", storedKey: K, outcome: "success" })]),
    ).toBeUndefined();
  });

  it("different args don't match; stored key OR recomputed argsRedacted / originalArgsRedacted match", () => {
    expect(find([row({ args: { payment_id: "pay_A1", amount: 501 } })])).toBeUndefined();
    // stored key only (args differ)
    expect(find([row({ args: { payment_id: "pay_Z", amount: 1 }, storedKey: K })])).toBeDefined();
    // original args (transformed row)
    expect(
      find([row({ args: { payment_id: "pay_A1", amount: 100 }, originalArgs: ARGS })]),
    ).toBeDefined();
    // legacy row without a stored key
    expect(find([row({ args: { ...ARGS, notes: { x: "y" } } })])).toBeDefined();
  });

  it("an unrecomputable same-tool row is a match (fail closed)", () => {
    expect(find([row({ args: "not-an-object" })])?.status).toBe("in_flight");
    expect(find([row({ args: ARGS, originalArgs: null, outcome: "success" })])?.status).toBe(
      "executed",
    );
  });

  it("excludeAttemptIds is honoured", () => {
    const r = row({ decision: "require_approval" });
    expect(find([r], KEYS, { excludeAttemptIds: new Set([r.attempt.id]) })).toBeUndefined();
    expect(find([r], KEYS, { excludeAttemptIds: new Set(["other"]) })).toBeDefined();
  });

  it("closed actions: window edge on max(attempt.ts, outcome.ts)", () => {
    expect(find([row({ outcome: "success", attemptAgoMin: 10 })])).toBeDefined(); // exactly at edge
    expect(find([row({ outcome: "success", attemptAgoMin: 10.001 })])).toBeUndefined();
    // old attempt, recent outcome ⇒ counted
    expect(find([row({ outcome: "timeout", attemptAgoMin: 60, outcomeAgoMin: 5 })])).toBeDefined();
    expect(
      find([row({ outcome: "success", attemptAgoMin: 30 })], KEYS, { windowMs: 60 * MIN }),
    ).toBeDefined();
  });

  it("may-have-executed (timeout / upstream_error) rows use the open lookback, not the window", () => {
    for (const outcome of ["timeout", "upstream_error"] as const) {
      expect(find([row({ outcome, attemptAgoMin: 11 })])?.status).toBe("may_have_executed");
      expect(find([row({ outcome, attemptAgoMin: 23 * 60 })])?.status).toBe("may_have_executed");
      expect(find([row({ outcome, attemptAgoMin: 24 * 60 })])?.status).toBe("may_have_executed");
      expect(find([row({ outcome, attemptAgoMin: 24 * 60 + 0.001 })])).toBeUndefined();
    }
    // executed rows still age out after the window
    expect(find([row({ outcome: "success", attemptAgoMin: 11 })])).toBeUndefined();
  });

  it("a pre-change stored key (v1 over ALL args) never hides a repeat differing only in free text", () => {
    const tool = "create_payment_link";
    const oldArgs = { amount: 100, currency: "INR", notes: { a: "1" }, description: "first" };
    const canon = canonicalJson({ v: IDEMPOTENCY_KEY_VERSION, tool, key: oldArgs });
    if (!canon.ok) throw new Error("canon");
    const legacyKey = nodeHasher.sha256Hex(canon.value);
    const r = row({ tool, args: oldArgs, storedKey: legacyKey, outcome: "success" });
    const live = key(tool, { amount: 100, currency: "INR", notes: { a: "2" }, receipt: "r2" });
    expect(live).not.toBe(legacyKey);
    const hit = findDuplicate([r], tool, new Set([live]), OPTS);
    expect(hit.ok && hit.value?.status).toBe("executed");
    const other = key(tool, { amount: 200, currency: "INR" });
    const miss = findDuplicate([r], tool, new Set([other]), OPTS);
    expect(miss.ok && miss.value).toBeUndefined();
  });

  it("open actions: counted up to openLookbackMs regardless of the window", () => {
    expect(find([row({ decision: "require_approval", attemptAgoMin: 23 * 60 })])).toBeDefined();
    expect(find([row({ decision: "require_approval", attemptAgoMin: 24 * 60 })])).toBeDefined();
    expect(
      find([row({ decision: "require_approval", attemptAgoMin: 24 * 60 + 0.001 })]),
    ).toBeUndefined();
  });

  it("unparseable timestamps are inside every window", () => {
    expect(find([row({ outcome: "success", attemptTs: "garbage" })])).toBeDefined();
  });

  it("returns the most recent match", () => {
    const older = row({ outcome: "success", attemptAgoMin: 5, upstreamRef: "rfnd_OLD123" });
    const newer = row({ decision: "require_approval", attemptAgoMin: 2 });
    expect(find([newer, older])?.attemptId).toBe(newer.attempt.id);
  });

  it("matches any of several keys", () => {
    const other = key("create_refund", { payment_id: "pay_B2", amount: 1 });
    expect(find([row()], new Set([other, K]))).toBeDefined();
    expect(find([row()], new Set([other]))).toBeUndefined();
  });

  it.each([
    [{ nowMs: Number.NaN }],
    [{ nowMs: -1 }],
    [{ nowMs: 1.5 }],
    [{ windowMs: 0 }],
    [{ windowMs: Number.POSITIVE_INFINITY }],
    [{ openLookbackMs: 0 }],
  ])("invalid config %j ⇒ err", (bad) => {
    const r = findDuplicate([row()], "create_refund", KEYS, { ...OPTS, ...bad });
    expect(!r.ok && r.error.code).toBe("idempotency.invalid_config");
  });

  it("an empty key set ⇒ err", () => {
    expect(findDuplicate([], "create_refund", new Set(), OPTS).ok).toBe(false);
  });

  it("has a constant message per status", () => {
    expect(Object.keys(DUPLICATE_MESSAGES).sort()).toEqual([
      "executed",
      "in_flight",
      "may_have_executed",
      "pending_approval",
    ]);
  });
});
