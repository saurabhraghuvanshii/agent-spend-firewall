import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildRecord, computeHash, verifyChain } from "./chain.js";
import {
  GENESIS_PREV_HASH,
  type AuditApprovalBody,
  type AuditAttemptBody,
  type AuditBody,
  type AuditOutcomeBody,
  type AuditRecord,
  type AuditVerificationBody,
  type Hasher,
  type InvalidAuditRow,
} from "./types.js";

const hasher: Hasher = {
  sha256Hex: (s) => createHash("sha256").update(s, "utf8").digest("hex"),
};

function attempt(id: string, extra: Partial<AuditAttemptBody> = {}): AuditAttemptBody {
  return {
    kind: "attempt",
    id,
    ts: "2026-10-23T10:00:00.000Z",
    sessionId: "sess_1",
    tool: "create_refund",
    argsRedacted: { payment_id: "pay_1", amount: 50000 },
    reason: "duplicate charge",
    decision: "allow",
    matchedRules: ["max-refund"],
    ...extra,
  };
}

function outcome(id: string, attemptId: string): AuditOutcomeBody {
  return {
    kind: "outcome",
    id,
    attemptId,
    ts: "2026-10-23T10:00:01.000Z",
    outcome: "success",
    latencyMs: 120,
    upstreamRef: "rfnd_1",
  };
}

function unwrap<T>(r: { ok: true; value: T } | { ok: false; error: { code: string } }): T {
  if (!r.ok) throw new Error(`unexpected err ${r.error.code}`);
  return r.value;
}

function chainOf(bodies: AuditBody[]): AuditRecord[] {
  const out: AuditRecord[] = [];
  for (const b of bodies) {
    const prev = out.at(-1) ?? null;
    out.push(unwrap(buildRecord(hasher, prev, b)));
  }
  return out;
}

const bodies = (): AuditBody[] => [
  attempt("a1"),
  outcome("o1", "a1"),
  attempt("a2", { decision: "transform", approver: "ops@tg" }),
  outcome("o2", "a2"),
];

describe("buildRecord / computeHash", () => {
  it("starts at seq 1 with the genesis prevHash", () => {
    const r = unwrap(buildRecord(hasher, null, attempt("a1")));
    expect(r.seq).toBe(1);
    expect(r.prevHash).toBe(GENESIS_PREV_HASH);
    expect(r.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("links each record to the previous hash", () => {
    const chain = chainOf(bodies());
    chain.forEach((r, i) => {
      expect(r.seq).toBe(i + 1);
      expect(r.prevHash).toBe(i === 0 ? GENESIS_PREV_HASH : chain[i - 1]?.hash);
    });
  });

  it("hash = sha256(prevHash + canonicalJson({...body, seq}))", () => {
    const body = attempt("a1");
    const r = unwrap(buildRecord(hasher, null, body));
    // canonical form has sorted keys; build it by hand to pin the format
    const canon =
      '{"argsRedacted":{"amount":50000,"payment_id":"pay_1"},"decision":"allow","id":"a1","kind":"attempt",' +
      '"matchedRules":["max-refund"],"reason":"duplicate charge","seq":1,"sessionId":"sess_1","tool":"create_refund",' +
      '"ts":"2026-10-23T10:00:00.000Z"}';
    expect(r.hash).toBe(hasher.sha256Hex(GENESIS_PREV_HASH + canon));
  });

  it("returns err when the hasher throws", () => {
    const bad: Hasher = {
      sha256Hex: () => {
        throw new Error("hsm down");
      },
    };
    const r = buildRecord(bad, null, attempt("a1"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.hasher_error");
  });

  it("returns err when the hasher returns a malformed digest", () => {
    const r = computeHash({ sha256Hex: () => "XYZ" }, GENESIS_PREV_HASH, 1, attempt("a1"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.hasher_error");
  });

  it("returns err for a body that cannot be canonicalised (float money)", () => {
    const r = buildRecord(hasher, null, attempt("a1", { argsRedacted: { amount: 499.5 } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("canonical_json.non_integer");
  });
});

describe("verifyChain", () => {
  it("accepts an empty chain", () => {
    expect(verifyChain(hasher, [])).toEqual({
      ok: true,
      count: 0,
      headHash: GENESIS_PREV_HASH,
      danglingAttempts: [],
    });
  });

  it("accepts a valid chain and reports the head hash", () => {
    const chain = chainOf(bodies());
    expect(verifyChain(hasher, chain)).toEqual({
      ok: true,
      count: 4,
      headHash: chain[3]?.hash,
      danglingAttempts: [],
    });
  });

  it("reports dangling attempts without breaking", () => {
    const chain = chainOf([attempt("a1"), attempt("a2"), outcome("o2", "a2"), attempt("a3")]);
    const r = verifyChain(hasher, chain);
    expect(r).toMatchObject({ ok: true, count: 4, danglingAttempts: ["a1", "a3"] });
  });

  it.each<[string, (r: AuditRecord) => AuditRecord]>([
    ["reason", (r) => ({ ...r, reason: "edited" }) as AuditRecord],
    ["decision", (r) => ({ ...r, decision: "allow" }) as AuditRecord],
    [
      "amount",
      (r) => ({ ...r, argsRedacted: { payment_id: "pay_1", amount: 5000000 } }) as AuditRecord,
    ],
    ["approver removed", (r) => ({ ...r, approver: undefined }) as unknown as AuditRecord],
    ["extra field", (r) => ({ ...r, injected: "x" }) as unknown as AuditRecord],
  ])("detects single-field mutation (%s) as hash_mismatch at the right index", (_name, mutate) => {
    const chain = chainOf(bodies());
    const target = chain[2];
    if (!target) throw new Error("missing");
    chain[2] = mutate(target);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 2, seq: 3, id: "a2", reason: "hash_mismatch" },
    });
  });

  it("detects a mutated stored hash as prev_hash_mismatch on the next record", () => {
    const chain = chainOf(bodies());
    const r0 = chain[0];
    if (!r0) throw new Error("missing");
    // attacker edits row 2 and recomputes its own hash, but cannot fix the next link without rewriting the tail
    chain[1] = unwrap(buildRecord(hasher, r0, { ...outcome("o1", "a1"), latencyMs: 1 }));
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 2, seq: 3, reason: "prev_hash_mismatch" },
    });
  });

  it("detects deletion as seq_gap", () => {
    const chain = chainOf(bodies());
    chain.splice(1, 1);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 1, seq: 3, id: "a2", reason: "seq_gap" },
    });
  });

  it("detects reordering as seq_gap", () => {
    const chain = chainOf(bodies());
    const [a, b] = [chain[1], chain[2]];
    if (!a || !b) throw new Error("missing");
    chain[1] = b;
    chain[2] = a;
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 1, reason: "seq_gap" },
    });
  });

  it("detects reordering with renumbered seq as prev_hash_mismatch", () => {
    const chain = chainOf(bodies());
    const [a, b] = [chain[1], chain[2]];
    if (!a || !b) throw new Error("missing");
    chain[1] = { ...b, seq: 2 };
    chain[2] = { ...a, seq: 3 };
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 1, seq: 2, reason: "prev_hash_mismatch" },
    });
  });

  it("detects a non-genesis first prevHash", () => {
    const tail = chainOf(bodies())
      .slice(1)
      .map((r, i) => ({ ...r, seq: i + 1 }));
    expect(verifyChain(hasher, tail)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, seq: 1, reason: "genesis_mismatch" },
    });
  });

  it("detects an outcome that references no earlier attempt", () => {
    const chain = chainOf([attempt("a1"), outcome("o1", "a1"), outcome("o2", "a-missing")]);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 2, seq: 3, id: "o2", reason: "orphan_outcome" },
    });
  });

  it("detects an outcome that precedes its attempt", () => {
    const chain = chainOf([outcome("o1", "a1"), attempt("a1")]);
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, reason: "orphan_outcome" },
    });
  });

  it("detects a second outcome for the same attempt as duplicate_outcome (hashes valid)", () => {
    const chain = chainOf([
      attempt("a1"),
      outcome("o1", "a1"),
      attempt("a2"),
      outcome("o1b", "a1"),
    ]);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 3, seq: 4, id: "o1b", reason: "duplicate_outcome" },
    });
  });

  it("detects a repeated attempt id as duplicate_id (hashes valid)", () => {
    const chain = chainOf([attempt("a1"), outcome("o1", "a1"), attempt("a1")]);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 2, seq: 3, id: "a1", reason: "duplicate_id" },
    });
  });

  it("detects an outcome id that repeats an attempt id as duplicate_id", () => {
    const chain = chainOf([attempt("a1"), attempt("a2"), outcome("a1", "a2")]);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 2, seq: 3, id: "a1", reason: "duplicate_id" },
    });
  });

  it("detects a repeated outcome id as duplicate_id (checked before duplicate_outcome)", () => {
    const chain = chainOf([attempt("a1"), outcome("o1", "a1"), outcome("o1", "a1")]);
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 2, seq: 3, id: "o1", reason: "duplicate_id" },
    });
  });

  it("still reports dangling attempts correctly with the duplicate checks in place", () => {
    const chain = chainOf([
      attempt("a1"),
      attempt("a2"),
      outcome("o2", "a2"),
      attempt("a3"),
      attempt("a4"),
      outcome("o1", "a1"),
    ]);
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: true,
      count: 6,
      danglingAttempts: ["a3", "a4"],
    });
  });

  it("reports an invalid row", () => {
    const chain: (AuditRecord | InvalidAuditRow)[] = chainOf(bodies());
    chain[1] = { invalid: true, seq: 2 };
    expect(verifyChain(hasher, chain)).toEqual({
      ok: false,
      brokenAt: { index: 1, seq: 2, id: null, reason: "invalid_row" },
    });
  });

  it("treats an unknown kind as invalid_row", () => {
    const chain = chainOf(bodies());
    const r0 = chain[0];
    if (!r0) throw new Error("missing");
    chain[0] = { ...r0, kind: "bogus" } as unknown as AuditRecord;
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, reason: "invalid_row" },
    });
  });

  it("treats a non-canonicalisable row (float injected) as invalid_row", () => {
    const chain = chainOf(bodies());
    const r1 = chain[1];
    if (!r1) throw new Error("missing");
    chain[1] = { ...r1, latencyMs: 1.5 } as AuditRecord;
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 1, reason: "invalid_row" },
    });
  });

  it("fails closed when the hasher throws during verification", () => {
    const chain = chainOf(bodies());
    const bad: Hasher = {
      sha256Hex: () => {
        throw new Error("boom");
      },
    };
    expect(verifyChain(bad, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, reason: "hasher_error" },
    });
  });

  it("accepts any iterable (generator)", () => {
    const chain = chainOf(bodies());
    function* rows(): Generator<AuditRecord> {
      yield* chain;
    }
    expect(verifyChain(hasher, rows())).toMatchObject({ ok: true, count: 4 });
  });
});

describe("originalArgsRedacted (T008)", () => {
  const transformed = (): AuditAttemptBody =>
    attempt("a3", {
      decision: "transform",
      argsRedacted: { payment_id: "pay_1", amount: 20000 },
      originalArgsRedacted: { payment_id: "pay_1", amount: 50000 },
    });

  it("verifies a chain mixing rows with and without the field", () => {
    const chain = chainOf([...bodies(), transformed(), outcome("o3", "a3")]);
    expect(chain[4]).toHaveProperty("originalArgsRedacted");
    expect(chain[0]).not.toHaveProperty("originalArgsRedacted");
    expect(verifyChain(hasher, chain)).toMatchObject({ ok: true, count: 6 });
  });

  it("hashes an explicitly-undefined field the same as an absent one (old rows stay valid)", () => {
    const withUndef = { ...attempt("a1"), originalArgsRedacted: undefined } as unknown as AuditBody;
    const a = unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, attempt("a1")));
    const b = unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, withUndef));
    expect(b).toBe(a);
  });

  it("detects tampering with originalArgsRedacted", () => {
    const chain = chainOf([attempt("a1"), transformed()]);
    const r = chain[1];
    if (!r || r.kind !== "attempt") throw new Error("missing");
    chain[1] = { ...r, originalArgsRedacted: { payment_id: "pay_1", amount: 20000 } };
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 1, reason: "hash_mismatch" },
    });
  });

  it("detects removal of originalArgsRedacted", () => {
    const chain = chainOf([transformed()]);
    const r = chain[0];
    if (!r || r.kind !== "attempt") throw new Error("missing");
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { originalArgsRedacted, ...stripped } = r;
    chain[0] = stripped;
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, reason: "hash_mismatch" },
    });
  });
});

describe("idempotencyKey (T009)", () => {
  const KEY = "a".repeat(32) + "0123456789abcdef".repeat(2);
  const keyed = (key: string = KEY): AuditAttemptBody => attempt("a1", { idempotencyKey: key });
  // Hash of `attempt("a1")` at seq 1 / genesis, computed with the pre-T009 build (no idempotencyKey support).
  const LEGACY_A1_HASH = "c9a6cc62cacebb7d00e0413adc91c43e4da9f7186b3d15c830b0d39cbb15c4e2";

  it("builds and verifies an attempt carrying a key, and the key is hashed", () => {
    const chain = chainOf([keyed(), outcome("o1", "a1")]);
    expect(chain[0]).toHaveProperty("idempotencyKey", KEY);
    expect(chain[0]?.hash).not.toBe(LEGACY_A1_HASH);
    expect(verifyChain(hasher, chain)).toMatchObject({ ok: true, count: 2 });
  });

  it("legacy attempt without the key hashes exactly as before and verifies", () => {
    expect(unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, attempt("a1")))).toBe(LEGACY_A1_HASH);
    const withUndef = { ...attempt("a1"), idempotencyKey: undefined } as unknown as AuditBody;
    expect(unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, withUndef))).toBe(LEGACY_A1_HASH);
    const chain = chainOf([attempt("a1"), outcome("o1", "a1")]);
    expect(chain[0]?.hash).toBe(LEGACY_A1_HASH);
    expect(verifyChain(hasher, chain)).toMatchObject({ ok: true, count: 2 });
  });

  it("detects changing the key after hashing", () => {
    const chain = chainOf([keyed(), outcome("o1", "a1")]);
    const r = chain[0];
    if (!r || r.kind !== "attempt") throw new Error("missing");
    chain[0] = { ...r, idempotencyKey: "b".repeat(64) };
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, reason: "hash_mismatch" },
    });
  });

  it("detects removing the key after hashing", () => {
    const chain = chainOf([keyed()]);
    const r = chain[0];
    if (!r || r.kind !== "attempt") throw new Error("missing");
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { idempotencyKey, ...stripped } = r;
    chain[0] = stripped;
    expect(verifyChain(hasher, chain)).toMatchObject({
      ok: false,
      brokenAt: { index: 0, reason: "hash_mismatch" },
    });
  });

  const bad: [string, unknown][] = [
    ["uppercase", "A".repeat(64)],
    ["mixed case", "a".repeat(63) + "F"],
    ["non-hex", "g".repeat(64)],
    ["63 chars", "a".repeat(63)],
    ["65 chars", "a".repeat(65)],
    ["empty", ""],
    ["trailing newline", "a".repeat(64) + "\n"],
    ["number", 123],
    ["null", null],
  ];

  it.each(bad)("buildRecord rejects a %s key", (_label, key) => {
    const body = { ...attempt("a1"), idempotencyKey: key } as unknown as AuditBody;
    const r = buildRecord(hasher, null, body);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_idempotency_key");
  });

  it.each(bad)("verifyChain reports invalid_row for a stored %s key", (_label, key) => {
    // Simulate a row that bypassed buildRecord: valid-looking hash computed over the bad body.
    const body = { ...attempt("a1"), idempotencyKey: key } as unknown as AuditBody;
    const canonHash = hasher.sha256Hex(GENESIS_PREV_HASH + JSON.stringify(body));
    const row = { ...body, seq: 1, prevHash: GENESIS_PREV_HASH, hash: canonHash };
    expect(verifyChain(hasher, [row])).toMatchObject({
      ok: false,
      brokenAt: { index: 0, seq: 1, id: "a1", reason: "invalid_row" },
    });
  });

  it("rejects an outcome record carrying a key (build and verify)", () => {
    const badOutcome = { ...outcome("o1", "a1"), idempotencyKey: KEY } as unknown as AuditBody;
    const prev = unwrap(buildRecord(hasher, null, keyed()));
    const built = buildRecord(hasher, prev, badOutcome);
    expect(built.ok).toBe(false);
    if (!built.ok) expect(built.error.code).toBe("audit.invalid_idempotency_key");

    const row = {
      ...badOutcome,
      seq: 2,
      prevHash: prev.hash,
      hash: hasher.sha256Hex(prev.hash + JSON.stringify(badOutcome)),
    };
    expect(verifyChain(hasher, [prev, row])).toMatchObject({
      ok: false,
      brokenAt: { index: 1, id: "o1", reason: "invalid_row" },
    });
  });

  it("an outcome with an explicitly-undefined key is treated as absent", () => {
    const o = { ...outcome("o1", "a1"), idempotencyKey: undefined } as unknown as AuditBody;
    expect(verifyChain(hasher, chainOf([keyed(), o]))).toMatchObject({ ok: true, count: 2 });
  });
});

describe("verification records and retryOf (T010)", () => {
  const LEGACY_A1_HASH = "c9a6cc62cacebb7d00e0413adc91c43e4da9f7186b3d15c830b0d39cbb15c4e2";

  function verification(
    id: string,
    attemptId: string,
    extra: Partial<AuditVerificationBody> = {},
  ): AuditVerificationBody {
    return {
      kind: "verification",
      id,
      attemptId,
      ts: "2026-10-23T10:00:20.000Z",
      trigger: "timeout",
      result: "not_happened",
      method: "refund_notes_marker",
      needsHuman: false,
      ...extra,
    };
  }
  const timeoutOutcome = (id: string, attemptId: string): AuditOutcomeBody => ({
    kind: "outcome",
    id,
    attemptId,
    ts: "2026-10-23T10:00:10.000Z",
    outcome: "timeout",
    errorCode: "upstream.timeout",
    latencyMs: 10000,
  });
  const brokenReason = (r: ReturnType<typeof verifyChain>): string | undefined =>
    r.ok ? undefined : r.brokenAt.reason;
  /** Build every body as a valid chain (hash-wise) so only the semantic rule can break. */
  const verify = (bs: AuditBody[]): ReturnType<typeof verifyChain> =>
    verifyChain(hasher, chainOf(bs));
  const asBody = (o: object): AuditBody => o as unknown as AuditBody;
  const codeOf = (b: AuditBody): string | undefined => {
    const r = computeHash(hasher, GENESIS_PREV_HASH, 1, b);
    return r.ok ? undefined : r.error.code;
  };

  it("legacy attempt (no retryOf) keeps its known hash; explicit undefined is the same", () => {
    expect(unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, attempt("a1")))).toBe(LEGACY_A1_HASH);
    const undef = asBody({ ...attempt("a1"), retryOf: undefined });
    expect(unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, undef))).toBe(LEGACY_A1_HASH);
  });

  it("retryOf is hashed when present (tampering detected)", () => {
    const chain = chainOf([
      attempt("a1"),
      timeoutOutcome("o1", "a1"),
      verification("v1", "a1"),
      attempt("a2", { retryOf: "a1" }),
    ]);
    expect(verifyChain(hasher, chain)).toMatchObject({ ok: true, count: 4 });
    const tampered = chain.map((r) => (r.id === "a2" ? { ...r, retryOf: "a0" } : r));
    expect(brokenReason(verifyChain(hasher, tampered))).toBe("hash_mismatch");
    const removed = chain.map((r) => {
      if (r.id !== "a2") return r;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { retryOf, ...rest } = r as AuditAttemptBody & AuditRecord;
      return rest;
    });
    expect(brokenReason(verifyChain(hasher, removed))).toBe("hash_mismatch");
  });

  it("rejects a malformed retryOf or one on a non-attempt record", () => {
    expect(codeOf(attempt("a1", { retryOf: "bad id!" }))).toBe("audit.invalid_retry_of");
    expect(codeOf(asBody({ ...attempt("a1"), retryOf: 7 }))).toBe("audit.invalid_retry_of");
    expect(codeOf(asBody({ ...outcome("o1", "a1"), retryOf: "a0" }))).toBe(
      "audit.invalid_retry_of",
    );
    expect(codeOf(asBody({ ...verification("v1", "a1"), retryOf: "a0" }))).toBe(
      "audit.invalid_retry_of",
    );
  });

  it("verifies a full timeout → verify not_happened → single retry → success chain", () => {
    const r = verify([
      attempt("a1"),
      timeoutOutcome("o1", "a1"),
      verification("v1", "a1", { trigger: "late_response" }),
      attempt("a2", { retryOf: "a1" }),
      outcome("o2", "a2"),
    ]);
    expect(r).toMatchObject({ ok: true, count: 5, danglingAttempts: [] });
  });

  it("hashes verification records (tampering with result detected)", () => {
    const chain = chainOf([attempt("a1"), timeoutOutcome("o1", "a1"), verification("v1", "a1")]);
    const tampered = chain.map((r) => (r.id === "v1" ? { ...r, result: "happened" } : r));
    expect(brokenReason(verifyChain(hasher, tampered as AuditRecord[]))).toBe("hash_mismatch");
  });

  it("accepts all valid enum values and optional fields", () => {
    const ok1 = verification("v1", "a1", {
      trigger: "startup",
      result: "unknown",
      method: "none",
      needsHuman: true,
      errorCode: "verify.lookup_failed",
    });
    expect(codeOf(ok1)).toBeUndefined();
    const ok2 = verification("v1", "a1", {
      trigger: "human",
      result: "happened",
      method: "none",
      resolver: "telegram:12345",
      upstreamRef: "rfnd_ABC123",
    });
    expect(codeOf(ok2)).toBeUndefined();
    expect(codeOf(verification("v1", "a1", { method: "payment_status" }))).toBeUndefined();
    expect(
      codeOf(
        asBody({ ...verification("v1", "a1", { trigger: "upstream_error" }), resolver: undefined }),
      ),
    ).toBeUndefined();
  });

  it.each<[string, object]>([
    ["unknown trigger", { trigger: "cron" }],
    ["unknown result", { result: "maybe" }],
    ["unknown method", { method: "guess" }],
    ["non-boolean needsHuman", { needsHuman: "yes" }],
    ["missing needsHuman", { needsHuman: undefined }],
    ["bad upstreamRef", { upstreamRef: "rfnd 1" }],
    ["non-string upstreamRef", { upstreamRef: 5 }],
    ["bad errorCode (uppercase)", { errorCode: "Upstream.Timeout" }],
    ["resolver without human trigger", { resolver: "telegram:1" }],
    ["human trigger without resolver", { trigger: "human" }],
    ["human trigger with PII resolver", { trigger: "human", resolver: "ops@example.com" }],
    ["extra field", { note: "x" }],
    ["bad id", { id: "v 1" }],
    ["bad attemptId", { attemptId: "" }],
    ["empty ts", { ts: "" }],
    ["idempotencyKey", { idempotencyKey: "a".repeat(64) }],
  ])("rejects a verification with %s (build and verify)", (_name, patch) => {
    const body = asBody({ ...verification("v1", "a1"), ...patch });
    const built = buildRecord(hasher, null, body);
    expect(built.ok).toBe(false);
    if (!built.ok) expect(built.error.code).toMatch(/^audit\.invalid_/);
    // A stored row with the same body (hash computed elsewhere) is reported as invalid_row.
    const chain = chainOf([attempt("a1"), timeoutOutcome("o1", "a1")]);
    const prev = chain[1];
    if (prev === undefined) throw new Error("unreachable");
    const row = { ...body, seq: 3, prevHash: prev.hash, hash: "0".repeat(64) };
    expect(brokenReason(verifyChain(hasher, [...chain, row]))).toBe("invalid_row");
  });

  it("orphan_verification: no earlier attempt with that id", () => {
    expect(
      brokenReason(verify([attempt("a1"), outcome("o1", "a1"), verification("v1", "zz")])),
    ).toBe("orphan_verification");
  });

  it("orphan_verification: verification before its attempt", () => {
    expect(brokenReason(verify([verification("v1", "a1"), attempt("a1")]))).toBe(
      "orphan_verification",
    );
  });

  it("verification_before_outcome: attempt has no outcome yet", () => {
    const r = verify([attempt("a1"), verification("v1", "a1"), timeoutOutcome("o1", "a1")]);
    expect(r).toMatchObject({ ok: false, brokenAt: { seq: 2, id: "v1" } });
    expect(brokenReason(r)).toBe("verification_before_outcome");
  });

  it.each<[AuditVerificationBody["result"], AuditVerificationBody["result"]]>([
    ["happened", "unknown"],
    ["happened", "happened"],
    ["not_happened", "happened"],
    ["not_happened", "unknown"],
  ])("verification_after_settled: %s then %s", (first, second) => {
    const r = verify([
      attempt("a1"),
      timeoutOutcome("o1", "a1"),
      verification("v1", "a1", { result: first }),
      verification("v2", "a1", { result: second }),
    ]);
    expect(r).toMatchObject({ ok: false, brokenAt: { seq: 4, id: "v2" } });
    expect(brokenReason(r)).toBe("verification_after_settled");
  });

  it("unknown may be followed by more verifications until settled", () => {
    const r = verify([
      attempt("a1"),
      timeoutOutcome("o1", "a1"),
      verification("v1", "a1", { result: "unknown", needsHuman: true, method: "none" }),
      verification("v2", "a1", { result: "unknown", needsHuman: true, trigger: "startup" }),
      verification("v3", "a1", { result: "happened", trigger: "late_response" }),
    ]);
    expect(r).toMatchObject({ ok: true, count: 5 });
  });

  it("a verification id colliding with another id is duplicate_id", () => {
    expect(
      brokenReason(verify([attempt("a1"), timeoutOutcome("o1", "a1"), verification("o1", "a1")])),
    ).toBe("duplicate_id");
  });

  it("verifications are not outcomes: dangling attempts are unaffected", () => {
    const r = verify([
      attempt("a1"),
      timeoutOutcome("o1", "a1"),
      verification("v1", "a1"),
      attempt("a2"),
    ]);
    expect(r).toMatchObject({ ok: true, danglingAttempts: ["a2"] });
  });

  describe("bad_retry_of", () => {
    const base = (): AuditBody[] => [attempt("a1"), timeoutOutcome("o1", "a1")];

    it("retryOf references no earlier attempt", () => {
      expect(brokenReason(verify([...base(), attempt("a2", { retryOf: "nope" })]))).toBe(
        "bad_retry_of",
      );
    });

    it("retryOf references itself", () => {
      expect(brokenReason(verify([...base(), attempt("a2", { retryOf: "a2" })]))).toBe(
        "bad_retry_of",
      );
    });

    it("original has no verification", () => {
      expect(brokenReason(verify([...base(), attempt("a2", { retryOf: "a1" })]))).toBe(
        "bad_retry_of",
      );
    });

    it.each<AuditVerificationBody["result"]>(["happened", "unknown"])(
      "original's latest verification is %s",
      (result) => {
        const r = verify([
          ...base(),
          verification("v1", "a1", { result }),
          attempt("a2", { retryOf: "a1" }),
        ]);
        expect(brokenReason(r)).toBe("bad_retry_of");
      },
    );

    it("original's verification comes after the retry", () => {
      const r = verify([...base(), attempt("a2", { retryOf: "a1" }), verification("v1", "a1")]);
      expect(brokenReason(r)).toBe("bad_retry_of");
    });

    it("original is a different tool", () => {
      const r = verify([
        ...base(),
        verification("v1", "a1"),
        attempt("a2", { retryOf: "a1", tool: "capture_payment" }),
      ]);
      expect(brokenReason(r)).toBe("bad_retry_of");
    });

    it("second retry of the same original", () => {
      const r = verify([
        ...base(),
        verification("v1", "a1"),
        attempt("a2", { retryOf: "a1" }),
        timeoutOutcome("o2", "a2"),
        attempt("a3", { retryOf: "a1" }),
      ]);
      expect(r).toMatchObject({ ok: false, brokenAt: { id: "a3" } });
      expect(brokenReason(r)).toBe("bad_retry_of");
    });

    it("retry of a retry (never a second retry)", () => {
      const r = verify([
        ...base(),
        verification("v1", "a1"),
        attempt("a2", { retryOf: "a1" }),
        timeoutOutcome("o2", "a2"),
        verification("v2", "a2"),
        attempt("a3", { retryOf: "a2" }),
      ]);
      expect(brokenReason(r)).toBe("bad_retry_of");
    });

    it("a retry that times out may itself be verified", () => {
      const r = verify([
        ...base(),
        verification("v1", "a1"),
        attempt("a2", { retryOf: "a1" }),
        timeoutOutcome("o2", "a2"),
        verification("v2", "a2", { result: "unknown", needsHuman: true }),
      ]);
      expect(r).toMatchObject({ ok: true, count: 6 });
    });
  });
});

describe("approval records (T011)", () => {
  const ra = (id: string, extra: Partial<AuditAttemptBody> = {}): AuditAttemptBody =>
    attempt(id, { decision: "require_approval", matchedRules: ["refund.approval"], ...extra });
  function approval(
    id: string,
    attemptId: string,
    extra: Partial<AuditApprovalBody> = {},
  ): AuditApprovalBody {
    return {
      kind: "approval",
      id,
      attemptId,
      ts: "2026-10-23T10:00:05.000Z",
      approvalId: "apr_1",
      decision: "approved",
      approver: "telegram:12345",
      ...extra,
    };
  }
  const out = (
    id: string,
    attemptId: string,
    o: AuditOutcomeBody["outcome"],
    errorCode?: string,
  ): AuditOutcomeBody => ({
    kind: "outcome",
    id,
    attemptId,
    ts: "2026-10-23T10:00:10.000Z",
    outcome: o,
    latencyMs: 0,
    ...(errorCode === undefined ? {} : { errorCode }),
  });
  const reason = (bs: AuditBody[]): string | undefined => {
    const r = verifyChain(hasher, chainOf(bs));
    return r.ok ? undefined : r.brokenAt.reason;
  };
  const codeOf = (b: AuditBody): string | undefined => {
    const r = computeHash(hasher, GENESIS_PREV_HASH, 1, b);
    return r.ok ? undefined : r.error.code;
  };
  const asBody = (o: object): AuditBody => o as unknown as AuditBody;

  it("accepts approved ⇒ success, rejected / expired ⇒ not_forwarded", () => {
    expect(reason([ra("a1"), approval("p1", "a1"), out("o1", "a1", "success")])).toBeUndefined();
    expect(
      reason([
        ra("a1"),
        approval("p1", "a1", { decision: "rejected" }),
        out("o1", "a1", "not_forwarded", "approval.rejected"),
      ]),
    ).toBeUndefined();
    const expired = approval("p1", "a1", { decision: "expired" });
    delete expired.approver;
    expect(
      reason([ra("a1"), expired, out("o1", "a1", "not_forwarded", "approval.expired")]),
    ).toBeUndefined();
    // Approved but re-evaluation denied: nothing sent.
    expect(
      reason([ra("a1"), approval("p1", "a1"), out("o1", "a1", "not_forwarded")]),
    ).toBeUndefined();
  });

  it("rejects a sent outcome of a require_approval attempt without an approved record", () => {
    for (const o of ["success", "upstream_error", "timeout"] as const) {
      expect(reason([ra("a1"), out("o1", "a1", o)])).toBe("approval_missing");
      expect(
        reason([ra("a1"), approval("p1", "a1", { decision: "rejected" }), out("o1", "a1", o)]),
      ).toBe("approval_missing");
    }
    // Not forwarded without any approval (e.g. the approval service was unavailable) is fine.
    expect(reason([ra("a1"), out("o1", "a1", "not_forwarded")])).toBeUndefined();
  });

  it("rejects a rejected / expired approval followed by a denied outcome", () => {
    expect(
      reason([ra("a1"), approval("p1", "a1", { decision: "rejected" }), out("o1", "a1", "denied")]),
    ).toBe("approval_outcome_mismatch");
  });

  it("rejects an approval that is orphaned, not required, after the outcome or duplicated", () => {
    expect(reason([approval("p1", "a1")])).toBe("orphan_approval");
    expect(reason([attempt("a1"), approval("p1", "a1")])).toBe("approval_not_required");
    expect(reason([ra("a1"), out("o1", "a1", "not_forwarded"), approval("p1", "a1")])).toBe(
      "approval_after_outcome",
    );
    expect(reason([ra("a1"), approval("p1", "a1"), approval("p2", "a1")])).toBe(
      "duplicate_approval",
    );
  });

  it("a retry of an approved attempt inherits the approval; an approval on a retry is refused", () => {
    const verification: AuditBody = {
      kind: "verification",
      id: "v1",
      attemptId: "a1",
      ts: "2026-10-23T10:00:20.000Z",
      trigger: "timeout",
      result: "not_happened",
      method: "refund_notes_marker",
      needsHuman: false,
    };
    const base = [ra("a1"), approval("p1", "a1"), out("o1", "a1", "timeout"), verification];
    expect(reason([...base, ra("a2", { retryOf: "a1" }), out("o2", "a2", "success")])).toBe(
      undefined,
    );
    expect(reason([...base, ra("a2", { retryOf: "a1" }), approval("p2", "a2")])).toBe(
      "approval_not_required",
    );
  });

  it("approval fields are hashed (tampering detected)", () => {
    const chain = chainOf([ra("a1"), approval("p1", "a1"), out("o1", "a1", "success")]);
    const tampered = chain.map((r) => (r.id === "p1" ? { ...r, approver: "telegram:999" } : r));
    const r = verifyChain(hasher, tampered);
    expect(r.ok ? undefined : r.brokenAt.reason).toBe("hash_mismatch");
  });

  it("rejects malformed approval records", () => {
    expect(codeOf(approval("p1", "a1"))).toBeUndefined();
    expect(codeOf(asBody({ ...approval("p1", "a1"), extra: 1 }))).toBe("audit.invalid_approval");
    expect(codeOf(approval("p1", "a1", { decision: "maybe" as "approved" }))).toBe(
      "audit.invalid_approval",
    );
    expect(codeOf(approval("p1", "a1", { approver: "bob@example.com" }))).toBe(
      "audit.invalid_approval",
    );
    const noApprover = approval("p1", "a1");
    delete noApprover.approver;
    expect(codeOf(noApprover)).toBe("audit.invalid_approval");
    expect(codeOf(approval("p1", "a1", { decision: "expired" }))).toBe("audit.invalid_approval");
    expect(codeOf(approval("p1", "a1", { approvalId: "bad id!" }))).toBe("audit.invalid_approval");
    expect(codeOf(approval("p1", "bad id!"))).toBe("audit.invalid_approval");
  });
});
