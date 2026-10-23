import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildRecord, computeHash, verifyChain } from "./chain.js";
import {
  GENESIS_PREV_HASH,
  type AuditAttemptBody,
  type AuditBody,
  type AuditOutcomeBody,
  type AuditRecord,
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
  attempt("a2", { decision: "require_approval", approver: "ops@tg" }),
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
