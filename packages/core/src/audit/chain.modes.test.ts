import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical-json.js";
import { buildRecord, computeHash, verifyChain } from "./chain.js";
import {
  GENESIS_PREV_HASH,
  MODE_ACTOR_RE,
  type AuditAttemptBody,
  type AuditBody,
  type AuditModeBody,
  type AuditOutcomeBody,
  type AuditRecord,
  type Hasher,
} from "./types.js";

const hasher: Hasher = {
  sha256Hex: (s) => createHash("sha256").update(s, "utf8").digest("hex"),
};

function attempt(id: string, extra: Partial<AuditAttemptBody> = {}): AuditAttemptBody {
  return {
    kind: "attempt",
    id,
    ts: "2026-10-29T10:00:00.000Z",
    sessionId: "sess_1",
    tool: "create_refund",
    argsRedacted: { payment_id: "pay_1", amount: 50000 },
    reason: "duplicate charge",
    decision: "allow",
    matchedRules: ["max-refund"],
    ...extra,
  };
}

function shadowAttempt(id: string, extra: Partial<AuditAttemptBody> = {}): AuditAttemptBody {
  return attempt(id, { shadow: true, wouldDecision: "deny", ...extra });
}

function mode(id: string, killSwitch: boolean, shadow: boolean, actor = "cli:ops"): AuditModeBody {
  return { kind: "mode", id, ts: "2026-10-29T09:00:00.000Z", killSwitch, shadow, actor };
}

function outcome(id: string, attemptId: string): AuditOutcomeBody {
  return {
    kind: "outcome",
    id,
    attemptId,
    ts: "2026-10-29T10:00:01.000Z",
    outcome: "success",
    latencyMs: 12,
  };
}

function unwrap<T>(r: { ok: true; value: T } | { ok: false; error: { code: string } }): T {
  if (!r.ok) throw new Error(`unexpected err ${r.error.code}`);
  return r.value;
}

function chainOf(bodies: AuditBody[]): AuditRecord[] {
  const out: AuditRecord[] = [];
  for (const b of bodies) out.push(unwrap(buildRecord(hasher, out.at(-1) ?? null, b)));
  return out;
}

/** Append `body` with a correct hash WITHOUT the shape checks (a forger with DB access). */
function forge(chain: AuditRecord[], body: Record<string, unknown>): AuditRecord[] {
  const prev = chain.at(-1);
  const seq = (prev?.seq ?? 0) + 1;
  const prevHash = prev?.hash ?? GENESIS_PREV_HASH;
  const canon = unwrap(canonicalJson({ ...body, seq }));
  const hash = hasher.sha256Hex(prevHash + canon);
  return [...chain, { ...body, seq, prevHash, hash } as unknown as AuditRecord];
}

describe("mode records (T012)", () => {
  it("chains and verifies mode records alongside attempts", () => {
    const chain = chainOf([
      mode("m1", true, false),
      mode("m2", false, true, "dashboard:ops-1"),
      attempt("a1"),
      outcome("o1", "a1"),
    ]);
    const v = verifyChain(hasher, chain);
    expect(v).toMatchObject({ ok: true, count: 4, danglingAttempts: [] });
  });

  it.each([
    ["extra key", { ...mode("m1", true, false), note: "x" }],
    ["non-boolean killSwitch", { ...mode("m1", true, false), killSwitch: "yes" }],
    ["non-boolean shadow", { ...mode("m1", true, false), shadow: 1 }],
    [
      "missing actor",
      { kind: "mode", id: "m1", ts: "2026-10-29T09:00:00.000Z", killSwitch: true, shadow: false },
    ],
    ["email actor", { ...mode("m1", true, false), actor: "ops@example.com" }],
    ["bad id", { ...mode("m1", true, false), id: "bad id" }],
  ])("rejects a malformed mode record: %s", (_label, body) => {
    const r = computeHash(hasher, GENESIS_PREV_HASH, 1, body as unknown as AuditBody);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_mode");
    const v = verifyChain(hasher, forge([], body));
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.brokenAt.reason).toBe("invalid_row");
  });

  it("actor pattern accepts cli / dashboard / telegram ids only", () => {
    expect(MODE_ACTOR_RE.test("cli:saurabh")).toBe(true);
    expect(MODE_ACTOR_RE.test("dashboard:ops")).toBe(true);
    expect(MODE_ACTOR_RE.test("telegram:12345")).toBe(true);
    expect(MODE_ACTOR_RE.test("cli:Saurabh")).toBe(false);
    expect(MODE_ACTOR_RE.test("api:x")).toBe(false);
  });

  it("an outcome cannot reference a mode record", () => {
    const v = verifyChain(hasher, chainOf([mode("m1", true, false), outcome("o1", "m1")]));
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.brokenAt.reason).toBe("orphan_outcome");
  });
});

describe("shadow attempts (T012)", () => {
  it("verifies a shadow attempt after shadow mode was turned on", () => {
    const chain = chainOf([
      mode("m1", false, true),
      shadowAttempt("a1"),
      outcome("o1", "a1"),
      shadowAttempt("a2", { wouldDecision: "require_approval" }),
      outcome("o2", "a2"),
      shadowAttempt("a3", { wouldDecision: "transform" }),
      shadowAttempt("a4", { wouldDecision: "allow" }),
      // A kill-switch change that keeps shadow on does not end it.
      mode("m2", true, true),
      shadowAttempt("a5"),
    ]);
    expect(verifyChain(hasher, chain)).toMatchObject({ ok: true, count: 9 });
  });

  it("rejects a shadow attempt after shadow mode was turned OFF again (shadow_without_mode)", () => {
    const chain = chainOf([
      mode("m1", false, true),
      shadowAttempt("a1"),
      mode("m2", false, false),
      shadowAttempt("a2"),
    ]);
    const v = verifyChain(hasher, chain);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.brokenAt).toMatchObject({ id: "a2", reason: "shadow_without_mode" });
    // Turned on again ⇒ accepted again.
    const again = chainOf([
      mode("m1", false, true),
      mode("m2", false, false),
      mode("m3", false, true),
      shadowAttempt("a1"),
    ]);
    expect(verifyChain(hasher, again).ok).toBe(true);
  });

  it("rejects a shadow attempt when shadow mode was never on (shadow_without_mode)", () => {
    for (const prefix of [[], [mode("m1", true, false)]] as AuditBody[][]) {
      const chain = chainOf([...prefix, shadowAttempt("a1")]);
      const v = verifyChain(hasher, chain);
      expect(v.ok).toBe(false);
      if (!v.ok) {
        expect(v.brokenAt.reason).toBe("shadow_without_mode");
        expect(v.brokenAt.id).toBe("a1");
      }
    }
  });

  it("rejects a shadow mode record AFTER the shadow attempt", () => {
    const chain = chainOf([shadowAttempt("a1"), mode("m1", false, true)]);
    const v = verifyChain(hasher, chain);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.brokenAt.reason).toBe("shadow_without_mode");
  });

  it.each([
    [
      "shadow-forwarded entry without its would-decision",
      { shadow: true, wouldDecision: undefined },
    ],
    ["wouldDecision without shadow", { shadow: undefined, wouldDecision: "deny" }],
    ["shadow: false", { shadow: false }],
    ["unknown wouldDecision", { wouldDecision: "maybe" }],
    ["shadow attempt recorded as deny", { decision: "deny" }],
    ["shadow attempt recorded as transform", { decision: "transform" }],
    ["shadow attempt with original args", { originalArgsRedacted: { amount: 1 } }],
    ["shadow attempt with approver", { approver: "telegram:1" }],
  ])("rejects an inconsistent shadow attempt: %s", (_label, extra) => {
    const raw: Record<string, unknown> = { ...shadowAttempt("a1"), ...extra };
    for (const k of Object.keys(raw)) if (raw[k] === undefined) delete raw[k];
    const body = raw as unknown as AuditBody;
    const built = computeHash(hasher, GENESIS_PREV_HASH, 2, body);
    expect(built.ok).toBe(false);
    if (!built.ok) expect(built.error.code).toBe("audit.invalid_shadow");
    const base = chainOf([mode("m1", false, true)]);
    const v = verifyChain(hasher, forge(base, raw));
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.brokenAt.reason).toBe("invalid_row");
      expect(v.brokenAt.seq).toBe(2);
    }
  });

  it("rejects shadow fields on non-attempt records", () => {
    const body = { ...outcome("o1", "a1"), shadow: true, wouldDecision: "deny" };
    const r = computeHash(hasher, GENESIS_PREV_HASH, 1, body);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.invalid_shadow");
  });

  it("legacy attempts without shadow fields hash exactly as before", () => {
    const plain = attempt("a1");
    const withUndefined = { ...plain, shadow: undefined, wouldDecision: undefined };
    expect(unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, plain))).toBe(
      unwrap(computeHash(hasher, GENESIS_PREV_HASH, 1, withUndefined as unknown as AuditBody)),
    );
  });
});
