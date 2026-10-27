import { describe, expect, it } from "vitest";
import { redact, REDACTED } from "../audit/redact.js";
import type {
  AuditDecision,
  AuditOutcome,
  AuditVerificationResult,
  JsonValue,
} from "../audit/types.js";
import {
  activityStatus,
  activityTs,
  argsMatch,
  blocksIndefinitely,
  countsTowardLimits,
  latestVerifications,
  type Countable,
} from "./activity.js";
import type { Args } from "./types.js";

describe("countsTowardLimits", () => {
  const decisions: AuditDecision[] = ["allow", "transform", "require_approval", "deny"];
  const outcomes: (AuditOutcome | undefined)[] = [
    undefined,
    "success",
    "timeout",
    "upstream_error",
    "denied",
    "not_forwarded",
  ];
  const expected = (d: AuditDecision, o: AuditOutcome | undefined): boolean =>
    d !== "deny" &&
    (o === undefined || o === "success" || o === "timeout" || o === "upstream_error");

  const table = decisions.flatMap((d) =>
    outcomes.map((o) => [d, o ?? "(none)", expected(d, o)] as const),
  );

  it("full table has 24 rows, 12 counted", () => {
    expect(table).toHaveLength(24);
    expect(table.filter(([, , e]) => e)).toHaveLength(12);
  });

  it.each(table)("decision %s × outcome %s ⇒ %s", (d, o, want) => {
    const a = o === "(none)" ? { decision: d } : { decision: d, outcome: o };
    expect(countsTowardLimits(a)).toBe(want);
  });

  it("pending (no outcome) allow / approval actions count, so a refund can't be queued twice", () => {
    expect(countsTowardLimits({ decision: "require_approval" })).toBe(true);
    expect(countsTowardLimits({ decision: "allow" })).toBe(true);
  });

  it("deny never counts, whatever the outcome", () => {
    for (const o of outcomes) {
      expect(
        countsTowardLimits(
          o === undefined ? { decision: "deny" } : { decision: "deny", outcome: o },
        ),
      ).toBe(false);
    }
  });

  it("values outside the audit schema are not counted", () => {
    expect(countsTowardLimits({ decision: "maybe" as AuditDecision })).toBe(false);
    expect(countsTowardLimits({ decision: "allow", outcome: "weird" as AuditOutcome })).toBe(false);
  });
});

describe("argsMatch", () => {
  const stored = (args: Record<string, JsonValue>): JsonValue => redact(args);

  it("exact match on every key", () => {
    expect(
      argsMatch(stored({ payment_id: "pay_1", amount: 30_000 }), {
        payment_id: "pay_1",
        amount: 30_000,
      }),
    ).toBe(true);
  });

  it("different value ⇒ false", () => {
    expect(
      argsMatch(stored({ payment_id: "pay_1", amount: 30_000 }), {
        payment_id: "pay_1",
        amount: 30_001,
      }),
    ).toBe(false);
    expect(
      argsMatch(stored({ payment_id: "pay_1", amount: 30_000 }), {
        payment_id: "pay_2",
        amount: 30_000,
      }),
    ).toBe(false);
  });

  it("type differences are not coerced", () => {
    expect(argsMatch(stored({ amount: 30_000 }), { amount: "30000" })).toBe(false);
  });

  it("missing key in the recorded args ⇒ false", () => {
    expect(argsMatch(stored({ payment_id: "pay_1" }), { payment_id: "pay_1", amount: 1 })).toBe(
      false,
    );
  });

  it("null in match does not equal a missing key", () => {
    expect(argsMatch(stored({}), { notes: null })).toBe(false);
    expect(argsMatch(stored({ notes: null }), { notes: null })).toBe(true);
  });

  it("extra keys in the recorded args are ignored", () => {
    expect(
      argsMatch(stored({ payment_id: "pay_1", amount: 5, speed: "normal", notes: { a: "b" } }), {
        payment_id: "pay_1",
      }),
    ).toBe(true);
  });

  it("nested values compare by canonical JSON (key order irrelevant)", () => {
    expect(argsMatch({ notes: { b: 2, a: 1 } }, { notes: { a: 1, b: 2 } })).toBe(true);
    expect(argsMatch({ notes: { a: 1 } }, { notes: { a: 1, b: 2 } })).toBe(false);
  });

  it("empty match matches any recorded object (over-match, fail closed for duplicates)", () => {
    expect(argsMatch({ a: 1 }, {})).toBe(true);
  });

  it.each<[string, JsonValue]>([
    ["null", null],
    ["array", [{ payment_id: "pay_1" }]],
    ["string", "pay_1"],
    ["number", 1],
  ])("non-object recorded args (%s) ⇒ false", (_n, a) => {
    expect(argsMatch(a, { payment_id: "pay_1" })).toBe(false);
  });

  it("PII field in match is compared after redaction", () => {
    const rec = stored({ payment_id: "pay_1", customer_email: "a@example.com" });
    expect(rec).toMatchObject({ customer_email: REDACTED });
    expect(argsMatch(rec, { payment_id: "pay_1", customer_email: "a@example.com" })).toBe(true);
  });

  it("PII inside a free-text value is redacted the same way on both sides", () => {
    const rec = stored({ notes: "call 9876543210" });
    expect(argsMatch(rec, { notes: "call 9876543210" })).toBe(true);
  });

  it("documented over-match: different values that both redact to [REDACTED] compare equal", () => {
    const rec = stored({ payment_id: "pay_1", customer_email: "a@example.com" });
    expect(
      argsMatch(rec, { payment_id: "pay_1", customer_email: "someone-else@example.com" }),
    ).toBe(true);
  });

  it("a match key that redact renames (PII in the key name) never matches", () => {
    const key = "a@example.com";
    expect(argsMatch(stored({ [key]: 1 }), { [key]: 1 })).toBe(false);
  });

  it("canonicalisation failure ⇒ false", () => {
    expect(argsMatch({ amount: 1.5 }, { amount: 1.5 })).toBe(false);
    expect(argsMatch({ amount: 1 }, { amount: Number.NaN })).toBe(false);
    expect(argsMatch({ amount: 1.5, id: "x" }, { id: "x" })).toBe(true); // unrelated bad key ignored
  });

  it("only own keys of the recorded args count (no prototype lookups)", () => {
    const rec = Object.create(null) as Record<string, JsonValue>;
    expect(argsMatch(rec, { toString: "x" })).toBe(false);
    expect(argsMatch({}, { constructor: "x" })).toBe(false);
  });

  it("non-plain match object ⇒ false", () => {
    expect(argsMatch({ a: 1 }, [] as unknown as Args)).toBe(false);
    expect(argsMatch({ a: 1 }, null as unknown as Args)).toBe(false);
  });
});

describe("activityTs", () => {
  it("attempt only ⇒ attempt time", () => {
    expect(activityTs("2026-10-23T10:00:00.000Z")).toBe(Date.UTC(2026, 9, 23, 10));
  });

  it("max of attempt and outcome", () => {
    expect(activityTs("2026-10-23T10:00:00.000Z", "2026-10-23T10:05:00.000Z")).toBe(
      Date.UTC(2026, 9, 23, 10, 5),
    );
    // An outcome earlier than the attempt (clock step-back) still yields the later one.
    expect(activityTs("2026-10-23T10:05:00.000Z", "2026-10-23T10:00:00.000Z")).toBe(
      Date.UTC(2026, 9, 23, 10, 5),
    );
  });

  it("handles timezone offsets", () => {
    expect(activityTs("2026-10-23T15:30:00+05:30")).toBe(Date.UTC(2026, 9, 23, 10));
    expect(activityTs("2026-10-23T10:00:00.000Z", "2026-10-23T15:31:00+05:30")).toBe(
      Date.UTC(2026, 9, 23, 10, 1),
    );
  });

  it.each([
    ["garbage attempt", "not a date", undefined],
    ["empty attempt", "", undefined],
    ["garbage outcome", "2026-10-23T10:00:00.000Z", "nope"],
    ["empty outcome", "2026-10-23T10:00:00.000Z", ""],
  ])("unparseable (%s) ⇒ undefined", (_n, a, o) => {
    expect(activityTs(a, o)).toBeUndefined();
  });

  it("non-string input ⇒ undefined", () => {
    expect(activityTs(123 as unknown as string)).toBeUndefined();
  });
});

describe("verification-aware counting (T010, D-023 amendment)", () => {
  const counted: AuditDecision[] = ["allow", "transform", "require_approval"];
  const unclear: AuditOutcome[] = ["timeout", "upstream_error"];

  it.each(counted.flatMap((d) => unclear.map((o) => [d, o] as const)))(
    "%s × %s: not_happened ⇒ not counted; happened ⇒ executed; unknown ⇒ unknown, blocks indefinitely",
    (decision, outcome) => {
      const c = (verification?: AuditVerificationResult): Countable =>
        verification === undefined ? { decision, outcome } : { decision, outcome, verification };
      expect(activityStatus(c())).toBe("may_have_executed");
      expect(blocksIndefinitely(c())).toBe(false);
      expect(countsTowardLimits(c("not_happened"))).toBe(false);
      expect(activityStatus(c("not_happened"))).toBe("not_counted");
      expect(activityStatus(c("happened"))).toBe("executed");
      expect(countsTowardLimits(c("happened"))).toBe(true);
      expect(blocksIndefinitely(c("happened"))).toBe(false);
      expect(activityStatus(c("unknown"))).toBe("unknown");
      expect(countsTowardLimits(c("unknown"))).toBe(true);
      expect(blocksIndefinitely(c("unknown"))).toBe(true);
    },
  );

  it("no verification keeps D-023 statuses", () => {
    expect(activityStatus({ decision: "allow" })).toBe("open");
    expect(activityStatus({ decision: "allow", outcome: "success" })).toBe("executed");
    expect(activityStatus({ decision: "allow", outcome: "denied" })).toBe("not_counted");
    expect(activityStatus({ decision: "allow", outcome: "not_forwarded" })).toBe("not_counted");
    expect(activityStatus({ decision: "deny" })).toBe("not_counted");
  });

  it("a success outcome is authoritative: a not_happened verification cannot uncount it", () => {
    const a: Countable = { decision: "allow", outcome: "success", verification: "not_happened" };
    expect(activityStatus(a)).toBe("executed");
    expect(countsTowardLimits(a)).toBe(true);
  });

  it("deny never counts, whatever the verification", () => {
    for (const v of ["happened", "not_happened", "unknown"] as const) {
      expect(countsTowardLimits({ decision: "deny", outcome: "timeout", verification: v })).toBe(
        false,
      );
    }
  });

  it("happened / unknown count even on an outcome that would not (fail closed)", () => {
    expect(
      activityStatus({ decision: "allow", outcome: "not_forwarded", verification: "happened" }),
    ).toBe("executed");
    expect(activityStatus({ decision: "allow", outcome: "denied", verification: "unknown" })).toBe(
      "unknown",
    );
  });

  it("a verification value outside the schema is treated as unknown (keeps blocking)", () => {
    const a: Countable = {
      decision: "allow",
      outcome: "timeout",
      verification: "weird" as AuditVerificationResult,
    };
    expect(activityStatus(a)).toBe("unknown");
    expect(blocksIndefinitely(a)).toBe(true);
  });

  it("latestVerifications picks the highest seq per attempt, in any order", () => {
    const m = latestVerifications([
      { attemptId: "a1", seq: 9, result: "happened" },
      { attemptId: "a1", seq: 4, result: "unknown" },
      { attemptId: "a2", seq: 5, result: "unknown" },
      { attemptId: "a2", seq: 7, result: "not_happened" },
      { attemptId: "a3", seq: 6, result: "unknown" },
    ]);
    expect(Object.fromEntries(m)).toEqual({
      a1: "happened",
      a2: "not_happened",
      a3: "unknown",
    });
    expect(latestVerifications([]).size).toBe(0);
  });
});

describe("activityTs with a verification timestamp (T010)", () => {
  const A = "2026-10-23T10:00:00.000Z";
  const O = "2026-10-23T10:00:10.000Z";
  const V = "2026-10-23T11:00:00.000Z";

  it("uses the latest of attempt, outcome and verification", () => {
    expect(activityTs(A, O, V)).toBe(Date.parse(V));
    expect(activityTs(A, V, O)).toBe(Date.parse(V));
    expect(activityTs(A, undefined, V)).toBe(Date.parse(V));
  });

  it("an unparseable verification timestamp ⇒ undefined (inside every window)", () => {
    expect(activityTs(A, O, "not a date")).toBeUndefined();
  });
});
