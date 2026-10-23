import { describe, expect, it } from "vitest";
import { redact, REDACTED } from "../audit/redact.js";
import type { AuditDecision, AuditOutcome, JsonValue } from "../audit/types.js";
import { activityTs, argsMatch, countsTowardLimits } from "./activity.js";
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
