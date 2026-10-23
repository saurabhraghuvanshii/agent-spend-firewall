import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical-json.js";

function encodeOk(v: unknown): string {
  const r = canonicalJson(v);
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

function errCode(v: unknown): string {
  const r = canonicalJson(v);
  if (r.ok) throw new Error(`expected error, got ${r.value}`);
  return r.error.code;
}

describe("canonicalJson", () => {
  it("sorts keys recursively", () => {
    expect(encodeOk({ b: 1, a: { d: [{ z: 1, y: 2 }], c: "x" } })).toBe(
      '{"a":{"c":"x","d":[{"y":2,"z":1}]},"b":1}',
    );
  });

  it("is independent of insertion order", () => {
    const a = { amountPaise: 50000, id: "pay_1", nested: { x: true, y: null } };
    const b = { nested: { y: null, x: true }, id: "pay_1", amountPaise: 50000 };
    expect(encodeOk(a)).toBe(encodeOk(b));
  });

  it("drops undefined object properties", () => {
    expect(encodeOk({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("encodes primitives and escapes strings", () => {
    expect(encodeOk(null)).toBe("null");
    expect(encodeOk(true)).toBe("true");
    expect(encodeOk('a"b\n')).toBe('"a\\"b\\n"');
    expect(encodeOk(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(encodeOk(Object.create(null) as object)).toBe("{}");
  });

  it("allows shared (non-cyclic) references", () => {
    const shared = { x: 1 };
    expect(encodeOk({ a: shared, b: shared })).toBe('{"a":{"x":1},"b":{"x":1}}');
  });

  it.each([
    ["NaN", Number.NaN, "canonical_json.non_finite"],
    ["Infinity", Number.POSITIVE_INFINITY, "canonical_json.non_finite"],
    ["-Infinity", Number.NEGATIVE_INFINITY, "canonical_json.non_finite"],
    ["-0", -0, "canonical_json.negative_zero"],
    ["float", 1.5, "canonical_json.non_integer"],
    ["unsafe integer", 2 ** 53, "canonical_json.unsafe_integer"],
    ["bigint", 10n, "canonical_json.unsupported_type"],
    ["function", () => 1, "canonical_json.unsupported_type"],
    ["symbol", Symbol("s"), "canonical_json.unsupported_type"],
    ["top-level undefined", undefined, "canonical_json.unsupported_type"],
    ["undefined in array", [1, undefined], "canonical_json.undefined_in_array"],
    // eslint-disable-next-line no-sparse-arrays
    ["array hole", [1, , 2], "canonical_json.undefined_in_array"],
    ["Date", new Date(0), "canonical_json.non_plain_object"],
    ["Map", new Map(), "canonical_json.non_plain_object"],
    ["nested float", { a: { amount: 10.5 } }, "canonical_json.non_integer"],
  ])("rejects %s", (_name, value, code) => {
    expect(errCode(value)).toBe(code);
  });

  it("rejects object cycles", () => {
    const o: Record<string, unknown> = { a: 1 };
    o["self"] = o;
    expect(errCode(o)).toBe("canonical_json.cycle");
  });

  it("rejects array cycles", () => {
    const arr: unknown[] = [];
    arr.push(arr);
    expect(errCode(arr)).toBe("canonical_json.cycle");
  });

  it("reports the path of the offending value", () => {
    const r = canonicalJson({ a: [{ b: 0.1 }] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.details?.["path"]).toBe("$.a[0].b");
  });

  it("never exposes PII-bearing key names in the error path", () => {
    const cases: Record<string, unknown>[] = [
      { "x@y.com": 0.5 },
      { a: { "9876543210": [0.5] } },
      { "4111111111111111": { ok: 1, bad: 0.5 } },
      { rzp_test_AbC123: Number.NaN },
    ];
    const paths = cases.map((c) => {
      const r = canonicalJson(c);
      expect(r.ok).toBe(false);
      return r.ok ? "" : String(r.error.details?.["path"]);
    });
    expect(paths).toEqual(["$.[key]", "$.a.[key][0]", "$.[key].bad", "$.[key]"]);
    for (const p of paths) expect(p).not.toMatch(/x@y|98765|4111|rzp_/);
  });

  it("returns err instead of throwing when a getter throws", () => {
    const o = {
      get boom(): number {
        throw new Error("nope");
      },
    };
    expect(errCode(o)).toBe("canonical_json.exception");
  });
});
