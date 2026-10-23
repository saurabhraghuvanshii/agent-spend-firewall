import { err, ok, type Result } from "../result.js";
import { redactText } from "./redact.js";

/**
 * Deterministic JSON encoding used for audit hashing.
 *
 * - Object keys sorted (UTF-16 code unit order) at every depth; `undefined` properties dropped.
 * - Only plain objects, arrays, strings, booleans, null and safe integers are accepted.
 *   Rejected: NaN, ±Infinity, -0, non-integers, unsafe integers, bigint, functions, symbols,
 *   `undefined` in arrays (incl. holes), Date and other non-plain objects, cycles.
 *
 * Never throws: any failure (including throwing getters) becomes an `err`.
 * Error `details.path` never contains a PII-bearing key name: such keys are shown as `[key]`.
 */
export function canonicalJson(value: unknown): Result<string> {
  try {
    return encode(value, "$", new Set<object>());
  } catch (e: unknown) {
    return err("canonical_json.exception", "canonical encoding threw", {
      cause: e instanceof Error ? e.message : String(e),
    });
  }
}

function encode(value: unknown, path: string, ancestors: Set<object>): Result<string> {
  if (value === null) return ok("null");
  switch (typeof value) {
    case "string":
      return ok(JSON.stringify(value));
    case "boolean":
      return ok(value ? "true" : "false");
    case "number":
      if (!Number.isFinite(value))
        return err("canonical_json.non_finite", "non-finite number", { path });
      if (Object.is(value, -0))
        return err("canonical_json.negative_zero", "-0 is not allowed", { path });
      if (!Number.isInteger(value))
        return err("canonical_json.non_integer", "non-integer number", { path });
      if (!Number.isSafeInteger(value))
        return err("canonical_json.unsafe_integer", "integer outside safe range", { path });
      return ok(String(value));
    case "object":
      break;
    default:
      return err("canonical_json.unsupported_type", `unsupported type: ${typeof value}`, { path });
  }

  if (ancestors.has(value)) return err("canonical_json.cycle", "cyclic structure", { path });

  if (Array.isArray(value)) {
    ancestors.add(value);
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      const item: unknown = value[i];
      const itemPath = `${path}[${i}]`;
      if (item === undefined)
        return err("canonical_json.undefined_in_array", "undefined in array", { path: itemPath });
      const r = encode(item, itemPath, ancestors);
      if (!r.ok) return r;
      parts.push(r.value);
    }
    ancestors.delete(value);
    return ok(`[${parts.join(",")}]`);
  }

  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return err("canonical_json.non_plain_object", "only plain objects are allowed", { path });
  }

  ancestors.add(value);
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = record[key];
    if (v === undefined) continue;
    const r = encode(v, `${path}.${pathSegment(key)}`, ancestors);
    if (!r.ok) return r;
    parts.push(`${JSON.stringify(key)}:${r.value}`);
  }
  ancestors.delete(value);
  return ok(`{${parts.join(",")}}`);
}

/** Path segment for an object key: the key itself, or `[key]` if it contains PII/secret patterns. */
function pathSegment(key: string): string {
  return redactText(key) === key ? key : "[key]";
}
