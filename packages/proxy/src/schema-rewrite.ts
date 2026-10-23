/**
 * Advertised-schema rewrite for money tools (T004, D-004).
 *
 * Pure: never mutates its input (the cached upstream `Tool`); always works on a deep clone.
 *
 * For a money tool's input schema:
 * - adds a required `reason: string` (10..500 code points) — untrusted justification, never used for allow decisions;
 * - tightens every number/integer property whose key matches `/amount/i` (at any depth via `properties`, `items`,
 *   `additionalProperties`) to `type: "integer"` with `minimum >= 1` (amounts are integer paise, D-003);
 * - restricts a top-level string `currency` property to `enum: ["INR"]` (D-017; enforcement is T008's job);
 * - an upstream schema that already has a `reason` property / required entry, or that is malformed, is an error:
 *   the tool is then advertised as unavailable and every call is denied (`firewall.schema_conflict`). Composition /
 *   reference / conditional keywords (`anyOf`, `$ref`, `if`, `patternProperties`, …) anywhere in the schema count as
 *   malformed: the call-time checks only follow `properties` / `items` / `additionalProperties`, so we fail closed
 *   rather than advertise or enforce something we don't understand (no Razorpay money tool uses them today).
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolClass } from "./tool-classes.js";

export type InputSchema = Tool["inputSchema"];

export const REASON_MIN = 10;
export const REASON_MAX = 500;
/** Max nesting of schema nodes we walk; deeper upstream schemas are treated as malformed (fail closed). */
export const MAX_SCHEMA_DEPTH = 64;

export const AMOUNT_KEY = /amount/i;

export const REASON_DESCRIPTION =
  "Explain to a human reviewer why this money action is needed (customer, order, evidence). Logged and shown to approvers; it does not authorise anything.";

export const MONEY_DESCRIPTION_PREFIX =
  "[Agent Spend Firewall] Money action: requires reason; amounts are integer paise; INR only; may be denied or held for approval. ";

export const UNAVAILABLE_DESCRIPTION_PREFIX = "UNAVAILABLE via firewall: ";

export interface RewriteError {
  readonly kind: "reason_collision" | "malformed_schema";
  readonly message: string;
}

export type RewriteResult =
  | { readonly ok: true; readonly value: InputSchema }
  | { readonly ok: false; readonly error: RewriteError };

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const malformed = (message: string): RewriteResult => ({
  ok: false,
  error: { kind: "malformed_schema", message },
});

/** Keywords whose presence anywhere in a money schema makes it `malformed_schema` (fail closed). */
export const UNSUPPORTED_KEYWORDS: ReadonlySet<string> = new Set([
  "anyOf",
  "oneOf",
  "allOf",
  "$ref",
  "$defs",
  "definitions",
  "patternProperties",
  "prefixItems",
  "if",
  "then",
  "else",
  "not",
]);

/** Keywords whose values are data, not subschemas (their keys are not keywords). */
const DATA_KEYWORDS: ReadonlySet<string> = new Set([
  "enum",
  "const",
  "default",
  "examples",
  "required",
]);

/** First unsupported keyword found in the schema tree, or `undefined`. `false` result ⇒ too deep. */
function findUnsupportedKeyword(node: unknown, depth: number): string | undefined | false {
  if (depth > MAX_SCHEMA_DEPTH) return false;
  if (Array.isArray(node)) {
    for (const x of node) {
      const r = findUnsupportedKeyword(x, depth + 1);
      if (r !== undefined) return r;
    }
    return undefined;
  }
  if (!isRecord(node)) return undefined;
  for (const [key, value] of Object.entries(node)) {
    if (UNSUPPORTED_KEYWORDS.has(key)) return key;
    if (DATA_KEYWORDS.has(key)) continue;
    // `properties` maps property NAMES (which may legitimately be "not", "if", …) to subschemas.
    const children = key === "properties" && isRecord(value) ? Object.values(value) : [value];
    for (const child of children) {
      const r = findUnsupportedKeyword(child, depth + 1);
      if (r !== undefined) return r;
    }
  }
  return undefined;
}

/** `type` (string or array of strings) declares a numeric type. */
function isNumericType(type: unknown): boolean {
  if (type === "number" || type === "integer") return true;
  return Array.isArray(type) && type.some((t) => t === "number" || t === "integer");
}

/**
 * One amount property → `type: "integer"`, `minimum = max(1, ceil(minimum), floor(exclusiveMinimum) + 1)`.
 * Handles both the numeric (draft 6+) and boolean (draft 4, applies to `minimum`) forms of `exclusiveMinimum`.
 */
function tightenAmount(child: Record<string, unknown>): void {
  const min = child["minimum"];
  const excl = child["exclusiveMinimum"];
  let bound = 1;
  if (typeof min === "number" && Number.isFinite(min)) {
    bound = Math.max(bound, excl === true ? Math.floor(min) + 1 : Math.ceil(min));
  }
  if (typeof excl === "number" && Number.isFinite(excl)) {
    bound = Math.max(bound, Math.floor(excl) + 1);
  }
  delete child["exclusiveMinimum"];
  child["type"] = "integer";
  child["minimum"] = bound;
}

/** Tighten amount-named numeric properties below `node` in place (node is part of a fresh clone). */
function tightenAmounts(node: Record<string, unknown>, depth: number): boolean {
  if (depth > MAX_SCHEMA_DEPTH) return false;
  const props = node["properties"];
  if (isRecord(props)) {
    for (const [key, child] of Object.entries(props)) {
      if (!isRecord(child)) continue;
      if (AMOUNT_KEY.test(key) && isNumericType(child["type"])) tightenAmount(child);
      if (!tightenAmounts(child, depth + 1)) return false;
    }
  }
  const items = node["items"];
  if (isRecord(items)) {
    if (!tightenAmounts(items, depth + 1)) return false;
  } else if (Array.isArray(items)) {
    for (const it of items) if (isRecord(it) && !tightenAmounts(it, depth + 1)) return false;
  }
  const extra = node["additionalProperties"];
  if (isRecord(extra) && !tightenAmounts(extra, depth + 1)) return false;
  return true;
}

export function rewriteMoneySchema(schema: InputSchema): RewriteResult {
  if (!isRecord(schema) || schema.type !== "object") {
    return malformed("input schema is not an object schema");
  }
  let clone: InputSchema;
  try {
    clone = structuredClone(schema);
  } catch {
    return malformed("input schema is not plain JSON");
  }
  const root: Record<string, unknown> = clone;
  const unsupported = findUnsupportedKeyword(root, 0);
  if (unsupported === false) return malformed("input schema is nested too deeply");
  if (unsupported !== undefined) {
    return malformed(`input schema uses unsupported keyword \`${unsupported}\``);
  }

  const props = root["properties"] ?? {};
  if (!isRecord(props)) return malformed("input schema `properties` is not an object");
  const required = root["required"] ?? [];
  if (!Array.isArray(required) || !required.every((r): r is string => typeof r === "string")) {
    return malformed("input schema `required` is not an array of strings");
  }
  if (Object.hasOwn(props, "reason") || required.includes("reason")) {
    return {
      ok: false,
      error: {
        kind: "reason_collision",
        message:
          "the upstream tool already defines a `reason` argument, which the firewall reserves",
      },
    };
  }
  root["properties"] = props;
  if (!tightenAmounts(root, 0)) return malformed("input schema is nested too deeply");

  const currency = props["currency"];
  if (isRecord(currency) && currency["type"] === "string") {
    delete currency["pattern"];
    currency["enum"] = ["INR"];
  }

  props["reason"] = {
    type: "string",
    minLength: REASON_MIN,
    maxLength: REASON_MAX,
    description: REASON_DESCRIPTION,
  };
  root["required"] = [...required, "reason"];
  return { ok: true, value: clone };
}

/**
 * The money tool as advertised to the agent. On a rewrite error the schema is left unchanged and the description
 * says the tool is unavailable (calls are denied with `firewall.schema_conflict` at call time).
 */
export function rewriteMoneyTool(tool: Tool): Tool {
  const copy = structuredClone(tool);
  const original = tool.description ?? "";
  const rewritten = rewriteMoneySchema(tool.inputSchema);
  if (!rewritten.ok) {
    return {
      ...copy,
      description: `${UNAVAILABLE_DESCRIPTION_PREFIX}${rewritten.error.message}. ${original}`,
    };
  }
  return {
    ...copy,
    description: `${MONEY_DESCRIPTION_PREFIX}${original}`,
    inputSchema: rewritten.value,
  };
}

/** The proxy's `advertise` hook: money tools rewritten, read tools returned as-is (byte-identical). */
export function advertiseTool(tool: Tool, toolClass: ToolClass): Tool {
  return toolClass === "money" ? rewriteMoneyTool(tool) : tool;
}
