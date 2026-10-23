import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  advertiseTool,
  isRecord,
  MONEY_DESCRIPTION_PREFIX,
  REASON_DESCRIPTION,
  REASON_MAX,
  REASON_MIN,
  rewriteMoneySchema,
  rewriteMoneyTool,
  UNAVAILABLE_DESCRIPTION_PREFIX,
  UNSUPPORTED_KEYWORDS,
  type InputSchema,
} from "./schema-rewrite.js";
import { classifyTool } from "./tool-classes.js";
import { toolsFileSchema } from "./tool-discovery.js";

function rewriteOk(s: InputSchema): Record<string, unknown> {
  const r = rewriteMoneySchema(s);
  if (!r.ok) throw new Error(`expected ok, got ${r.error.kind}: ${r.error.message}`);
  return r.value;
}

function prop(schema: unknown, ...path: string[]): Record<string, unknown> {
  let node: unknown = schema;
  for (const p of path) {
    if (!isRecord(node)) throw new Error(`no node at ${p}`);
    node = node[p];
  }
  if (!isRecord(node)) throw new Error(`no object at ${path.join(".")}`);
  return node;
}

const refundSchema: InputSchema = {
  type: "object",
  properties: {
    payment_id: { type: "string" },
    amount: { type: "number", minimum: 100, description: "paise" },
    speed: { type: "string" },
    notes: { type: "object", properties: {} },
  },
  required: ["payment_id"],
};

describe("rewriteMoneySchema", () => {
  it("adds a required reason (10..500) with the reviewer-facing description", () => {
    const out = rewriteOk(refundSchema);
    expect(prop(out, "properties", "reason")).toEqual({
      type: "string",
      minLength: REASON_MIN,
      maxLength: REASON_MAX,
      description: REASON_DESCRIPTION,
    });
    expect(out["required"]).toEqual(["payment_id", "reason"]);
    expect(REASON_MIN).toBe(10);
    expect(REASON_MAX).toBe(500);
  });

  it("creates missing properties / required", () => {
    const out = rewriteOk({ type: "object" });
    expect(Object.keys(prop(out, "properties"))).toEqual(["reason"]);
    expect(out["required"]).toEqual(["reason"]);
  });

  it("tightens top-level amounts to integer, keeping a higher minimum", () => {
    const out = rewriteOk({
      type: "object",
      properties: {
        amount: { type: "number", minimum: 100 },
        first_min_partial_amount: { type: "number" },
        Max_Amount: { type: "integer", minimum: 0 },
        frac_amount: { type: "number", minimum: 0.5 },
      },
    });
    expect(prop(out, "properties", "amount")).toEqual({ type: "integer", minimum: 100 });
    expect(prop(out, "properties", "first_min_partial_amount")).toEqual({
      type: "integer",
      minimum: 1,
    });
    expect(prop(out, "properties", "Max_Amount")).toEqual({ type: "integer", minimum: 1 });
    expect(prop(out, "properties", "frac_amount")).toEqual({ type: "integer", minimum: 1 });
  });

  it("tightens a numeric union type to integer", () => {
    const out = rewriteOk({
      type: "object",
      properties: { amount: { type: ["number", "null"] } },
    });
    expect(prop(out, "properties", "amount")).toEqual({ type: "integer", minimum: 1 });
  });

  it("tightens nested amounts via items / properties / additionalProperties", () => {
    const out = rewriteOk({
      type: "object",
      properties: {
        transfers: {
          type: "array",
          items: {
            type: "object",
            properties: { account: { type: "string" }, amount: { type: "number" } },
          },
        },
        token: { type: "object", properties: { max_amount: { type: "number", minimum: 500 } } },
        by_key: {
          type: "object",
          additionalProperties: { type: "object", properties: { amount: { type: "number" } } },
        },
        tuple: {
          type: "array",
          items: [{ type: "object", properties: { amount: { type: "number" } } }],
        },
      },
    });
    expect(prop(out, "properties", "transfers", "items", "properties", "amount")).toEqual({
      type: "integer",
      minimum: 1,
    });
    expect(prop(out, "properties", "token", "properties", "max_amount")).toEqual({
      type: "integer",
      minimum: 500,
    });
    expect(
      prop(out, "properties", "by_key", "additionalProperties", "properties", "amount"),
    ).toEqual({ type: "integer", minimum: 1 });
    const tuple = prop(out, "properties", "tuple")["items"];
    expect(tuple).toEqual([
      { type: "object", properties: { amount: { type: "integer", minimum: 1 } } },
    ]);
  });

  it("leaves non-numeric amount-named fields (fixed_amount boolean) untouched", () => {
    const fixed = { type: "boolean", default: false, description: "only a specific amount" };
    const label = { type: "string" };
    const out = rewriteOk({
      type: "object",
      properties: { fixed_amount: fixed, amount_label: label },
    });
    expect(prop(out, "properties", "fixed_amount")).toEqual(fixed);
    expect(prop(out, "properties", "amount_label")).toEqual(label);
  });

  it("restricts a top-level string currency to INR, dropping a conflicting pattern", () => {
    const out = rewriteOk({
      type: "object",
      properties: {
        currency: { type: "string", pattern: "^[A-Z]{3}$", description: "ISO code" },
      },
    });
    expect(prop(out, "properties", "currency")).toEqual({
      type: "string",
      enum: ["INR"],
      description: "ISO code",
    });
  });

  it.each([
    ["reason property", { type: "object", properties: { reason: { type: "string" } } }],
    ["reason required only", { type: "object", properties: {}, required: ["reason"] }],
  ] as const)("upstream %s ⇒ reason_collision", (_n, schema) => {
    const r = rewriteMoneySchema(schema as unknown as InputSchema);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("reason_collision");
  });

  it.each([
    ["non-object type", { type: "array" }],
    ["properties not an object", { type: "object", properties: [] }],
    ["properties a string", { type: "object", properties: "x" }],
    ["required not strings", { type: "object", required: [1] }],
  ])("%s ⇒ malformed_schema", (_n, schema) => {
    const r = rewriteMoneySchema(schema as unknown as InputSchema);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("malformed_schema");
  });

  it.each(
    [...UNSUPPORTED_KEYWORDS].flatMap((kw) => [
      [`${kw} at the root`, { type: "object", [kw]: [{ type: "object" }] }],
      [
        `${kw} nested in a property`,
        { type: "object", properties: { amount: { type: "number", [kw]: { type: "string" } } } },
      ],
      [
        `${kw} deep in items`,
        {
          type: "object",
          properties: {
            transfers: {
              type: "array",
              items: { type: "object", properties: { x: { [kw]: {} } } },
            },
          },
        },
      ],
    ]),
  )("%s ⇒ malformed_schema (fail closed)", (_n, schema) => {
    const r = rewriteMoneySchema(schema as unknown as InputSchema);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.kind).toBe("malformed_schema");
      expect(r.error.message).toContain("unsupported keyword");
    }
  });

  it("property NAMES and data values that look like keywords are fine", () => {
    const out = rewriteOk({
      type: "object",
      properties: {
        not: { type: "string" },
        if: { type: "object", properties: { anyOf: { type: "string" } } },
        mode: { type: "string", enum: [{ $ref: "x" }], default: { oneOf: 1 } },
      },
    });
    expect(Object.keys(prop(out, "properties"))).toEqual(["not", "if", "mode", "reason"]);
  });

  it.each([
    ["numeric exclusiveMinimum 0", { exclusiveMinimum: 0 }, 1],
    ["numeric exclusiveMinimum 99", { exclusiveMinimum: 99 }, 100],
    ["fractional exclusiveMinimum 99.5", { exclusiveMinimum: 99.5 }, 100],
    ["exclusiveMinimum below minimum", { minimum: 500, exclusiveMinimum: 10 }, 500],
    ["exclusiveMinimum above minimum", { minimum: 10, exclusiveMinimum: 500 }, 501],
    ["draft-4 boolean exclusiveMinimum", { minimum: 100, exclusiveMinimum: true }, 101],
    ["draft-4 boolean false", { minimum: 100, exclusiveMinimum: false }, 100],
    ["negative exclusiveMinimum", { exclusiveMinimum: -5 }, 1],
  ])("amount with %s ⇒ integer minimum %d, exclusiveMinimum removed", (_n, bounds, expected) => {
    const out = rewriteOk({
      type: "object",
      properties: { amount: { type: "number", ...bounds } },
    });
    expect(prop(out, "properties", "amount")).toEqual({ type: "integer", minimum: expected });
  });

  it("over-deep schema ⇒ malformed_schema", () => {
    let node: Record<string, unknown> = { type: "number" };
    for (let i = 0; i < 80; i++) node = { type: "object", properties: { x: node } };
    const r = rewriteMoneySchema(node as InputSchema);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("malformed_schema");
  });

  it("does not mutate its input", () => {
    const input = structuredClone(refundSchema);
    const before = JSON.stringify(input);
    Object.freeze(input);
    const out = rewriteOk(input);
    expect(JSON.stringify(input)).toBe(before);
    expect(out).not.toBe(input);
    expect(out["properties"]).not.toBe(input.properties);
  });
});

describe("rewriteMoneyTool / advertiseTool", () => {
  const tool: Tool = {
    name: "create_refund",
    description: "Create a refund",
    inputSchema: refundSchema,
    annotations: { destructiveHint: true },
  };

  it("prefixes the description and rewrites the schema without mutating the tool", () => {
    const before = JSON.stringify(tool);
    const out = rewriteMoneyTool(tool);
    expect(out.description).toBe(`${MONEY_DESCRIPTION_PREFIX}Create a refund`);
    expect(out.inputSchema.required).toContain("reason");
    expect(out.annotations).toEqual(tool.annotations);
    expect(JSON.stringify(tool)).toBe(before);
  });

  it("on a rewrite error: marked unavailable, schema unchanged", () => {
    const clash: Tool = {
      name: "x",
      description: "orig",
      inputSchema: { type: "object", properties: { reason: { type: "string" } } },
    };
    const out = rewriteMoneyTool(clash);
    expect(out.description?.startsWith(UNAVAILABLE_DESCRIPTION_PREFIX)).toBe(true);
    expect(out.description?.endsWith("orig")).toBe(true);
    expect(out.inputSchema).toEqual(clash.inputSchema);
  });

  it("read tools are returned as the same object", () => {
    expect(advertiseTool(tool, "read")).toBe(tool);
    expect(advertiseTool(tool, "money")).not.toBe(tool);
  });
});

describe("docs/razorpay-tools.json", () => {
  const file = toolsFileSchema.parse(
    JSON.parse(readFileSync(new URL("../../../docs/razorpay-tools.json", import.meta.url), "utf8")),
  );
  const tools: Tool[] = file.tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
  const money = tools.filter((t) => classifyTool(t.name) === "money");
  const read = tools.filter((t) => classifyTool(t.name) === "read");

  it("has both classes", () => {
    expect(money.length).toBeGreaterThan(0);
    expect(read.length).toBeGreaterThan(0);
  });

  it.each(money.map((t) => [t.name, t] as const))(
    "money tool %s rewrites ok (required reason, integer amounts, INR)",
    (_n, t) => {
      const out = rewriteOk(t.inputSchema);
      expect(out["required"]).toContain("reason");
      const props = prop(out, "properties");
      for (const [k, v] of Object.entries(props)) {
        if (/amount/i.test(k) && isRecord(v) && v["type"] !== "boolean") {
          expect(v["type"]).toBe("integer");
          expect(v["minimum"]).toBeGreaterThanOrEqual(1);
        }
        if (k === "currency") expect(prop(v)["enum"]).toEqual(["INR"]);
      }
    },
  );

  it.each(read.map((t) => [t.name, t] as const))(
    "read tool %s is advertised untouched",
    (_n, t) => {
      const before = JSON.stringify(t);
      expect(JSON.stringify(advertiseTool(t, "read"))).toBe(before);
    },
  );

  it("advertised money schemas (snapshot)", () => {
    const view = Object.fromEntries(money.map((t) => [t.name, rewriteOk(t.inputSchema)]));
    expect(view).toMatchSnapshot();
  });
});
