/**
 * Call-time checks for money tools (T004): the enforcement side of `schema-rewrite.ts`. The advertised schema is only a
 * hint to the agent; nothing here trusts that the agent honoured it.
 *
 * For `toolClass === "money"` (read tools pass through untouched, including any `reason` argument):
 * 1. The upstream schema must still be rewritable ⇒ else deny `firewall.schema_conflict`.
 * 2. Args must be bounded (depth <= 32, <= 10k nodes) ⇒ else deny `firewall.invalid_args`.
 * 3. Top-level keys must be ASCII `[A-Za-z0-9_]+`, and no key other than exactly `reason` may fold (lowercase,
 *    alphanumerics only) to "reason" (`Reason`, `re_ason`, Cyrillic lookalikes, …) ⇒ else deny `firewall.invalid_args`.
 *    Full unknown-key rejection is T020.
 * 4. `reason`: a string, 10..500 code points after trimming, at least 5 letters/digits, no control characters other
 *    than tab / newline, no format / separator / private-use / unassigned characters or blank fillers, no lone
 *    surrogates ⇒ else deny `firewall.reason_required`. The reason is never echoed back or logged here.
 * 5. Every key matching `/^currency$/i` at any depth (incl. `transfers[].currency`, `notes`) must hold exactly the
 *    string "INR" ⇒ else deny `firewall.currency_not_inr` (D-017).
 * 6. Every `/amount/i` key at any depth (incl. inside `notes`, arrays) must hold a positive safe integer, at least the
 *    advertised `minimum` where the schema describes that position ⇒ else deny `firewall.invalid_amount` naming the
 *    field path (safe key names only, never the value). Exceptions: a boolean on a key the schema declares `boolean`
 *    (e.g. `create_qr_code.fixed_amount`); a STRING directly under top-level `notes` (Razorpay notes are opaque).
 * 7. `reason` is stripped (fresh object) and exposed to later stages only as `ctx.untrustedReason` (D-004, D-015).
 *
 * Every deny is returned before `next`, so upstream is never called.
 */
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Stage } from "./interceptor-chain.js";
import {
  AMOUNT_KEY,
  isRecord,
  REASON_MAX,
  REASON_MIN,
  rewriteMoneySchema,
} from "./schema-rewrite.js";
import { denyResult } from "./server.js";

export const MAX_ARGS_DEPTH = 32;
export const MAX_ARGS_NODES = 10_000;

/** A reason must contain at least this many letters / digits (so ".........." or emoji-only is not a reason). */
export const REASON_MIN_WORD_CHARS = 5;

export const REASON_REQUIRED_MESSAGE =
  `money tools require a "reason" argument: a string of ${String(REASON_MIN)} to ${String(REASON_MAX)} characters ` +
  `(at least ${String(REASON_MIN_WORD_CHARS)} letters or digits) explaining to a human reviewer why this action is needed ` +
  "(customer, order, evidence), without control or invisible characters. " +
  "The call was not sent.";

/** C0 (except \t and \n), DEL and C1 control characters. */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Invisible / layout-breaking characters: format (ZWSP, ZWJ, bidi overrides, BOM, …), line / paragraph separators,
 * private use, unassigned, and blank "filler" letters that render as nothing (Hangul fillers, braille blank).
 */
const INVISIBLE_CHARS = /[\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}\u115F\u1160\u3164\uFFA0\u2800]/u;
const WORD_CHAR = /[\p{L}\p{N}]/gu;

export function isValidReason(reason: unknown): reason is string {
  if (typeof reason !== "string") return false;
  // Cheap bound before any code-point spreading (a code point is at most 2 UTF-16 units).
  if (reason.length > REASON_MAX * 2) return false;
  if (CONTROL_CHARS.test(reason) || LONE_SURROGATE.test(reason) || INVISIBLE_CHARS.test(reason)) {
    return false;
  }
  if ([...reason].length > REASON_MAX) return false;
  if ([...reason.trim()].length < REASON_MIN) return false;
  return (reason.match(WORD_CHAR)?.length ?? 0) >= REASON_MIN_WORD_CHARS;
}

const ASCII_KEY = /^[A-Za-z0-9_]+$/;

/** True iff the top-level keys can't smuggle a second "reason" past the strip (see module doc, step 3). */
export function hasSafeTopLevelKeys(args: Readonly<Record<string, unknown>>): boolean {
  return Object.keys(args).every(
    (k) =>
      ASCII_KEY.test(k) &&
      (k === "reason" || k.toLowerCase().replace(/[^a-z0-9]/g, "") !== "reason"),
  );
}

const CURRENCY_KEY = /^currency$/i;

/** True iff every `currency`-named key at any depth holds exactly "INR". */
export function allCurrenciesInr(value: unknown): boolean {
  if (Array.isArray(value)) return value.every(allCurrenciesInr);
  if (!isRecord(value)) return true;
  return Object.entries(value).every(
    ([k, v]) => (!CURRENCY_KEY.test(k) || v === "INR") && allCurrenciesInr(v),
  );
}

/** True iff `value` is within the depth and node budget. */
export function isBounded(value: unknown): boolean {
  let nodes = 0;
  const visit = (v: unknown, depth: number): boolean => {
    nodes++;
    if (nodes > MAX_ARGS_NODES || depth > MAX_ARGS_DEPTH) return false;
    if (Array.isArray(v)) return v.every((x) => visit(x, depth + 1));
    if (isRecord(v)) return Object.values(v).every((x) => visit(x, depth + 1));
    return true;
  };
  return visit(value, 0);
}

const SAFE_KEY = /^[A-Za-z0-9_]{1,64}$/;

/** Key names are agent input: anything but a short ASCII identifier is rendered as `<key>` (no bidi / escapes). */
function pathSegment(key: string): string {
  return SAFE_KEY.test(key) ? key : "<key>";
}

function join(path: string, key: string): string {
  const seg = pathSegment(key);
  return path === "" ? seg : `${path}.${seg}`;
}

/** Schema node describing `value[key]` (properties, then additionalProperties), if any. */
function childSchema(
  schema: Record<string, unknown> | undefined,
  key: string,
): Record<string, unknown> | undefined {
  if (schema === undefined) return undefined;
  const props = schema["properties"];
  if (isRecord(props) && Object.hasOwn(props, key)) {
    const c = props[key];
    return isRecord(c) ? c : undefined;
  }
  const extra = schema["additionalProperties"];
  return isRecord(extra) ? extra : undefined;
}

function itemSchema(
  schema: Record<string, unknown> | undefined,
  index: number,
): Record<string, unknown> | undefined {
  const items = schema?.["items"];
  if (isRecord(items)) return items;
  if (Array.isArray(items)) {
    const it: unknown = items[index];
    return isRecord(it) ? it : undefined;
  }
  return undefined;
}

function isValidAmount(value: unknown, schema: Record<string, unknown> | undefined): boolean {
  if (typeof value === "boolean") return schema?.["type"] === "boolean";
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) return false;
  const min = schema?.["minimum"];
  return typeof min !== "number" || value >= min;
}

/**
 * Path of the first invalid amount-named field, or `undefined` if all are valid. `value` is the top-level args
 * object; string values directly under its `notes` are exempt (opaque Razorpay notes).
 */
export function findInvalidAmount(
  value: unknown,
  schema: Record<string, unknown> | undefined,
): string | undefined {
  return walkAmounts(value, schema, "", "top");
}

type Level = "top" | "notes" | "other";

function walkAmounts(
  value: unknown,
  schema: Record<string, unknown> | undefined,
  path: string,
  level: Level,
): string | undefined {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const bad = walkAmounts(value[i], itemSchema(schema, i), `${path}[${String(i)}]`, "other");
      if (bad !== undefined) return bad;
    }
    return undefined;
  }
  if (!isRecord(value)) return undefined;
  for (const [key, child] of Object.entries(value)) {
    const sub = childSchema(schema, key);
    const p = join(path, key);
    const exempt = level === "notes" && typeof child === "string";
    if (!exempt && AMOUNT_KEY.test(key) && !isValidAmount(child, sub)) return p;
    const childLevel: Level = level === "top" && key === "notes" ? "notes" : "other";
    const bad = walkAmounts(child, sub, p, childLevel);
    if (bad !== undefined) return bad;
  }
  return undefined;
}

export const moneyArgsStage: Stage = (ctx, next): Promise<CallToolResult> => {
  if (ctx.toolClass !== "money") return next(ctx);

  const rewritten = rewriteMoneySchema(ctx.inputSchema);
  if (!rewritten.ok) {
    return Promise.resolve(
      denyResult(
        "firewall.schema_conflict",
        `this tool is unavailable through the firewall (${rewritten.error.message}); the call was not sent`,
      ),
    );
  }
  if (!isBounded(ctx.args)) {
    return Promise.resolve(
      denyResult(
        "firewall.invalid_args",
        `tool arguments are too large or too deeply nested (max depth ${String(MAX_ARGS_DEPTH)}, max ${String(MAX_ARGS_NODES)} values); the call was not sent`,
      ),
    );
  }
  if (!hasSafeTopLevelKeys(ctx.args)) {
    return Promise.resolve(
      denyResult(
        "firewall.invalid_args",
        'top-level argument names must be ASCII letters, digits or underscores, and only the exact key "reason" may carry the justification; the call was not sent',
      ),
    );
  }
  const { reason, ...rest } = ctx.args;
  if (!isValidReason(reason)) {
    return Promise.resolve(denyResult("firewall.reason_required", REASON_REQUIRED_MESSAGE));
  }
  if (!allCurrenciesInr(rest)) {
    return Promise.resolve(
      denyResult(
        "firewall.currency_not_inr",
        'only INR is supported: every "currency" field must be exactly "INR" (amounts in paise); the call was not sent',
      ),
    );
  }
  const badAmount = findInvalidAmount(rest, rewritten.value);
  if (badAmount !== undefined) {
    return Promise.resolve(
      denyResult(
        "firewall.invalid_amount",
        `field ${badAmount} must be a positive whole number of paise (integer, at least the tool's minimum; ₹1 = 100 paise); the call was not sent`,
      ),
    );
  }
  return next({ ...ctx, args: rest, untrustedReason: reason });
};
