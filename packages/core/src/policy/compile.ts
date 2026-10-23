import { err, ok, type FirewallErrorDetail, type Result } from "../result.js";
import {
  DEFAULT_POLICY_TIMEOUT_MS,
  type CompiledPolicy,
  type CompiledRule,
  type PolicySpec,
  type Predicate,
  type RuleAction,
} from "./types.js";

export const RULE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const RESERVED_PREFIXES = ["engine-", "policy-"] as const;
const RESERVED_IDS: ReadonlySet<string> = new Set(["invalid-args", "invalid-amount"]);
const MAX_TIMEOUT_MS = 10_000;
const MAX_APPROVAL_TIMEOUT_MIN = 1440;

export function isReservedRuleId(id: string): boolean {
  return RESERVED_IDS.has(id) || RESERVED_PREFIXES.some((p) => id.startsWith(p));
}

/**
 * Validate a policy spec and freeze it into an evaluable form. Treats the spec as untrusted at
 * runtime (it may come from JS or casts), so every field is re-checked. Never throws.
 */
export function compilePolicy(spec: PolicySpec): Result<CompiledPolicy> {
  try {
    return compileUnsafe(spec);
  } catch (e: unknown) {
    return err("policy.compile_exception", "policy compilation threw", {
      cause: e instanceof Error ? e.name : typeof e,
    });
  }
}

function compileUnsafe(spec: unknown): Result<CompiledPolicy> {
  if (!isRecord(spec)) return err("policy.invalid_spec", "policy spec must be an object");

  const def = spec["default"];
  if (def !== "deny" && def !== "allow") {
    return err("policy.invalid_default", 'policy default must be "deny" or "allow"');
  }

  const rawTimeout = spec["timeoutMs"];
  const timeoutMs = rawTimeout === undefined ? DEFAULT_POLICY_TIMEOUT_MS : rawTimeout;
  if (
    typeof timeoutMs !== "number" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS
  ) {
    return err("policy.invalid_timeout", `timeoutMs must be an integer 1..${MAX_TIMEOUT_MS}`);
  }

  const rules = spec["rules"];
  if (!Array.isArray(rules)) return err("policy.invalid_spec", "policy rules must be an array");

  const seen = new Set<string>();
  const compiled: CompiledRule[] = [];
  for (let index = 0; index < rules.length; index++) {
    const r = compileRule(rules[index] as unknown, index, seen);
    if (!r.ok) return r;
    compiled.push(r.value);
  }

  return ok(
    Object.freeze({
      kind: "compiled-policy" as const,
      rules: Object.freeze(compiled),
      default: def,
      timeoutMs,
    }),
  );
}

function compileRule(raw: unknown, index: number, seen: Set<string>): Result<CompiledRule> {
  const at: Record<string, FirewallErrorDetail> = { index };
  if (!isRecord(raw)) return err("policy.invalid_rule", "rule must be an object", at);
  if (raw["kind"] !== "rule") {
    return err(
      "policy.missing_action",
      "not a finished rule: call .deny/.requireApproval/.transform/.allow",
      at,
    );
  }

  const id = raw["id"];
  if (typeof id !== "string" || !RULE_ID_PATTERN.test(id)) {
    return err("policy.invalid_rule_id", `rule id must match ${String(RULE_ID_PATTERN)}`, at);
  }
  const where: Record<string, FirewallErrorDetail> = { index, ruleId: id };
  if (isReservedRuleId(id)) {
    return err("policy.reserved_rule_id", `rule id "${id}" is reserved`, where);
  }
  if (seen.has(id)) return err("policy.duplicate_rule_id", `duplicate rule id "${id}"`, where);
  seen.add(id);

  const tools = raw["tools"];
  if (!Array.isArray(tools) || tools.length === 0) {
    return err(
      "policy.missing_tools",
      `rule "${id}" must target at least one tool via .on()`,
      where,
    );
  }
  const toolList: string[] = [];
  for (const t of tools as unknown[]) {
    if (typeof t !== "string" || t === "" || t.trim() !== t) {
      return err(
        "policy.invalid_tool",
        `rule "${id}" has an empty, non-string or whitespace-padded tool name`,
        where,
      );
    }
    if (!toolList.includes(t)) toolList.push(t);
  }
  const toolSet: readonly string[] = Object.freeze(toolList);

  const when = raw["when"];
  if (when !== undefined && typeof when !== "function") {
    return err("policy.invalid_predicate", `rule "${id}" predicate must be a function`, where);
  }

  if (raw["action"] === undefined) {
    return err(
      "policy.missing_action",
      `rule "${id}" has no action (call .deny/.requireApproval/.transform/.allow)`,
      where,
    );
  }
  const action = compileAction(raw["action"], id, where);
  if (!action.ok) return action;

  const base = { index, id, tools: toolSet, action: action.value };
  return ok(Object.freeze(when === undefined ? base : { ...base, when: when as Predicate }));
}

function compileAction(
  raw: unknown,
  id: string,
  where: Record<string, FirewallErrorDetail>,
): Result<RuleAction> {
  if (!isRecord(raw))
    return err("policy.invalid_action", `rule "${id}" action is malformed`, where);
  switch (raw["kind"]) {
    case "allow":
      return ok(Object.freeze({ kind: "allow" as const }));
    case "deny": {
      const message = raw["message"];
      if (!isNonEmptyString(message)) {
        return err("policy.invalid_action", `rule "${id}" deny message must be non-empty`, where);
      }
      return ok(Object.freeze({ kind: "deny" as const, message }));
    }
    case "require_approval": {
      const { via, timeoutMin, message } = raw;
      if (via !== "telegram" && via !== "dashboard") {
        return err(
          "policy.invalid_action",
          `rule "${id}" approval via must be "telegram" or "dashboard"`,
          where,
        );
      }
      if (
        typeof timeoutMin !== "number" ||
        !Number.isInteger(timeoutMin) ||
        timeoutMin < 1 ||
        timeoutMin > MAX_APPROVAL_TIMEOUT_MIN
      ) {
        return err(
          "policy.invalid_action",
          `rule "${id}" approval timeoutMin must be an integer 1..${MAX_APPROVAL_TIMEOUT_MIN}`,
          where,
        );
      }
      if (!isNonEmptyString(message)) {
        return err(
          "policy.invalid_action",
          `rule "${id}" approval message must be non-empty`,
          where,
        );
      }
      return ok(Object.freeze({ kind: "require_approval" as const, via, timeoutMin, message }));
    }
    case "transform": {
      const fn = raw["fn"];
      if (typeof fn !== "function") {
        return err("policy.invalid_action", `rule "${id}" transform must be a function`, where);
      }
      return ok(Object.freeze({ kind: "transform" as const, fn: fn as RuleActionTransformFn }));
    }
    default:
      return err("policy.invalid_action", `rule "${id}" has an unknown action`, where);
  }
}

type RuleActionTransformFn = Extract<RuleAction, { kind: "transform" }>["fn"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim() !== "";
}
