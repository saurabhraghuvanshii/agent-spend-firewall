import { canonicalJson } from "../audit/canonical-json.js";
import type { JsonValue } from "../audit/types.js";
import { err, ok, type Result } from "../result.js";
import {
  PolicyFault,
  createContext,
  deepFreeze,
  isPlainObject,
  newEvalState,
  settleInflight,
  toFrozenJsonObject,
  type EvalState,
} from "./context.js";
import {
  RESERVED_RULE_IDS,
  type Args,
  type CompiledPolicy,
  type CompiledRule,
  type Decision,
  type EvalInput,
  type EvalResult,
  type PolicyContext,
  type PolicyDeps,
  type RuleTrace,
  type TimerHandle,
} from "./types.js";

/**
 * Evaluate a compiled policy. Never rejects: every failure becomes a `deny` (fail closed, D-002).
 *
 * Semantics (D-013):
 * 1. Transform phase — transform rules targeting the tool run in declaration order; each sees the
 *    previous output. Patches merge shallowly. A patch must be JSON, must not set `reason`, and must
 *    not add, remove, raise or retype any field whose key contains "amount" (at any depth); a
 *    changed amount must be a positive safe integer (paise)
 *    ⇒ otherwise deny `engine-invalid-patch`.
 * 2. Gate phase — deny / require_approval / allow rules are evaluated against the transformed args.
 *    Most severe matching rule wins: deny > require_approval > allow; ties go to the first declared.
 *    The first matching deny short-circuits (later rules are not evaluated).
 * 3. Result — deny ⇒ deny. require_approval ⇒ require_approval (+ `patch` if transforms changed
 *    args). allow ⇒ `transform` if transforms changed args, else `allow`. No gate matched ⇒ policy
 *    default (`policy-default`): "deny" denies even if transforms ran; "allow" behaves like allow.
 *
 * Failures ⇒ deny: predicate/transform throws or rejects, a port returns `err` or a malformed value,
 * a predicate returns a non-boolean (`engine-error`); whole evaluation exceeds `timeoutMs`
 * (`engine-timeout`); bad input args (`invalid-args`); `ctx.amountPaise()` on a bad amount
 * (`invalid-amount`). A fault raised by a ctx helper denies even if the rule catches it.
 *
 * Port calls a rule started but did not await are still awaited (within the timeout) before any
 * non-deny result is returned; if one of them faulted the action is denied.
 * `evaluate` never rejects: a top-level guard turns any unexpected throw into `engine-error`.
 *
 * Known limitations: a synchronous infinite loop in a rule cannot be interrupted (JS is single
 * threaded; the timeout only wins at an `await`). Port calls in flight when the timeout fires keep
 * running; their results are ignored.
 */
export async function evaluate(
  policy: CompiledPolicy,
  input: EvalInput,
  deps: PolicyDeps,
): Promise<EvalResult> {
  const r: Run = { state: newEvalState(), trace: [], matched: [], args: EMPTY_ARGS };
  try {
    return await evaluateGuarded(policy, input, deps, r);
  } catch {
    // Top-level guard: `evaluate` must never reject, whatever the policy, input or ports do.
    r.state.closed = true;
    return deny(r, RESERVED_RULE_IDS.engineError, "Policy engine failed; action denied");
  }
}

async function evaluateGuarded(
  policy: CompiledPolicy,
  input: EvalInput,
  deps: PolicyDeps,
  r: Run,
): Promise<EvalResult> {
  if (!isCompiledPolicy(policy)) {
    return deny(r, RESERVED_RULE_IDS.engineError, "Policy not compiled; action denied");
  }

  let handle: TimerHandle;
  try {
    const h: unknown = deps.timer.after(policy.timeoutMs);
    if (!isTimerHandle(h)) {
      return deny(r, RESERVED_RULE_IDS.engineError, "Policy timer unavailable; action denied");
    }
    handle = h;
  } catch {
    return deny(r, RESERVED_RULE_IDS.engineError, "Policy timer unavailable; action denied");
  }

  let outcome: Outcome;
  try {
    const inner: Promise<Outcome> = run(policy, input, deps, r).then(
      (result): Outcome => ({ kind: "done", result }),
      (): Outcome => ({ kind: "crash" }),
    );
    const timeout: Promise<Outcome> = Promise.resolve(handle.promise).then(
      (): Outcome => ({ kind: "timeout" }),
      (): Outcome => ({ kind: "timer-failed" }),
    );
    outcome = await Promise.race([inner, timeout]);
  } catch {
    outcome = { kind: "crash" };
  }
  // From here on, ctx port wrappers refuse to run and late results are ignored.
  r.state.closed = true;

  try {
    handle.cancel();
  } catch {
    return deny(r, RESERVED_RULE_IDS.engineError, "Policy timer cancel failed; action denied");
  }

  switch (outcome.kind) {
    case "done":
      return outcome.result;
    case "timeout": {
      const at = r.state.currentRuleId === "" ? "" : ` in rule "${r.state.currentRuleId}"`;
      return deny(
        r,
        RESERVED_RULE_IDS.engineTimeout,
        `Policy evaluation exceeded ${policy.timeoutMs}ms${at}; action denied`,
      );
    }
    case "timer-failed":
      return deny(r, RESERVED_RULE_IDS.engineError, "Policy timer failed; action denied");
    case "crash":
      return deny(r, RESERVED_RULE_IDS.engineError, "Policy engine failed; action denied");
  }
}

function isCompiledPolicy(p: unknown): p is CompiledPolicy {
  if (typeof p !== "object" || p === null) return false;
  const c = p as Record<string, unknown>;
  return (
    c["kind"] === "compiled-policy" &&
    Array.isArray(c["rules"]) &&
    (c["default"] === "deny" || c["default"] === "allow") &&
    typeof c["timeoutMs"] === "number" &&
    Number.isSafeInteger(c["timeoutMs"]) &&
    c["timeoutMs"] > 0
  );
}

function isTimerHandle(h: unknown): h is TimerHandle {
  if (typeof h !== "object" || h === null) return false;
  const o = h as Record<string, unknown>;
  const promise = o["promise"];
  return (
    typeof promise === "object" &&
    promise !== null &&
    typeof (promise as Record<string, unknown>)["then"] === "function" &&
    typeof o["cancel"] === "function"
  );
}

type Outcome =
  | { kind: "done"; result: EvalResult }
  | { kind: "timeout" }
  | { kind: "timer-failed" }
  | { kind: "crash" };

/** Internal tracking shared by both phases. */
interface Run {
  state: EvalState;
  trace: RuleTrace[];
  matched: { index: number; id: string }[];
  args: Args;
}

const EMPTY_ARGS: Args = Object.freeze({});

async function run(
  policy: CompiledPolicy,
  input: EvalInput,
  deps: PolicyDeps,
  r: Run,
): Promise<EvalResult> {
  try {
    const res = await runPhases(policy, input, deps, r);
    if (res.decision.type === "deny") return res;
    // A rule may have started a port call without awaiting it. Wait for every such call (still
    // inside the timeout race) and deny if any of them faulted.
    await settleInflight(r.state);
    const fault: PolicyFault | undefined = r.state.fault;
    if (fault !== undefined) {
      return deny(
        r,
        fault.code,
        `Rule "${fault.ruleId}": ${fault.safeMessage} (unawaited); action denied`,
      );
    }
    return res;
  } catch {
    return deny(r, RESERVED_RULE_IDS.engineError, "Policy engine failed; action denied");
  }
}

async function runPhases(
  policy: CompiledPolicy,
  input: EvalInput,
  deps: PolicyDeps,
  r: Run,
): Promise<EvalResult> {
  if (typeof input !== "object" || input === null) {
    return deny(r, RESERVED_RULE_IDS.invalidArgs, "Evaluation input must be an object");
  }
  const { tool, reason, sessionId } = input;
  if (typeof tool !== "string" || tool === "") {
    return deny(r, RESERVED_RULE_IDS.invalidArgs, "Tool name must be a non-empty string");
  }
  if (typeof reason !== "string") {
    return deny(r, RESERVED_RULE_IDS.invalidArgs, "Reason must be a string");
  }
  if (typeof sessionId !== "string" || sessionId === "") {
    return deny(r, RESERVED_RULE_IDS.invalidArgs, "Session id must be a non-empty string");
  }
  const args = toFrozenJsonObject(input.args);
  if (args === undefined) {
    return deny(
      r,
      RESERVED_RULE_IDS.invalidArgs,
      "Tool arguments must be a JSON object with integer numbers",
    );
  }
  r.args = args;
  const ctxFor = (a: Args): PolicyContext =>
    createContext(r.state, { tool, args: a, reason, sessionId }, deps);

  // Phase 1: transforms.
  let combined: Record<string, JsonValue> | undefined;
  let firstTransformId: string | undefined;
  for (const rule of policy.rules) {
    if (rule.action.kind !== "transform" || !rule.tools.includes(tool)) continue;
    r.state.currentRuleId = rule.id;
    const ctx = ctxFor(r.args);
    const m = await matches(rule, ctx, r);
    if (m !== true) {
      if (m === false) continue;
      return m;
    }

    let raw: unknown;
    try {
      raw = await rule.action.fn(ctx);
    } catch {
      return ruleFailure(r, rule, "transform threw");
    }
    if (r.state.fault !== undefined) return ruleFailure(r, rule, "transform threw");

    const patch = validatePatch(raw, r.args);
    if (!patch.ok) {
      markError(r, rule);
      return deny(
        r,
        RESERVED_RULE_IDS.invalidPatch,
        `Rule "${rule.id}" returned an invalid patch (${patch.error.message}); action denied`,
      );
    }
    if (Object.keys(patch.value).length > 0) {
      r.args = deepFreeze({ ...r.args, ...patch.value });
      combined = { ...combined, ...patch.value };
      firstTransformId ??= rule.id;
    }
  }

  // Phase 2: gates.
  let winner: CompiledRule | undefined;
  const ctx = ctxFor(r.args);
  for (const rule of policy.rules) {
    if (rule.action.kind === "transform" || !rule.tools.includes(tool)) continue;
    r.state.currentRuleId = rule.id;
    const m = await matches(rule, ctx, r);
    if (m !== true) {
      if (m === false) continue;
      return m;
    }
    if (winner === undefined || severity(rule) > severity(winner)) winner = rule;
    if (rule.action.kind === "deny") break;
  }

  const patch: Args | undefined = combined === undefined ? undefined : deepFreeze({ ...combined });
  const matchedRules = matchedIds(r);
  const action = winner?.action;

  if (winner !== undefined && action?.kind === "deny") {
    return result(r, { type: "deny", ruleId: winner.id, message: action.message, matchedRules });
  }
  if (winner !== undefined && action?.kind === "require_approval") {
    const base = {
      type: "require_approval" as const,
      ruleId: winner.id,
      message: action.message,
      via: action.via,
      timeoutMin: action.timeoutMin,
    };
    return result(
      r,
      patch === undefined ? { ...base, matchedRules } : { ...base, patch, matchedRules },
    );
  }
  if (winner === undefined && policy.default === "deny") {
    return deny(r, RESERVED_RULE_IDS.default, "No rule allowed this action");
  }
  if (patch !== undefined && firstTransformId !== undefined) {
    return result(r, { type: "transform", ruleId: firstTransformId, patch, matchedRules });
  }
  return result(r, {
    type: "allow",
    ruleId: winner === undefined ? RESERVED_RULE_IDS.default : winner.id,
    matchedRules,
  });
}

/** `true` / `false`, or a deny result if the predicate failed. */
async function matches(
  rule: CompiledRule,
  ctx: PolicyContext,
  r: Run,
): Promise<boolean | EvalResult> {
  if (rule.when === undefined) {
    recordMatch(r, rule);
    return true;
  }
  let v: unknown;
  try {
    v = await rule.when(ctx);
  } catch {
    return ruleFailure(r, rule, "predicate threw");
  }
  if (r.state.fault !== undefined) return ruleFailure(r, rule, "predicate threw");
  if (typeof v !== "boolean") return ruleFailure(r, rule, "predicate returned a non-boolean");
  if (v) {
    recordMatch(r, rule);
  } else {
    r.trace.push({ ruleId: rule.id, action: rule.action.kind, result: "not_matched" });
  }
  return v;
}

function recordMatch(r: Run, rule: CompiledRule): void {
  r.trace.push({ ruleId: rule.id, action: rule.action.kind, result: "matched" });
  r.matched.push({ index: rule.index, id: rule.id });
}

function markError(r: Run, rule: CompiledRule): void {
  const last = r.trace[r.trace.length - 1];
  if (last !== undefined && last.ruleId === rule.id) {
    last.result = "error";
  } else {
    r.trace.push({ ruleId: rule.id, action: rule.action.kind, result: "error" });
  }
}

/** Deny for a failing rule. Uses the recorded ctx fault if any (it wins over the generic message). */
function ruleFailure(r: Run, rule: CompiledRule, what: string): EvalResult {
  markError(r, rule);
  const fault: PolicyFault | undefined = r.state.fault;
  if (fault !== undefined) {
    return deny(
      r,
      fault.code,
      `Rule "${fault.ruleId || rule.id}": ${fault.safeMessage}; action denied`,
    );
  }
  return deny(r, RESERVED_RULE_IDS.engineError, `Rule "${rule.id}": ${what}; action denied`);
}

function severity(rule: CompiledRule): number {
  switch (rule.action.kind) {
    case "deny":
      return 3;
    case "require_approval":
      return 2;
    case "transform":
    case "allow":
      return 1;
  }
}

function matchedIds(r: Run): string[] {
  return [...r.matched].sort((a, b) => a.index - b.index).map((m) => m.id);
}

function result(r: Run, decision: Decision): EvalResult {
  return { decision, finalArgs: r.args, trace: r.trace.map((t) => ({ ...t })) };
}

function deny(r: Run, ruleId: string, message: string): EvalResult {
  return result(r, { type: "deny", ruleId, message, matchedRules: matchedIds(r) });
}

// ---------------------------------------------------------------------------------------------
// Patch validation
// ---------------------------------------------------------------------------------------------

const AMOUNT_KEY = /amount/i;

function validatePatch(raw: unknown, current: Args): Result<Args> {
  if (!isPlainObject(raw)) return err("patch.not_object", "patch must be a plain object");
  const patch = toFrozenJsonObject(raw);
  if (patch === undefined) return err("patch.not_json", "patch must be JSON with integer numbers");
  if (Object.hasOwn(patch, "reason")) return err("patch.reason", "patch must not set reason");

  const merged: Args = { ...current, ...patch };
  const before = amountLeaves(current);
  const after = amountLeaves(merged);
  for (const path of before.keys()) {
    if (!after.has(path))
      return err("patch.amount_removed", "patch must not remove an amount field");
  }
  for (const [path, v] of after) {
    const b = before.get(path);
    if (b === undefined) return err("patch.amount_added", "patch must not add an amount field");
    if (sameJson(v, b)) continue;
    if (typeof v !== "number" || typeof b !== "number") {
      return err("patch.amount_type", "patch must not change the type of an amount field");
    }
    if (!Number.isSafeInteger(v) || v <= 0) {
      return err("patch.amount_invalid", "a changed amount must be a positive integer in paise");
    }
    if (v > b) return err("patch.amount_increased", "patch must not increase an amount");
  }
  return ok(patch);
}

/** Every value under a key matching /amount/i, keyed by its JSON path. */
function amountLeaves(root: JsonValue): Map<string, JsonValue> {
  const out = new Map<string, JsonValue>();
  const walk = (v: JsonValue, path: (string | number)[]): void => {
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(item, [...path, i]));
    } else if (typeof v === "object" && v !== null) {
      for (const [k, child] of Object.entries(v)) {
        const p = [...path, k];
        if (AMOUNT_KEY.test(k)) out.set(JSON.stringify(p), child);
        walk(child, p);
      }
    }
  };
  walk(root, []);
  return out;
}

function sameJson(a: JsonValue, b: JsonValue): boolean {
  const ea = canonicalJson(a);
  const eb = canonicalJson(b);
  return ea.ok && eb.ok && ea.value === eb.value;
}

// ---------------------------------------------------------------------------------------------
// Explain
// ---------------------------------------------------------------------------------------------

/** Human-readable explanation: the decision, then each evaluated rule and its result. */
export function explain(res: EvalResult): string[] {
  const d = res.decision;
  const lines: string[] = [];
  switch (d.type) {
    case "allow":
      lines.push(`allow (${d.ruleId})`);
      break;
    case "deny":
      lines.push(`deny (${d.ruleId}): ${d.message}`);
      break;
    case "require_approval":
      lines.push(
        `require_approval (${d.ruleId}) via ${d.via}, timeout ${d.timeoutMin}min: ${d.message}` +
          (d.patch === undefined ? "" : ` [patched: ${Object.keys(d.patch).sort().join(", ")}]`),
      );
      break;
    case "transform":
      lines.push(`transform (${d.ruleId}) [patched: ${Object.keys(d.patch).sort().join(", ")}]`);
      break;
  }
  lines.push(
    d.matchedRules.length === 0
      ? "matched rules: none"
      : `matched rules: ${d.matchedRules.join(", ")}`,
  );
  for (const t of res.trace)
    lines.push(`  ${t.ruleId} [${t.action}]: ${t.result.replace("_", " ")}`);
  return lines;
}
