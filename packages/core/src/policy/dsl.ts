import type {
  ApprovalOptions,
  PolicySpec,
  Predicate,
  Rule,
  RuleAction,
  TransformFn,
} from "./types.js";

/** Terminal step of the builder: every method returns a finished `Rule`. */
export interface RuleActions {
  deny(message: string): Rule;
  requireApproval(opts: ApprovalOptions): Rule;
  transform(fn: TransformFn): Rule;
  allow(): Rule;
}

/** After `.on()`: optionally add one predicate, then pick an action. */
export interface RuleTarget extends RuleActions {
  when(pred: Predicate): RuleActions;
}

/** After `rule(id)`: the tool(s) must be chosen first. */
export interface RuleStart {
  on(tools: string | readonly string[]): RuleTarget;
}

/**
 * Fluent rule builder:
 * `rule("refund.hard_cap").on("create_refund").when((ctx) => ctx.amountPaise() > 1_000_000).deny("…")`.
 *
 * Builders are immutable and never throw; all validation happens in `compilePolicy`.
 * An unfinished builder (no action) is not assignable to `Rule`.
 */
export function rule(id: string): RuleStart {
  return {
    on(tools: string | readonly string[]): RuleTarget {
      const toolList: readonly string[] = Object.freeze(
        typeof tools === "string" ? [tools] : [...tools],
      );
      return {
        ...actions(id, toolList, undefined),
        when(pred: Predicate): RuleActions {
          return actions(id, toolList, pred);
        },
      };
    },
  };
}

function actions(id: string, tools: readonly string[], when: Predicate | undefined): RuleActions {
  const make = (action: RuleAction): Rule =>
    Object.freeze(
      when === undefined
        ? { kind: "rule" as const, id, tools, action: Object.freeze(action) }
        : { kind: "rule" as const, id, tools, when, action: Object.freeze(action) },
    );
  return {
    deny: (message) => make({ kind: "deny", message }),
    requireApproval: (opts) =>
      make({
        kind: "require_approval",
        via: opts.via,
        timeoutMin: opts.timeoutMin,
        message: opts.message,
      }),
    transform: (fn) => make({ kind: "transform", fn }),
    allow: () => make({ kind: "allow" }),
  };
}

/**
 * Declare a policy. Rules are evaluated in declaration order; see `evaluate` for precedence.
 * Returns the spec unchanged (frozen); call `compilePolicy` to validate it.
 */
export function definePolicy(spec: PolicySpec): PolicySpec {
  const rules = Object.freeze([...spec.rules]);
  return Object.freeze(
    spec.timeoutMs === undefined
      ? { rules, default: spec.default }
      : { rules, default: spec.default, timeoutMs: spec.timeoutMs },
  );
}
