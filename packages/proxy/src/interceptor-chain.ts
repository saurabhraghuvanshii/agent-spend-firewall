/**
 * Composable call-interceptor stages (T004; T008 adds the policy stage).
 *
 * A `Stage` either returns a result itself (deny, …) or calls `next(ctx')` with a possibly narrowed context. The
 * last `next` forwards `ctx.args` upstream. Guarantees:
 * - each `next` may be invoked at most once; a second invocation is refused (`firewall.forward_twice`) and never
 *   reaches later stages or upstream (the server's `forward` enforces the same at the boundary);
 * - a stage that throws ⇒ structured deny (fail closed). If the call may already have been sent, the message says
 *   so (never claims "not sent").
 */
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { denyResult, type CallContext, type CallInterceptor } from "./server.js";
import type { Logger } from "./upstream.js";
import { moneyArgsStage } from "./money-args.js";

export type Next = (ctx: CallContext) => Promise<CallToolResult>;
export type Stage = (ctx: CallContext, next: Next) => Promise<CallToolResult>;

export interface ComposeOptions {
  /** Operator log (stderr). Only the error class is logged, never messages (they may embed agent input). */
  readonly logger?: Logger;
}

export function composeInterceptors(
  stages: readonly Stage[],
  opts: ComposeOptions = {},
): CallInterceptor {
  const frozen = [...stages];
  const log: Logger = opts.logger ?? (() => undefined);
  return {
    intercept: async (ctx, forward) => {
      let forwarded = false;
      const at = (i: number): Next => {
        let used = false;
        return async (c) => {
          if (used) {
            return denyResult(
              "firewall.forward_twice",
              "the firewall refused to send this call twice; the second send was not made",
            );
          }
          used = true;
          const stage = frozen[i];
          if (stage === undefined) {
            forwarded = true;
            return forward({ ...c.args });
          }
          return stage(c, at(i + 1));
        };
      };
      try {
        return await at(0)(ctx);
      } catch (e: unknown) {
        log(
          `interceptor stage threw ${e instanceof Error ? e.name : typeof e}; denied (forwarded: ${String(forwarded)})`,
        );
        return denyResult(
          "firewall.interceptor_error",
          forwarded
            ? "the firewall failed after this call was sent upstream; check its status before retrying"
            : "the firewall could not evaluate this call; it was denied (fail closed)",
        );
      }
    },
  };
}

/**
 * The firewall's stage list: `moneyArgsStage` ALWAYS first, then `laterStages` in order. Later stages (policy, audit,
 * approvals) therefore only ever see money calls whose args are validated with `reason` stripped, and the
 * justification only as `ctx.untrustedReason`. Use this rather than hand-assembling the list.
 */
export function firewallChain(...laterStages: readonly Stage[]): readonly Stage[] {
  return Object.freeze([moneyArgsStage, ...laterStages]);
}
