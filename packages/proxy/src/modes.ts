/**
 * T012 — firewall modes: kill switch and shadow mode.
 *
 * State lives in the AUDIT LOG (D-035): every change is a chained `mode` record {killSwitch, shadow, actor, ts}, and
 * the latest one (indexed lookup, own hash re-checked) is the current mode; none ⇒ both off. The proxy reads it on
 * EVERY money call, so a change from the CLI (`asf-proxy mode …`) or, later, the API (T013) takes effect on the next
 * call without a restart.
 *
 * - Fail closed: if the mode can't be read (DB error, malformed / tampered record, store closed, reader threw) the
 *   kill switch is treated as ON.
 * - Kill switch ON ⇒ every money call is denied `{decision:"deny", ruleId:"kill-switch", message}` — live calls, T011
 *   approved executions and T010 retries (checked again right before each send). Read tools pass through. It wins
 *   over shadow mode and over every other state.
 * - Shadow mode ON (kill off) ⇒ the money pipeline computes the policy decision but forwards the agent's ORIGINAL
 *   validated args; the attempt is recorded `decision: "allow"`, `shadow: true`, `wouldDecision`. Firewall
 *   invariants (args validation, reason, INR, duplicates, verify-before-retry, audit-before-forward) still apply, and
 *   an engine error / timeout / invalid patch is still a real deny (`isShadowableDecision`).
 */
import {
  err,
  ok,
  RESERVED_RULE_IDS,
  type CompiledPolicy,
  type EvalResult,
  type Result,
} from "@asf/core";
import type { AuditModeRecord, AuditStore, ChangeModeInput } from "./audit-store.js";
import type { PreCheckVerdict } from "./interceptor.js";
import type { CallContext } from "./server.js";
import type { Logger } from "./upstream.js";

/** Rule id of every kill-switch deny (agent result and audit). */
export const KILL_SWITCH_RULE = "kill-switch";

export const KILL_SWITCH_MESSAGE =
  "the firewall kill switch is ON: all money actions are frozen by the operator. The call was not sent; do not retry until an operator turns it off";
export const MODE_UNREADABLE_MESSAGE =
  "the firewall could not read its mode, so money actions are frozen (kill switch treated as ON). The call was not sent";

export interface ModeState {
  readonly killSwitch: boolean;
  readonly shadow: boolean;
}

/** Current mode plus who set it and when (absent when no mode record was ever written). */
export interface ModeSnapshot extends ModeState {
  readonly changedAt?: string;
  readonly actor?: string;
  readonly recordId?: string;
}

export interface ModeChange {
  readonly killSwitch?: boolean;
  readonly shadow?: boolean;
  /** `cli:<slug>` | `dashboard:<slug>` | `telegram:<id>` (core `MODE_ACTOR_RE`). */
  readonly actor: string;
}

/**
 * Small surface for the CLI, the proxy and the T013 API. `read` never throws; `err` means "unknown" and callers must
 * treat it as kill switch ON (`effectiveMode`).
 */
export interface ModeStore {
  read(): Result<ModeSnapshot>;
  set(change: ModeChange): Result<{ readonly changed: boolean; readonly mode: ModeSnapshot }>;
}

export const DEFAULT_MODE: ModeSnapshot = Object.freeze({ killSwitch: false, shadow: false });

function snapshotOf(rec: AuditModeRecord | undefined): ModeSnapshot {
  if (rec === undefined) return DEFAULT_MODE;
  return {
    killSwitch: rec.killSwitch,
    shadow: rec.shadow,
    changedAt: rec.ts,
    actor: rec.actor,
    recordId: rec.id,
  };
}

/** `ModeStore` over the audit store (same DB, chained `mode` records). */
export function createModeStore(store: Pick<AuditStore, "readMode" | "changeMode">): ModeStore {
  return {
    read: () => {
      let r: Result<AuditModeRecord | undefined>;
      try {
        r = store.readMode();
      } catch (e: unknown) {
        return err("mode.unreadable", `mode read threw ${e instanceof Error ? e.name : typeof e}`);
      }
      return r.ok ? ok(snapshotOf(r.value)) : err("mode.unreadable", r.error.code);
    },
    set: (change) => {
      const input: ChangeModeInput = { actor: change.actor };
      if (change.killSwitch !== undefined) input.killSwitch = change.killSwitch;
      if (change.shadow !== undefined) input.shadow = change.shadow;
      let r: ReturnType<AuditStore["changeMode"]>;
      try {
        r = store.changeMode(input);
      } catch (e: unknown) {
        return err(
          "mode.write_failed",
          `mode change threw ${e instanceof Error ? e.name : typeof e}`,
        );
      }
      if (!r.ok) return err(r.error.code, r.error.message);
      return ok({ changed: r.value.changed, mode: snapshotOf(r.value.record) });
    },
  };
}

/** The mode to enforce: an unreadable mode is kill switch ON (fail closed). */
export function effectiveMode(r: Result<ModeSnapshot>): ModeState & { readonly readable: boolean } {
  return r.ok
    ? { killSwitch: r.value.killSwitch, shadow: r.value.shadow, readable: true }
    : { killSwitch: true, shadow: false, readable: false };
}

/**
 * The T008 `preCheck` seam for T012: kill switch ON or mode unreadable ⇒ deny `kill-switch`; shadow ON ⇒ the call
 * runs in shadow mode; otherwise nothing. Reads the mode on EVERY call (the pipeline calls it at the start of a money
 * call and again right before each send).
 */
export function createModePreCheck(
  modes: Pick<ModeStore, "read">,
  logger?: Logger,
): (ctx: CallContext) => PreCheckVerdict | undefined {
  return () => {
    let r: Result<ModeSnapshot>;
    try {
      r = modes.read();
    } catch (e: unknown) {
      r = err("mode.unreadable", `mode read threw ${e instanceof Error ? e.name : typeof e}`);
    }
    const m = effectiveMode(r);
    if (!m.readable) {
      logger?.(
        `firewall mode unreadable (${r.ok ? "?" : r.error.message}); kill switch treated as ON`,
      );
      return { ruleId: KILL_SWITCH_RULE, message: MODE_UNREADABLE_MESSAGE };
    }
    if (m.killSwitch) return { ruleId: KILL_SWITCH_RULE, message: KILL_SWITCH_MESSAGE };
    if (m.shadow) return { shadow: true };
    return undefined;
  };
}

/**
 * True iff `res` is a decision the POLICY made (and so may be shadowed): any non-deny, `policy-default`, or a deny by
 * one of the policy's own deny rules — with no rule that errored. Engine errors, timeouts, invalid patches, invalid
 * args / amounts and unawaited faults (all reserved ids) are never shadowed: they stay real denies (fail closed).
 */
export function isShadowableDecision(policy: CompiledPolicy, res: EvalResult): boolean {
  if (res.trace.some((t) => t.result === "error")) return false;
  const d = res.decision;
  if (d.type !== "deny") return true;
  if (d.ruleId === RESERVED_RULE_IDS.default) return true;
  return policy.rules.some((r) => r.id === d.ruleId && r.action.kind === "deny");
}

/** One-line operator description (escaped by the caller if needed). */
export function describeMode(m: ModeSnapshot): string {
  const parts = [
    `kill switch ${m.killSwitch ? "ON" : "off"}`,
    `shadow mode ${m.shadow ? "ON" : "off"}`,
  ];
  if (m.killSwitch && m.shadow) parts.push("(kill switch wins: every money call is denied)");
  if (m.changedAt !== undefined && m.actor !== undefined) {
    parts.push(`last changed ${m.changedAt} by ${m.actor}`);
  } else {
    parts.push("never changed (defaults)");
  }
  return parts.join("; ");
}
