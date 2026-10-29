/**
 * JSON views of audit records for the dashboard (T013).
 *
 * - Args: only the audit log's `argsRedacted` / `originalArgsRedacted` (the agent's raw / final args are never stored,
 *   D-002), passed through core `redact()` once more as defence in depth.
 * - Agent-controlled text is marked: the reason is `{ untrusted: true, label, text }` built by `formatUntrustedReason`
 *   (escaped, single line, truncated), and every attempt lists `untrustedFields`. The dashboard must still escape all
 *   strings for HTML (React does).
 * - `amountPaise` is surfaced only when the redacted args carry an integer `amount` (paise; never a float).
 */
import {
  formatUntrustedReason,
  redact,
  UNTRUSTED_REASON_LABEL,
  type AuditRecord,
  type JsonValue,
} from "@asf/core";
import type { ApprovalSummary, AuditRow } from "./ports.js";

export interface UntrustedText {
  readonly untrusted: true;
  readonly label: typeof UNTRUSTED_REASON_LABEL;
  readonly text: string;
}

export type RecordView = { readonly [key: string]: JsonValue | UntrustedText | undefined };

export const ATTEMPT_UNTRUSTED_FIELDS = ["reason", "argsRedacted", "originalArgsRedacted"] as const;

export function untrustedReason(reason: string): UntrustedText {
  const f = formatUntrustedReason(reason);
  return { untrusted: true, label: f.label, text: f.text };
}

/** Integer paise from `{ amount }`, or `undefined`. */
export function amountPaiseOf(args: JsonValue): number | undefined {
  if (typeof args !== "object" || args === null || Array.isArray(args)) return undefined;
  const a = args["amount"];
  return typeof a === "number" && Number.isSafeInteger(a) && a >= 0 ? a : undefined;
}

function common(r: AuditRecord): { seq: number; id: string; ts: string; hash: string } {
  return { seq: r.seq, id: r.id, ts: r.ts, hash: r.hash };
}

export function recordView(row: AuditRow): RecordView {
  if ("invalid" in row) return { kind: "invalid", seq: row.seq };
  switch (row.kind) {
    case "attempt": {
      const args = redact(row.argsRedacted);
      const amountPaise = amountPaiseOf(args);
      return {
        kind: "attempt",
        ...common(row),
        sessionId: row.sessionId,
        tool: row.tool,
        decision: row.decision,
        matchedRules: [...row.matchedRules],
        argsRedacted: args,
        ...(row.originalArgsRedacted === undefined
          ? {}
          : { originalArgsRedacted: redact(row.originalArgsRedacted) }),
        ...(amountPaise === undefined ? {} : { amountPaise }),
        reason: untrustedReason(row.reason),
        ...(row.approver === undefined ? {} : { approver: row.approver }),
        ...(row.retryOf === undefined ? {} : { retryOf: row.retryOf }),
        ...(row.shadow === undefined ? {} : { shadow: true }),
        ...(row.wouldDecision === undefined ? {} : { wouldDecision: row.wouldDecision }),
        untrustedFields: [...ATTEMPT_UNTRUSTED_FIELDS],
      };
    }
    case "outcome":
      return {
        kind: "outcome",
        ...common(row),
        attemptId: row.attemptId,
        outcome: row.outcome,
        latencyMs: row.latencyMs,
        ...(row.errorCode === undefined ? {} : { errorCode: row.errorCode }),
        ...(row.upstreamRef === undefined ? {} : { upstreamRef: row.upstreamRef }),
      };
    case "verification":
      return {
        kind: "verification",
        ...common(row),
        attemptId: row.attemptId,
        trigger: row.trigger,
        result: row.result,
        method: row.method,
        needsHuman: row.needsHuman,
        ...(row.upstreamRef === undefined ? {} : { upstreamRef: row.upstreamRef }),
        ...(row.errorCode === undefined ? {} : { errorCode: row.errorCode }),
        ...(row.resolver === undefined ? {} : { resolver: row.resolver }),
      };
    case "approval":
      return {
        kind: "approval",
        ...common(row),
        attemptId: row.attemptId,
        approvalId: row.approvalId,
        decision: row.decision,
        ...(row.approver === undefined ? {} : { approver: row.approver }),
      };
    case "mode":
      return {
        kind: "mode",
        ...common(row),
        killSwitch: row.killSwitch,
        shadow: row.shadow,
        actor: row.actor,
      };
  }
}

/** A pending approval joined with its (redacted) attempt, if the audit log has it. */
export function approvalView(a: ApprovalSummary, attempt: AuditRecord | undefined): RecordView {
  const base: RecordView = {
    approvalId: a.approvalId,
    attemptId: a.attemptId,
    sessionId: a.sessionId,
    tool: a.tool,
    ruleId: a.ruleId,
    state: a.state,
    createdAt: new Date(a.createdAtMs).toISOString(),
    expiresAt: new Date(a.expiresAtMs).toISOString(),
  };
  if (attempt?.kind !== "attempt") return base;
  const args = redact(attempt.argsRedacted);
  const amountPaise = amountPaiseOf(args);
  return {
    ...base,
    argsRedacted: args,
    ...(amountPaise === undefined ? {} : { amountPaise }),
    reason: untrustedReason(attempt.reason),
    untrustedFields: ["reason", "argsRedacted"],
  };
}
