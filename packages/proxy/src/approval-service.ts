/**
 * The approval workflow (T011): implements `ApprovalPort` over the `@asf/approvals` SQLite store and a notifier
 * (the Telegram approver), executes approved actions through `MoneyPipeline.executeApproved`, and serves the agent's
 * `firewall_check_approval` tool.
 *
 * Flow:
 * 1. `create` (pipeline, on `require_approval`): a pending row (`apr_<uuid>`, callback nonce, deadline = now +
 *    `timeoutMin`), the request's `finalArgs` kept IN MEMORY only (never persisted: they may hold PII; a restart
 *    therefore expires every pending approval — `expireStale` + startup reconciliation), then the notification
 *    (redacted args + `formatUntrustedReason` output only). Any failure ⇒ `err` (the pipeline records
 *    `not_forwarded` + `approval.unavailable`) and the row is force-expired so it can never be approved later.
 * 2. `decide` (Telegram button, already authenticated by the approver): ONE atomic store transition. A loser (double
 *    approve, approve-after-reject, replay) changes nothing. A pending row past its deadline is expired instead
 *    (treated as rejected). Rejected / expired ⇒ `pipeline.resolveApproval` (chained `approval` record + terminal
 *    `not_forwarded` outcome). Approved ⇒ `pipeline.executeApproved` in the background (chained `approval` record
 *    first, then locks, re-evaluation, forward, T010 verification); its status is stored and shown on the message.
 * 3. `sweepExpired` (timer) and `firewall_check_approval` (agent poll) expire overdue approvals the same way.
 *
 * Fail closed: an unattached service (no pipeline yet), a store error or a clock error never executes anything.
 */
import { err, ok, type Clock, type JsonValue, type Result } from "@asf/core";
import {
  newNonce,
  type ApprovalNotice,
  type ApprovalRow,
  type ApprovalStore,
  type DecisionReply,
  type DecisionRequest,
} from "@asf/approvals";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { ApprovalPort, PendingApprovalRequest } from "./approval-port.js";
import { escapeForTerminal } from "./cli/audit-verify.js";
import { redactionSafeUuid } from "./ids.js";
import type { ExecuteApprovedResult, MoneyPipeline } from "./interceptor.js";
import { isSafeUpstreamRef } from "./result-redaction.js";
import type { LocalTool, OpenDirectCall } from "./server.js";
import type { Logger } from "./upstream.js";

export const CHECK_APPROVAL_TOOL = "firewall_check_approval";
export const APPROVAL_ID_PATTERN =
  /^apr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MS_PER_MIN = 60_000;

/** What the service needs from a notifier (satisfied by `@asf/approvals` `TelegramApprover`). */
export interface ApprovalNotifier {
  notify(notice: ApprovalNotice, nonce: string): Promise<Result<{ messageId: number }>>;
  showResolution(row: ApprovalRow): Promise<Result<null>>;
}

export interface ApprovalServiceOptions {
  readonly store: ApprovalStore;
  readonly notifier: ApprovalNotifier;
  readonly clock: Clock;
  readonly logger?: Logger;
  /** Default: `redactionSafeUuid("apr_")`. */
  readonly idGen?: () => string;
  /** Default: `newNonce` (16 random bytes). */
  readonly nonceGen?: () => string;
}

export interface ApprovalServiceDeps {
  readonly pipeline: Pick<MoneyPipeline, "executeApproved" | "resolveApproval">;
  readonly openCall: OpenDirectCall;
}

export interface ApprovalService extends ApprovalPort {
  /** Wire the pipeline and the server's direct-call opener (they are built after the service). Once. */
  attach(deps: ApprovalServiceDeps): void;
  /** `onDecision` handler for the Telegram approver. */
  decide(d: DecisionRequest): Promise<DecisionReply>;
  /** Expire every overdue pending approval (audit outcome `approval.expired`); returns how many. */
  sweepExpired(): Promise<number>;
  /**
   * Startup: force-expire store rows left pending by an earlier run (their args are gone) and flag approved rows whose
   * execution never finished as `unknown` (`approval.interrupted`). The audit side is closed / verified by startup
   * reconciliation (`approvalIdOf` supplies the ids). Returns how many were expired.
   */
  expireStale(): Result<number>;
  /** Approval id of an attempt, if the store knows it. */
  approvalIdOf(attemptId: string): string | undefined;
  /** The agent's polling tool. */
  readonly checkTool: LocalTool;
  /** Resolves when no approved action is executing (tests / shutdown). */
  idle(): Promise<void>;
}

interface PendingArgs {
  readonly req: PendingApprovalRequest;
}

export const DECISION_ANSWERS = {
  approved: "Approved. The firewall is executing the action.",
  rejected: "Rejected. Nothing was executed.",
  expired: "This approval has expired (treated as rejected). Nothing was executed.",
  alreadyDecided: "This approval was already decided. Nothing changed.",
  unavailable: "The firewall could not process this decision; nothing was executed.",
} as const;

export const CHECK_MESSAGES = {
  pending:
    "waiting for a human decision; the action has NOT been executed. Poll again later; do not retry the action",
  executing: "approved; the firewall is executing it now. Poll again shortly",
  executed: "approved and executed",
  failed:
    "approved, but Razorpay rejected the action; it was not executed. Explain this to the user",
  unknown:
    "approved, but the outcome is unknown and was flagged for a human. Do NOT retry; a human will check with Razorpay",
  notExecuted:
    "approved, but the firewall did not execute it (see ruleId). Explain this to the user rather than retrying",
  rejected: "a human rejected this action; it was not executed. Do not retry it",
  expired: "nobody approved this action in time (treated as rejected); it was not executed",
  notFound: "no such approval for this session",
} as const;

const checkArgsSchema = z.strictObject({ approvalId: z.string().regex(APPROVAL_ID_PATTERN) });

function json(isError: boolean, body: Record<string, JsonValue>): CallToolResult {
  return { isError, content: [{ type: "text", text: JSON.stringify(body) }] };
}

export function createApprovalService(o: ApprovalServiceOptions): ApprovalService {
  const log: Logger = o.logger ?? (() => undefined);
  const idGen = o.idGen ?? (() => redactionSafeUuid("apr_"));
  const nonceGen = o.nonceGen ?? newNonce;
  const pending = new Map<string, PendingArgs>();
  const inflight = new Set<Promise<void>>();
  let deps: ApprovalServiceDeps | undefined;

  const nowMs = (): number | undefined => {
    try {
      const n = o.clock.nowMs();
      return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
    } catch (e: unknown) {
      log(`approval clock threw ${e instanceof Error ? e.name : typeof e}`);
      return undefined;
    }
  };

  const show = async (row: ApprovalRow): Promise<void> => {
    const r = await o.notifier.showResolution(row);
    if (!r.ok)
      log(`approval ${row.approvalId}: updating the notification failed (${r.error.code})`);
  };

  // Callers may not await the returned promise, so a rejection is logged here instead of crashing the process.
  const track = (p: Promise<void>): Promise<void> => {
    const caught = p.catch((e: unknown) => {
      log(`approval task threw ${e instanceof Error ? e.name : typeof e}`);
    });
    inflight.add(caught);
    void caught.finally(() => inflight.delete(caught));
    return caught;
  };

  /** Close a row that this call moved to `expired` / `rejected` on the audit side, then update the message. */
  const closeOnAudit = async (
    row: ApprovalRow,
    decision: "rejected" | "expired",
    approver?: string,
  ): Promise<void> => {
    pending.delete(row.approvalId);
    if (deps === undefined) {
      log(
        `approval ${row.approvalId} ${decision} before the pipeline was attached; audit left open`,
      );
    } else {
      const r = deps.pipeline.resolveApproval({
        approvalId: row.approvalId,
        attemptId: row.attemptId,
        decision,
        ...(approver === undefined ? {} : { approver }),
      });
      if (!r.ok) log(`approval ${row.approvalId}: audit close failed (${r.error.code})`);
    }
    await show(row);
  };

  const expireRow = async (row: ApprovalRow, now: number): Promise<boolean> => {
    const t = o.store.expire(row.approvalId, now);
    if (!t.ok) {
      log(`approval ${row.approvalId}: expiry failed (${t.error.code})`);
      return false;
    }
    if (!t.value.won) return false;
    log(`approval ${row.approvalId} expired (treated as rejected)`);
    await closeOnAudit(t.value.row, "expired");
    return true;
  };

  const execute = async (row: ApprovalRow, p: PendingArgs, approver: string): Promise<void> => {
    if (deps === undefined) return; // checked by the caller
    const setExec = (
      status: ExecuteApprovedResult["status"] | "executing",
      extra: { upstreamRef?: string; code?: string } = {},
    ): void => {
      const r = o.store.setExecution(row.approvalId, { status, ...extra });
      if (!r.ok)
        log(`approval ${row.approvalId}: recording execution status failed (${r.error.code})`);
    };
    setExec("executing");
    let res: ExecuteApprovedResult;
    try {
      res = await deps.pipeline.executeApproved(
        {
          approvalId: row.approvalId,
          attemptId: row.attemptId,
          argsHash: row.argsHash,
          tool: p.req.tool,
          finalArgs: p.req.finalArgs,
          untrustedReason: p.req.untrustedReason,
          sessionId: p.req.sessionId,
          ruleId: p.req.ruleId,
          approver,
        },
        deps.openCall,
      );
    } catch (e: unknown) {
      // executeApproved never throws; if it did, the action may have been sent: unknown, never "not executed".
      log(`approval ${row.approvalId}: execution threw ${e instanceof Error ? e.name : typeof e}`);
      setExec("unknown", { code: "firewall.internal_error" });
      return;
    } finally {
      pending.delete(row.approvalId);
    }
    setExec(res.status, {
      ...(res.upstreamRef === undefined ? {} : { upstreamRef: res.upstreamRef }),
      ...(res.code === undefined ? {} : { code: res.code }),
    });
    log(
      `approval ${row.approvalId}: ${res.status}${res.code === undefined ? "" : ` (${escapeForTerminal(res.code)})`}`,
    );
    const after = o.store.get(row.approvalId);
    if (after.ok && after.value !== undefined) await show(after.value);
  };

  const decideNow = (d: DecisionRequest): DecisionReply => {
    const now = nowMs();
    if (deps === undefined || now === undefined) return { answer: DECISION_ANSWERS.unavailable };
    const t = o.store.decide(d.approvalId, d.decision, d.approver, now);
    if (!t.ok) {
      log(`approval ${d.approvalId}: decision failed (${t.error.code})`);
      return { answer: DECISION_ANSWERS.unavailable };
    }
    const row = t.value.row;
    if (!t.value.won) {
      if (row.state === "pending") {
        // Past its deadline: an expired approval is treated as rejected.
        const completion = track(expireRow(row, now).then(() => undefined));
        return { answer: DECISION_ANSWERS.expired, completion };
      }
      return { answer: DECISION_ANSWERS.alreadyDecided };
    }
    if (d.decision === "rejected") {
      log(`approval ${row.approvalId} rejected by ${d.approver}`);
      return {
        answer: DECISION_ANSWERS.rejected,
        completion: track(closeOnAudit(row, "rejected", d.approver)),
      };
    }
    log(`approval ${row.approvalId} approved by ${d.approver}`);
    const p = pending.get(row.approvalId);
    if (p === undefined || p.req.attemptId !== row.attemptId) {
      // Args are gone (should not happen within one run): never execute; the attempt keeps counting until
      // startup reconciliation closes it.
      const r = o.store.setExecution(row.approvalId, {
        status: "not_executed",
        code: "approval.args_unavailable",
      });
      if (!r.ok) log(`approval ${row.approvalId}: recording execution status failed`);
      log(
        `approval ${row.approvalId}: approved but its arguments are no longer available; not executed`,
      );
      return { answer: DECISION_ANSWERS.unavailable };
    }
    return { answer: DECISION_ANSWERS.approved, completion: track(execute(row, p, d.approver)) };
  };

  const service: ApprovalService = {
    async create(req) {
      const now = nowMs();
      if (now === undefined) return err("approval.clock_failed", "the clock is unavailable");
      if (!Number.isSafeInteger(req.timeoutMin) || req.timeoutMin < 1 || req.timeoutMin > 1440) {
        return err("approval.invalid_timeout", "approval timeout must be 1..1440 minutes");
      }
      const approvalId = idGen();
      const nonce = nonceGen();
      const expiresAtMs = now + req.timeoutMin * MS_PER_MIN;
      const created = o.store.create({
        approvalId,
        attemptId: req.attemptId,
        sessionId: req.sessionId,
        tool: req.tool,
        argsHash: req.argsHash,
        ruleId: req.ruleId,
        callbackNonce: nonce,
        createdAtMs: now,
        expiresAtMs,
      });
      if (!created.ok) return created;
      pending.set(approvalId, { req });
      const sent = await o.notifier.notify(
        {
          approvalId,
          tool: req.tool,
          argsRedacted: req.finalArgsRedacted,
          reason: req.reasonForDisplay,
          ruleId: req.ruleId,
          policyMessage: req.message,
          expiresAtMs,
        },
        nonce,
      );
      if (!sent.ok) {
        // The message may have been delivered (and even approved) before the error surfaced: report a failure only
        // if THIS call retired the approval; if a human already decided it, the decision stands.
        const ex = o.store.expire(approvalId, now, true);
        if (ex.ok && !ex.value.won && ex.value.row.state !== "pending") {
          log(
            `approval ${approvalId}: notification reported ${sent.error.code} but it was already ${ex.value.row.state}`,
          );
          return ok({ approvalId });
        }
        pending.delete(approvalId);
        if (!ex.ok || !ex.value.won) {
          log(`approval ${approvalId}: could not retire it after a failed notification`);
        }
        log(`approval ${approvalId}: notification failed (${sent.error.code}); not pending`);
        return err("approval.notify_failed", "the approval request could not be delivered");
      }
      return ok({ approvalId });
    },

    attach(d) {
      if (deps !== undefined) throw new Error("approval service already attached");
      deps = d;
    },

    decide: (d) => Promise.resolve(decideNow(d)),

    async sweepExpired() {
      const now = nowMs();
      if (now === undefined) return 0;
      const due = o.store.listDue(now);
      if (!due.ok) {
        log(`approval sweep failed (${due.error.code})`);
        return 0;
      }
      let n = 0;
      for (const row of due.value) if (await expireRow(row, now)) n++;
      return n;
    },

    expireStale() {
      const now = nowMs();
      if (now === undefined) return err("approval.clock_failed", "the clock is unavailable");
      const rows = o.store.listPending();
      if (!rows.ok) return rows;
      let n = 0;
      for (const row of rows.value) {
        if (pending.has(row.approvalId)) continue;
        const t = o.store.expire(row.approvalId, now, true);
        if (!t.ok) return t;
        if (t.value.won) n++;
      }
      if (n > 0)
        log(`startup: ${String(n)} approval(s) from an earlier run expired (not executed)`);
      // Approved before the restart but never finished: may or may not have run (the audit side is verified by
      // startup reconciliation); never re-executed.
      const unfinished = o.store.listUnfinished();
      if (!unfinished.ok) return unfinished;
      for (const row of unfinished.value) {
        if (pending.has(row.approvalId)) continue;
        const r = o.store.setExecution(row.approvalId, {
          status: "unknown",
          code: "approval.interrupted",
        });
        if (!r.ok) return r;
        log(
          `startup: approved action ${row.approvalId} was interrupted by the restart; flagged unknown`,
        );
      }
      return ok(n);
    },

    approvalIdOf(attemptId) {
      const r = o.store.getByAttempt(attemptId);
      return r.ok ? r.value?.approvalId : undefined;
    },

    idle: async () => {
      while (inflight.size > 0) await Promise.all([...inflight]);
    },

    checkTool: {
      tool: {
        name: CHECK_APPROVAL_TOOL,
        description:
          "Check the status of a money action that is awaiting human approval (the approvalId from a pending_approval result). Returns pending, approved (with the execution result), rejected or expired. Never executes or retries anything itself.",
        inputSchema: {
          type: "object",
          properties: {
            approvalId: {
              type: "string",
              pattern: APPROVAL_ID_PATTERN.source,
              description: "The approvalId returned with decision pending_approval",
            },
          },
          required: ["approvalId"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
      async call(args, ctx) {
        const parsed = checkArgsSchema.safeParse(args);
        if (!parsed.success) {
          return json(true, {
            decision: "deny",
            ruleId: "firewall.invalid_args",
            message: "approvalId must be the apr_<uuid> id from a pending_approval result",
          });
        }
        const approvalId = parsed.data.approvalId;
        const notFound = json(true, {
          decision: "deny",
          ruleId: "approval.not_found",
          message: CHECK_MESSAGES.notFound,
        });
        let row = o.store.get(approvalId);
        if (!row.ok) {
          return json(true, {
            decision: "deny",
            ruleId: "approval.unavailable",
            message: "the approval store is unavailable",
          });
        }
        if (row.value === undefined || row.value.sessionId !== ctx.sessionId) return notFound;
        const now = nowMs();
        if (row.value.state === "pending" && now !== undefined && row.value.expiresAtMs <= now) {
          await expireRow(row.value, now);
          row = o.store.get(approvalId);
          if (!row.ok || row.value === undefined) return notFound;
        }
        return checkResult(row.value);
      },
    },
  };
  return service;
}

/** Agent-facing `firewall_check_approval` result for a row (only validated ids, fixed messages). */
export function checkResult(row: ApprovalRow): CallToolResult {
  const base = { approvalId: row.approvalId, status: row.state };
  switch (row.state) {
    case "pending":
      return json(false, { ...base, message: CHECK_MESSAGES.pending });
    case "rejected":
      return json(true, {
        decision: "deny",
        ruleId: "approval.rejected",
        ...base,
        message: CHECK_MESSAGES.rejected,
      });
    case "expired":
      return json(true, {
        decision: "deny",
        ruleId: "approval.expired",
        ...base,
        message: CHECK_MESSAGES.expired,
      });
    case "approved":
      break;
  }
  const ex = row.execution;
  const execution: Record<string, JsonValue> = {
    status: ex?.status ?? "executing",
    attemptId: row.attemptId,
    ...(isSafeUpstreamRef(ex?.upstreamRef) ? { upstreamRef: ex.upstreamRef } : {}),
  };
  switch (ex?.status) {
    case undefined:
    case "executing":
      return json(false, { ...base, execution, message: CHECK_MESSAGES.executing });
    case "executed":
      return json(false, { ...base, execution, message: CHECK_MESSAGES.executed });
    case "failed":
      return json(true, {
        error: "upstream_error",
        ...base,
        execution,
        message: CHECK_MESSAGES.failed,
      });
    case "unknown":
      return json(true, {
        outcome: "unknown",
        flaggedForHuman: true,
        ...base,
        execution,
        message: CHECK_MESSAGES.unknown,
      });
    case "not_executed":
      return json(true, {
        decision: "deny",
        ruleId: ex.code ?? "approval.not_executed",
        ...base,
        execution,
        message: CHECK_MESSAGES.notExecuted,
      });
  }
}
