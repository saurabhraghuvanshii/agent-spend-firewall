/**
 * T013 (D-036): adapters from the proxy's own stores / services to the `@asf/api` ports. The API runs IN the proxy
 * process, so a dashboard approve / reject reaches the in-memory pending args (D-034) and goes through the very same
 * `ApprovalService.decide()` as a Telegram button: single-use store transition, then `executeApproved` (approval
 * record first, locks, re-evaluation, args hash, kill-switch pre-check, T010 verification).
 */
import { err, ok, type Result } from "@asf/core";
import type {
  ApprovalSummary,
  ApprovalsPort,
  AuditPort,
  DecisionStatus,
  ModesPort,
} from "@asf/api";
import type { ApprovalNotifier, ApprovalService } from "./approval-service.js";
import { DECISION_ANSWERS } from "./approval-service.js";
import type { ApprovalStore } from "@asf/approvals";
import type { AuditStore } from "./audit-store.js";
import type { ModeStore } from "./modes.js";
import type { Logger } from "./upstream.js";

export interface ApiPorts {
  readonly audit: AuditPort;
  readonly modes: ModesPort;
  readonly approvals?: ApprovalsPort;
}

const guard = <T>(what: string, f: () => Result<T>): Result<T> => {
  try {
    return f();
  } catch (e: unknown) {
    return err("api.port_threw", `${what} threw ${e instanceof Error ? e.name : typeof e}`);
  }
};

export function auditPortOf(
  store: Pick<AuditStore, "readPage" | "readSession" | "readAttempt" | "verify">,
): AuditPort {
  return {
    readPage: (q) => guard("readPage", () => store.readPage(q)),
    readSession: (id, limit) => guard("readSession", () => store.readSession(id, limit)),
    readAttempt: (id) =>
      guard("readAttempt", () => {
        const r = store.readAttempt(id);
        return r.ok ? ok(r.value?.attempt) : r;
      }),
    verify: () => guard("verify", () => store.verify()),
  };
}

/** Map the service's fixed answer strings to API statuses (anything unexpected ⇒ `unavailable`). */
export function decisionStatusOf(
  answer: string,
  decision: "approved" | "rejected",
): DecisionStatus {
  switch (answer) {
    case DECISION_ANSWERS.approved:
      return decision === "approved" ? "approved" : "unavailable";
    case DECISION_ANSWERS.rejected:
      return decision === "rejected" ? "rejected" : "unavailable";
    case DECISION_ANSWERS.expired:
      return "expired";
    case DECISION_ANSWERS.alreadyDecided:
      return "already_decided";
    default:
      return "unavailable";
  }
}

export function approvalsPortOf(
  service: Pick<ApprovalService, "decide">,
  store: Pick<ApprovalStore, "get" | "listPending">,
  logger?: Logger,
): ApprovalsPort {
  const log = logger ?? (() => undefined);
  return {
    listPending: (limit) =>
      guard("listPending", () => {
        const r = store.listPending(limit);
        if (!r.ok) return r;
        // Never the callback nonce, message id or execution internals.
        return ok(
          r.value.map((row): ApprovalSummary => ({
            approvalId: row.approvalId,
            attemptId: row.attemptId,
            sessionId: row.sessionId,
            tool: row.tool,
            ruleId: row.ruleId,
            state: row.state,
            createdAtMs: row.createdAtMs,
            expiresAtMs: row.expiresAtMs,
          })),
        );
      }),
    decide: async (d) => {
      const row = guard("get", () => store.get(d.approvalId));
      if (!row.ok) {
        log(`api: approval lookup failed (${row.error.code})`);
        return "unavailable";
      }
      if (row.value === undefined) return "not_found";
      try {
        const reply = await service.decide(d);
        return decisionStatusOf(reply.answer, d.decision);
      } catch (e: unknown) {
        log(`api: approval decision threw ${e instanceof Error ? e.name : typeof e}`);
        return "unavailable";
      }
    },
  };
}

export function createApiPorts(o: {
  readonly audit: AuditStore;
  readonly modes: ModeStore;
  readonly approvals?: { readonly service: ApprovalService; readonly store: ApprovalStore };
  readonly logger?: Logger;
}): ApiPorts {
  return {
    audit: auditPortOf(o.audit),
    modes: o.modes,
    ...(o.approvals === undefined
      ? {}
      : { approvals: approvalsPortOf(o.approvals.service, o.approvals.store, o.logger) }),
  };
}

/**
 * Notifier for dashboard-only approvals (API enabled with a valid admin token, Telegram not configured): nothing is
 * sent anywhere; the request shows up in `GET /approvals` and can be decided only through the authenticated API.
 */
export const dashboardOnlyNotifier: ApprovalNotifier = {
  notify: () => Promise.resolve(ok({ messageId: 0 })),
  showResolution: () => Promise.resolve(ok(null)),
};
