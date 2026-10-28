/**
 * Seam between the money pipeline and the approval workflow (T008 → T011).
 *
 * On `require_approval` the pipeline records the attempt (decision `require_approval`, no outcome yet — it stays
 * open and counts toward duplicate / velocity limits, D-023) and calls `ApprovalPort.create`. The approval binds to
 * `argsHash` = SHA-256 of `canonicalJson({ tool, args: finalArgs })`: exactly the post-transform args that would be
 * forwarded. T011 must refuse to execute if the args to forward don't hash to the same value.
 *
 * T011: with `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` the CLI wires `createApprovalService` (`approval-service.ts`):
 * SQLite store, Telegram buttons, `executeApproved` on approval. Without them it wires `createInMemoryApprovalStub()`:
 * it records requests (the last `STUB_MAX_REQUESTS`) and returns an id, but NOTHING is ever executed (the attempts
 * stay open until a restart's reconciliation expires them).
 *
 * DISPLAY RULE (T011 Telegram / dashboard): approvers must only ever be shown `finalArgsRedacted` and
 * `reasonForDisplay` (`formatUntrustedReason` over the PII-scrubbed reason). Never render `finalArgs` or
 * `untrustedReason` directly: they may contain customer PII, and the reason is attacker-controllable text.
 */
import {
  canonicalJson,
  err,
  formatUntrustedReason,
  ok,
  redact,
  redactText,
  type ApprovalChannel,
  type Args,
  type FormattedUntrusted,
  type JsonValue,
  type Result,
} from "@asf/core";
import { redactionSafeUuid } from "./ids.js";
import { nodeHasher } from "./node-hasher.js";

export interface PendingApprovalRequest {
  /** Audit attempt id (decision `require_approval`, still open). */
  readonly attemptId: string;
  /** Exact upstream tool name. */
  readonly tool: string;
  /**
   * Post-transform args that would be forwarded (deep-frozen). Never contains `reason`. For binding / execution
   * only: NEVER display these to an approver (use `finalArgsRedacted`).
   */
  readonly finalArgs: Args;
  /** `finalArgs` through core `redact` (PII / secrets removed): the only form of the args an approver may see. */
  readonly finalArgsRedacted: JsonValue;
  /** `sha256(canonicalJson({ tool, args: finalArgs }))`, lowercase hex. */
  readonly argsHash: string;
  /** Agent-supplied justification, raw. UNTRUSTED: never show it unescaped (use `reasonForDisplay`). */
  readonly untrustedReason: string;
  /**
   * PII-scrubbed (`redactText`), escaped and labelled rendering of the reason for humans (Telegram / dashboard).
   * Consumers must still escape `text` for their markup (HTML / MarkdownV2).
   */
  readonly reasonForDisplay: FormattedUntrusted;
  readonly sessionId: string;
  /** Rule that required approval. */
  readonly ruleId: string;
  /** Policy-authored message (trusted). */
  readonly message: string;
  readonly via: ApprovalChannel;
  /** Integer minutes, 1..1440. */
  readonly timeoutMin: number;
  readonly matchedRules: readonly string[];
}

export interface ApprovalPort {
  /** Persist a pending approval and notify approvers. Never executes anything. */
  create(req: PendingApprovalRequest): Promise<Result<{ approvalId: string }>>;
}

/** Hash an approval binds to. `err` if the args can't be canonicalised. */
export function approvalArgsHash(tool: string, finalArgs: Args): Result<string> {
  const canon = canonicalJson({ tool, args: finalArgs });
  if (!canon.ok) return err("approval.unhashable_args", "approval args are not canonical JSON");
  return ok(nodeHasher.sha256Hex(canon.value));
}

/** PII / secret-redacted copy of the args for an approver (core `redact`). */
export function argsForDisplay(finalArgs: Args): JsonValue {
  return redact(finalArgs);
}

/** Escaped, labelled, PII-scrubbed reason for an approver. */
export function reasonForDisplay(untrustedReason: string): FormattedUntrusted {
  return formatUntrustedReason(redactText(untrustedReason));
}

/** The in-memory stub keeps at most this many (most recent) requests, so a long-running proxy can't grow without bound. */
export const STUB_MAX_REQUESTS = 100;

export interface InMemoryApprovalStub extends ApprovalPort {
  /** The last `STUB_MAX_REQUESTS` requests received, oldest first (test / debug only). */
  readonly requests: readonly PendingApprovalRequest[];
}

/** Fallback without Telegram config: returns `apr_<uuid>`, keeps recent requests in memory, never executes anything. */
export function createInMemoryApprovalStub(): InMemoryApprovalStub {
  const requests: PendingApprovalRequest[] = [];
  return {
    requests,
    create(req: PendingApprovalRequest): Promise<Result<{ approvalId: string }>> {
      requests.push(req);
      if (requests.length > STUB_MAX_REQUESTS)
        requests.splice(0, requests.length - STUB_MAX_REQUESTS);
      return Promise.resolve(ok({ approvalId: redactionSafeUuid("apr_") }));
    },
  };
}
