/**
 * Telegram approver (T011): posts approval requests with Approve / Reject buttons and turns button presses into
 * decisions. The Bot API is behind `TelegramTransport` (grammy in production, `grammy-transport.ts`; a fake in
 * tests), so nothing here touches the network.
 *
 * A button press is acted on only if ALL hold (else it is answered with a generic refusal and logged, no decision):
 * 1. its callback data verifies (`CallbackSigner`: well-formed, HMAC valid — forged / tampered / old-run data fails);
 * 2. it comes from the configured `TELEGRAM_CHAT_ID`: the message's chat id equals it, and for a private chat
 *    (positive id) the presser's user id equals it too; in a group chat (negative id) any member may act and is
 *    recorded as `telegram:<user id>`;
 * 3. the nonce names a known approval and the press is on THAT approval's message.
 * The decision itself (single-use, expiry) is the `onDecision` handler's job (the store's atomic transition).
 *
 * Logs never include callback data, message text or user names — only ids and fixed reasons.
 */
import { err, ok, type Result } from "@asf/core";
import {
  createCallbackSigner,
  type CallbackAction,
  type CallbackSigner,
} from "./callback-token.js";
import { renderApprovalMessage, renderResolution, type ApprovalNotice } from "./render.js";
import type { ApprovalRow, ApprovalStore } from "./store.js";

export interface InlineButton {
  readonly text: string;
  readonly data: string;
}

/** A callback query, reduced to what the approver checks. */
export interface IncomingCallback {
  readonly id: string;
  readonly data: string | undefined;
  /** Telegram user id of whoever pressed the button. */
  readonly fromId: number;
  /** Chat of the message the button belongs to (absent for inline-mode messages). */
  readonly chatId: number | undefined;
  readonly messageId: number | undefined;
}

export interface TelegramTransport {
  /** Send an HTML message with one row of inline buttons. */
  sendMessage(
    chatId: string,
    html: string,
    buttons: readonly InlineButton[],
  ): Promise<Result<{ messageId: number }>>;
  /** Replace a message's text and remove its buttons. */
  editMessage(chatId: string, messageId: number, html: string): Promise<Result<null>>;
  answerCallback(callbackId: string, text: string): Promise<Result<null>>;
  /** Register THE callback handler (one). */
  onCallback(handler: (cb: IncomingCallback) => Promise<void>): void;
  start(): Result<null>;
  stop(): Promise<void>;
}

export interface DecisionRequest {
  readonly approvalId: string;
  readonly decision: "approved" | "rejected";
  /** `telegram:<user id>`. */
  readonly approver: string;
}

export interface DecisionReply {
  /** Short text for the callback answer (shown to the approver). Fixed strings only. */
  readonly answer: string;
  /**
   * Resolves when follow-up work (executing the action, editing the message) is done. Never rejects. The approver does
   * NOT await it (the handler owns tracking it, e.g. `ApprovalService.idle()`).
   */
  readonly completion?: Promise<void>;
}

export interface TelegramApproverOptions {
  readonly transport: TelegramTransport;
  /** `TELEGRAM_CHAT_ID`: a numeric chat id (`-` for groups). */
  readonly chatId: string;
  readonly store: Pick<ApprovalStore, "getByNonce" | "setMessageId">;
  readonly onDecision: (d: DecisionRequest) => Promise<DecisionReply>;
  readonly signer?: CallbackSigner;
  readonly logger?: (line: string) => void;
}

export interface TelegramApprover {
  /** Post the approval request for `notice` with signed buttons for `nonce`; stores the message id. */
  notify(notice: ApprovalNotice, nonce: string): Promise<Result<{ messageId: number }>>;
  /** Show the final state of a decided / expired approval on its message (buttons removed). Best effort. */
  showResolution(row: ApprovalRow): Promise<Result<null>>;
  /** The handler registered on the transport (exposed for tests). */
  handleCallback(cb: IncomingCallback): Promise<void>;
  start(): Result<null>;
  stop(): Promise<void>;
}

export const CHAT_ID_RE = /^-?[0-9]{1,20}$/;

export const ANSWERS = {
  invalid: "This button is invalid or has expired.",
  unauthorised: "You are not allowed to decide this approval.",
  unknown: "This approval is unknown or no longer pending.",
  unavailable: "The firewall could not process this decision; nothing was executed.",
} as const;

/** @throws RangeError for a malformed `chatId` (configuration error). */
export function createTelegramApprover(o: TelegramApproverOptions): TelegramApprover {
  if (!CHAT_ID_RE.test(o.chatId))
    throw new RangeError("TELEGRAM_CHAT_ID must be a numeric chat id");
  const log = o.logger ?? (() => undefined);
  const signer = o.signer ?? createCallbackSigner();
  const privateChat = !o.chatId.startsWith("-");

  const answer = async (cb: IncomingCallback, text: string): Promise<void> => {
    const r = await o.transport.answerCallback(cb.id, text);
    if (!r.ok) log(`telegram: answering a callback failed (${r.error.code})`);
  };

  const handleCallback = async (cb: IncomingCallback): Promise<void> => {
    const parsed = cb.data === undefined ? undefined : signer.verify(cb.data);
    if (parsed === undefined) {
      log("telegram: refused a callback with invalid or forged data");
      return answer(cb, ANSWERS.invalid);
    }
    const fromOk = Number.isSafeInteger(cb.fromId) && cb.fromId > 0;
    if (
      cb.chatId === undefined ||
      String(cb.chatId) !== o.chatId ||
      !fromOk ||
      (privateChat && String(cb.fromId) !== o.chatId)
    ) {
      log(
        `telegram: refused a callback from an unauthorised chat/user (chat ${cb.chatId === undefined ? "none" : String(cb.chatId)}, user ${fromOk ? String(cb.fromId) : "invalid"})`,
      );
      return answer(cb, ANSWERS.unauthorised);
    }
    const row = o.store.getByNonce(parsed.nonce);
    if (!row.ok) {
      log(`telegram: approval lookup failed (${row.error.code})`);
      return answer(cb, ANSWERS.unavailable);
    }
    if (row.value === undefined) return answer(cb, ANSWERS.unknown);
    if (row.value.messageId !== undefined && cb.messageId !== row.value.messageId) {
      log(`telegram: refused a callback for approval ${row.value.approvalId} from another message`);
      return answer(cb, ANSWERS.unauthorised);
    }
    const decision: DecisionRequest = {
      approvalId: row.value.approvalId,
      decision: actionToDecision(parsed.action),
      approver: `telegram:${String(cb.fromId)}`,
    };
    let reply: DecisionReply;
    try {
      reply = await o.onDecision(decision);
    } catch (e: unknown) {
      log(`telegram: decision handler threw ${e instanceof Error ? e.name : typeof e}`);
      return answer(cb, ANSWERS.unavailable);
    }
    // Answer at once; follow-up work (execution) is tracked by the decision handler, not awaited here, so one slow
    // execution never holds up other updates.
    await answer(cb, reply.answer);
  };

  o.transport.onCallback(handleCallback);

  return {
    async notify(notice, nonce) {
      let html: string;
      let buttons: InlineButton[];
      try {
        html = renderApprovalMessage(notice);
        buttons = [
          { text: "Approve", data: signer.sign("approve", nonce) },
          { text: "Reject", data: signer.sign("reject", nonce) },
        ];
      } catch (e: unknown) {
        return err(
          "approval.render_failed",
          `rendering failed (${e instanceof Error ? e.name : typeof e})`,
        );
      }
      const sent = await o.transport.sendMessage(o.chatId, html, buttons);
      if (!sent.ok) return sent;
      const stored = o.store.setMessageId(notice.approvalId, sent.value.messageId);
      if (!stored.ok) return stored;
      return ok({ messageId: sent.value.messageId });
    },
    async showResolution(row) {
      if (row.messageId === undefined) return ok(null);
      return o.transport.editMessage(o.chatId, row.messageId, renderResolution(row));
    },
    handleCallback,
    start: () => o.transport.start(),
    stop: () => o.transport.stop(),
  };
}

function actionToDecision(a: CallbackAction): "approved" | "rejected" {
  return a === "approve" ? "approved" : "rejected";
}
