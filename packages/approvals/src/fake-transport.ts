/**
 * In-memory `TelegramTransport` for tests (this package's and the proxy's). Records every request; never touches
 * the network. `press()` simulates a button press by delivering a callback query to the registered handler.
 */
import { err, ok, type Result } from "@asf/core";
import type { IncomingCallback, InlineButton, TelegramTransport } from "./telegram.js";

export interface FakeSentMessage {
  readonly chatId: string;
  readonly messageId: number;
  readonly html: string;
  readonly buttons: readonly InlineButton[];
}

export interface FakeTelegramTransport extends TelegramTransport {
  readonly sent: FakeSentMessage[];
  readonly edits: Array<{ chatId: string; messageId: number; html: string }>;
  readonly answers: Array<{ callbackId: string; text: string }>;
  /** Make the next `sendMessage` calls fail. */
  failSends: boolean;
  /** Deliver a callback query to the handler; resolves when the handler is done. */
  press(cb: Partial<IncomingCallback> & { readonly data: string | undefined }): Promise<void>;
}

export function createFakeTelegramTransport(): FakeTelegramTransport {
  let handler: ((cb: IncomingCallback) => Promise<void>) | undefined;
  let nextMessageId = 100;
  let nextCallback = 1;
  const fake: FakeTelegramTransport = {
    sent: [],
    edits: [],
    answers: [],
    failSends: false,
    sendMessage(chatId, html, buttons): Promise<Result<{ messageId: number }>> {
      if (fake.failSends) return Promise.resolve(err("telegram.send_failed", "fake send failure"));
      const messageId = nextMessageId++;
      fake.sent.push({ chatId, messageId, html, buttons: [...buttons] });
      return Promise.resolve(ok({ messageId }));
    },
    editMessage(chatId, messageId, html): Promise<Result<null>> {
      fake.edits.push({ chatId, messageId, html });
      return Promise.resolve(ok(null));
    },
    answerCallback(callbackId, text): Promise<Result<null>> {
      fake.answers.push({ callbackId, text });
      return Promise.resolve(ok(null));
    },
    onCallback(h) {
      handler = h;
    },
    start: () => ok(null),
    stop: () => Promise.resolve(),
    async press(cb) {
      if (handler === undefined) throw new Error("no callback handler registered");
      await handler({
        id: cb.id ?? `cb-${String(nextCallback++)}`,
        data: cb.data,
        fromId: cb.fromId ?? 0,
        chatId: cb.chatId,
        messageId: cb.messageId,
      });
    },
  };
  return fake;
}
