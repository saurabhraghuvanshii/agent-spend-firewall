/**
 * Production `TelegramTransport` over grammy (long polling, callback queries only). Not unit-tested against the
 * network; `telegram.test.ts` covers the approver through a fake transport and `grammy-transport.test.ts` covers this
 * adapter's mapping with grammy's own API object stubbed.
 *
 * The bot token is a secret: it is never logged. Errors are reduced to their class name (grammy's `HttpError` /
 * `GrammyError` messages can embed request details).
 */
import { Bot, type Context } from "grammy";
import { err, ok, type Result } from "@asf/core";
import type { IncomingCallback, InlineButton, TelegramTransport } from "./telegram.js";

/** Minimal slice of grammy's `Api` the transport uses (lets tests stub it). */
export interface GrammyApiLike {
  sendMessage(
    chatId: string,
    text: string,
    other: {
      parse_mode: "HTML";
      link_preview_options: { is_disabled: boolean };
      reply_markup: { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> };
    },
  ): Promise<{ message_id: number }>;
  editMessageText(
    chatId: string,
    messageId: number,
    text: string,
    other: {
      parse_mode: "HTML";
      link_preview_options: { is_disabled: boolean };
      reply_markup: { inline_keyboard: never[] };
    },
  ): Promise<unknown>;
  answerCallbackQuery(id: string, other: { text: string }): Promise<unknown>;
}

export interface GrammyLike {
  readonly api: GrammyApiLike;
  on(filter: "callback_query:data", handler: (ctx: Context) => Promise<void>): void;
  catch(handler: (e: unknown) => void): void;
  start(opts: {
    allowed_updates: ["callback_query"];
    drop_pending_updates: boolean;
  }): Promise<void>;
  stop(): Promise<void>;
}

function failure(code: string, e: unknown): Result<never> {
  return err(code, `telegram request failed (${e instanceof Error ? e.name : typeof e})`);
}

/** Wrap a grammy bot (or a stub with the same surface). */
export function grammyTransport(
  bot: GrammyLike,
  logger: (line: string) => void = () => undefined,
): TelegramTransport {
  let handler: ((cb: IncomingCallback) => Promise<void>) | undefined;
  let started = false;
  bot.catch((e: unknown) => {
    logger(`telegram: update handling failed (${e instanceof Error ? e.name : typeof e})`);
  });
  bot.on("callback_query:data", async (ctx: Context) => {
    const q = ctx.callbackQuery;
    if (q === undefined || handler === undefined) return;
    const msg = q.message;
    await handler({
      id: q.id,
      data: q.data,
      fromId: q.from.id,
      chatId: msg?.chat.id,
      messageId: msg?.message_id,
    });
  });
  return {
    async sendMessage(chatId, html, buttons: readonly InlineButton[]) {
      try {
        const m = await bot.api.sendMessage(chatId, html, {
          parse_mode: "HTML",
          link_preview_options: { is_disabled: true },
          reply_markup: {
            inline_keyboard: [buttons.map((b) => ({ text: b.text, callback_data: b.data }))],
          },
        });
        return ok({ messageId: m.message_id });
      } catch (e: unknown) {
        return failure("telegram.send_failed", e);
      }
    },
    async editMessage(chatId, messageId, html) {
      try {
        await bot.api.editMessageText(chatId, messageId, html, {
          parse_mode: "HTML",
          link_preview_options: { is_disabled: true },
          reply_markup: { inline_keyboard: [] },
        });
        return ok(null);
      } catch (e: unknown) {
        return failure("telegram.edit_failed", e);
      }
    },
    async answerCallback(id, text) {
      try {
        await bot.api.answerCallbackQuery(id, { text });
        return ok(null);
      } catch (e: unknown) {
        return failure("telegram.answer_failed", e);
      }
    },
    onCallback(h) {
      handler = h;
    },
    start() {
      if (started) return err("telegram.already_started", "the bot is already running");
      started = true;
      bot
        .start({ allowed_updates: ["callback_query"], drop_pending_updates: true })
        .catch((e: unknown) => {
          started = false;
          logger(`telegram: polling stopped (${e instanceof Error ? e.name : typeof e})`);
        });
      return ok(null);
    },
    async stop() {
      if (!started) return;
      started = false;
      try {
        await bot.stop();
      } catch (e: unknown) {
        logger(`telegram: stopping the bot failed (${e instanceof Error ? e.name : typeof e})`);
      }
    },
  };
}

/** Production transport for `TELEGRAM_BOT_TOKEN`. */
export function createGrammyTransport(
  token: string,
  logger?: (line: string) => void,
): TelegramTransport {
  return grammyTransport(new Bot(token), logger);
}
