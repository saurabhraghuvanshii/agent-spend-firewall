import type { Context } from "grammy";
import { describe, expect, it } from "vitest";
import { grammyTransport, type GrammyApiLike, type GrammyLike } from "./grammy-transport.js";
import type { IncomingCallback } from "./telegram.js";

function stubBot(fail = false): {
  bot: GrammyLike;
  calls: unknown[][];
  deliver: (ctx: Partial<Context>) => Promise<void>;
  errors: Array<(e: unknown) => void>;
} {
  const calls: unknown[][] = [];
  let onData: ((ctx: Context) => Promise<void>) | undefined;
  const errors: Array<(e: unknown) => void> = [];
  const maybeFail = <T>(v: T): Promise<T> =>
    fail ? Promise.reject(new TypeError("network down: token in url")) : Promise.resolve(v);
  const api: GrammyApiLike = {
    sendMessage: (...args) => {
      calls.push(["sendMessage", ...args]);
      return maybeFail({ message_id: 55 });
    },
    editMessageText: (...args) => {
      calls.push(["editMessageText", ...args]);
      return maybeFail(true);
    },
    answerCallbackQuery: (...args) => {
      calls.push(["answerCallbackQuery", ...args]);
      return maybeFail(true);
    },
  };
  const bot: GrammyLike = {
    api,
    on: (_filter, h) => {
      onData = h;
    },
    catch: (h) => {
      errors.push(h);
    },
    start: (opts) => {
      calls.push(["start", opts]);
      return new Promise<void>(() => undefined);
    },
    stop: () => {
      calls.push(["stop"]);
      return Promise.resolve();
    },
  };
  return {
    bot,
    calls,
    errors,
    deliver: async (ctx) => {
      if (onData === undefined) throw new Error("no handler");
      await onData(ctx as Context);
    },
  };
}

describe("grammyTransport", () => {
  it("maps send / edit / answer to the Bot API with HTML and inline buttons", async () => {
    const s = stubBot();
    const t = grammyTransport(s.bot);
    expect(await t.sendMessage("42", "<b>x</b>", [{ text: "Approve", data: "d1" }])).toEqual({
      ok: true,
      value: { messageId: 55 },
    });
    expect((await t.editMessage("42", 55, "done")).ok).toBe(true);
    expect((await t.answerCallback("cb1", "ok")).ok).toBe(true);
    expect(s.calls).toEqual([
      [
        "sendMessage",
        "42",
        "<b>x</b>",
        {
          parse_mode: "HTML",
          link_preview_options: { is_disabled: true },
          reply_markup: { inline_keyboard: [[{ text: "Approve", callback_data: "d1" }]] },
        },
      ],
      [
        "editMessageText",
        "42",
        55,
        "done",
        {
          parse_mode: "HTML",
          link_preview_options: { is_disabled: true },
          reply_markup: { inline_keyboard: [] },
        },
      ],
      ["answerCallbackQuery", "cb1", { text: "ok" }],
    ]);
  });

  it("returns errors without their messages (they may carry request details)", async () => {
    const t = grammyTransport(stubBot(true).bot);
    const r = await t.sendMessage("42", "x", []);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("telegram.send_failed");
      expect(r.error.message).not.toContain("token");
    }
    expect((await t.editMessage("42", 1, "x")).ok).toBe(false);
    expect((await t.answerCallback("c", "x")).ok).toBe(false);
  });

  it("delivers callback queries as IncomingCallback", async () => {
    const s = stubBot();
    const t = grammyTransport(s.bot);
    const got: IncomingCallback[] = [];
    t.onCallback((cb) => {
      got.push(cb);
      return Promise.resolve();
    });
    await s.deliver({
      callbackQuery: {
        id: "q1",
        data: "v1.a.x",
        from: { id: 7, is_bot: false, first_name: "A" },
        chat_instance: "ci",
        message: {
          message_id: 9,
          date: 0,
          chat: { id: 42, type: "private", first_name: "A" },
        },
      },
    });
    expect(got).toEqual([{ id: "q1", data: "v1.a.x", fromId: 7, chatId: 42, messageId: 9 }]);
  });

  it("starts long polling for callback queries only, once; stops", async () => {
    const s = stubBot();
    const logs: string[] = [];
    const t = grammyTransport(s.bot, (l) => logs.push(l));
    expect(t.start().ok).toBe(true);
    expect(t.start().ok).toBe(false);
    expect(s.calls[0]).toEqual([
      "start",
      { allowed_updates: ["callback_query"], drop_pending_updates: true },
    ]);
    await t.stop();
    expect(s.calls.at(-1)).toEqual(["stop"]);
    s.errors[0]?.(new RangeError("x"));
    expect(logs).toEqual(["telegram: update handling failed (RangeError)"]);
  });
});
