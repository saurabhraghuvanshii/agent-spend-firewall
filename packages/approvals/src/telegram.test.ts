import { formatUntrustedReason, type Result } from "@asf/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createCallbackSigner, newNonce } from "./callback-token.js";
import { createFakeTelegramTransport, type FakeTelegramTransport } from "./fake-transport.js";
import { openApprovalStore, type ApprovalStore } from "./store.js";
import {
  ANSWERS,
  createTelegramApprover,
  type DecisionRequest,
  type TelegramApprover,
} from "./telegram.js";

const CHAT = "424242";
const T0 = 1_000_000;

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

let store: ApprovalStore;
let transport: FakeTelegramTransport;
let decisions: DecisionRequest[];
let approver: TelegramApprover;
let logs: string[];
const signer = createCallbackSigner(new Uint8Array(32).fill(3));

function setup(chatId = CHAT): void {
  transport = createFakeTelegramTransport();
  decisions = [];
  logs = [];
  approver = createTelegramApprover({
    transport,
    chatId,
    store,
    signer,
    logger: (l) => logs.push(l),
    onDecision: (d) => {
      decisions.push(d);
      return Promise.resolve({ answer: `ok ${d.decision}` });
    },
  });
}

async function pending(id = "apr_1"): Promise<{ nonce: string; messageId: number }> {
  const nonce = newNonce();
  unwrap(
    store.create({
      approvalId: id,
      attemptId: `att-${id}`,
      sessionId: "s",
      tool: "create_refund",
      argsHash: "b".repeat(64),
      ruleId: "refund.approval",
      callbackNonce: nonce,
      createdAtMs: T0,
      expiresAtMs: T0 + 60_000,
    }),
  );
  const sent = unwrap(
    await approver.notify(
      {
        approvalId: id,
        tool: "create_refund",
        argsRedacted: { payment_id: "pay_1", amount: 300_000 },
        reason: formatUntrustedReason("double charge"),
        ruleId: "refund.approval",
        policyMessage: "needs approval",
        expiresAtMs: T0 + 60_000,
      },
      nonce,
    ),
  );
  return { nonce, messageId: sent.messageId };
}

beforeEach(() => {
  store = unwrap(openApprovalStore({ path: ":memory:" }));
  setup();
});
afterEach(() => {
  store.close();
});

describe("telegram approver", () => {
  it("sends the request to the configured chat with signed Approve / Reject buttons", async () => {
    const { nonce, messageId } = await pending();
    const msg = transport.sent[0];
    expect(msg?.chatId).toBe(CHAT);
    expect(msg?.buttons.map((b) => b.text)).toEqual(["Approve", "Reject"]);
    expect(msg?.buttons.map((b) => signer.verify(b.data))).toEqual([
      { action: "approve", nonce },
      { action: "reject", nonce },
    ]);
    expect(unwrap(store.get("apr_1"))?.messageId).toBe(messageId);
  });

  it("an authorised press becomes a decision with an opaque approver id", async () => {
    const { messageId } = await pending();
    const data = transport.sent[0]?.buttons[0]?.data;
    await transport.press({ data, fromId: 424242, chatId: 424242, messageId });
    expect(decisions).toEqual([
      { approvalId: "apr_1", decision: "approved", approver: "telegram:424242" },
    ]);
    expect(transport.answers.at(-1)?.text).toBe("ok approved");
    const reject = transport.sent[0]?.buttons[1]?.data;
    await transport.press({ data: reject, fromId: 424242, chatId: 424242, messageId });
    expect(decisions.at(-1)?.decision).toBe("rejected");
  });

  it("refuses a press from another chat or another user (wrong chat)", async () => {
    const { messageId } = await pending();
    const data = transport.sent[0]?.buttons[0]?.data;
    await transport.press({ data, fromId: 999, chatId: 999, messageId });
    await transport.press({ data, fromId: 999, chatId: 424242, messageId });
    await transport.press({ data, fromId: 424242, chatId: undefined, messageId });
    await transport.press({ data, fromId: -5, chatId: 424242, messageId });
    expect(decisions).toEqual([]);
    expect(transport.answers.map((a) => a.text)).toEqual([
      ANSWERS.unauthorised,
      ANSWERS.unauthorised,
      ANSWERS.unauthorised,
      ANSWERS.unauthorised,
    ]);
    expect(logs.join("\n")).toContain("unauthorised");
  });

  it("in a group chat any member may decide and is recorded by user id", async () => {
    setup("-100123");
    const { messageId } = await pending();
    const data = transport.sent[0]?.buttons[0]?.data;
    await transport.press({ data, fromId: 7, chatId: -100123, messageId });
    expect(decisions[0]?.approver).toBe("telegram:7");
  });

  it("refuses forged, tampered and missing callback data", async () => {
    const { nonce, messageId } = await pending();
    const reject = transport.sent[0]?.buttons[1]?.data ?? "";
    const forgedSigner = createCallbackSigner(new Uint8Array(32).fill(9));
    for (const data of [
      undefined,
      "approve",
      reject.replace("v1.r.", "v1.a."),
      forgedSigner.sign("approve", nonce),
      `${reject.slice(0, -1)}${reject.endsWith("A") ? "B" : "A"}`,
    ]) {
      await transport.press({ data, fromId: 424242, chatId: 424242, messageId });
    }
    expect(decisions).toEqual([]);
    expect(new Set(transport.answers.map((a) => a.text))).toEqual(new Set([ANSWERS.invalid]));
    expect(logs.join("\n")).not.toContain(nonce);
  });

  it("refuses a valid button pressed on another message, and unknown nonces", async () => {
    const { messageId } = await pending();
    const data = transport.sent[0]?.buttons[0]?.data;
    await transport.press({ data, fromId: 424242, chatId: 424242, messageId: messageId + 50 });
    await transport.press({
      data: signer.sign("approve", newNonce()),
      fromId: 424242,
      chatId: 424242,
      messageId,
    });
    expect(decisions).toEqual([]);
    expect(transport.answers.map((a) => a.text)).toEqual([ANSWERS.unauthorised, ANSWERS.unknown]);
  });

  it("a throwing decision handler is answered as unavailable", async () => {
    const t = createFakeTelegramTransport();
    createTelegramApprover({
      transport: t,
      chatId: CHAT,
      store,
      signer,
      onDecision: () => Promise.reject(new Error("boom")),
    });
    const nonce = newNonce();
    unwrap(
      store.create({
        approvalId: "apr_9",
        attemptId: "att-9",
        sessionId: "s",
        tool: "create_refund",
        argsHash: "c".repeat(64),
        ruleId: "r",
        callbackNonce: nonce,
        createdAtMs: T0,
        expiresAtMs: T0 + 1,
      }),
    );
    await t.press({ data: signer.sign("approve", nonce), fromId: 424242, chatId: 424242 });
    expect(t.answers.at(-1)?.text).toBe(ANSWERS.unavailable);
  });

  it("send failures are returned; resolutions edit the message", async () => {
    transport.failSends = true;
    unwrap(
      store.create({
        approvalId: "apr_f",
        attemptId: "att-f",
        sessionId: "s",
        tool: "create_refund",
        argsHash: "d".repeat(64),
        ruleId: "r",
        callbackNonce: newNonce(),
        createdAtMs: T0,
        expiresAtMs: T0 + 1,
      }),
    );
    const r = await approver.notify(
      {
        approvalId: "apr_f",
        tool: "create_refund",
        argsRedacted: {},
        reason: formatUntrustedReason("x"),
        ruleId: "r",
        policyMessage: "m",
        expiresAtMs: T0 + 1,
      },
      newNonce(),
    );
    expect(r.ok).toBe(false);
    transport.failSends = false;
    await pending("apr_2");
    const row = unwrap(store.get("apr_2"));
    if (row === undefined) throw new Error("missing");
    unwrap(await approver.showResolution({ ...row, state: "rejected", decidedBy: "telegram:1" }));
    expect(transport.edits.at(-1)?.html).toContain("REJECTED");
    // No message ⇒ nothing to edit.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { messageId, ...noMessage } = row;
    unwrap(await approver.showResolution(noMessage));
  });

  it("answers at once and does not wait for the decision's follow-up work (updates never serialize)", async () => {
    const t = createFakeTelegramTransport();
    createTelegramApprover({
      transport: t,
      chatId: CHAT,
      store,
      signer,
      onDecision: () =>
        Promise.resolve({ answer: "working", completion: new Promise<void>(() => undefined) }),
    });
    const nonce = newNonce();
    unwrap(
      store.create({
        approvalId: "apr_slow",
        attemptId: "att-slow",
        sessionId: "s",
        tool: "create_refund",
        argsHash: "e".repeat(64),
        ruleId: "r",
        callbackNonce: nonce,
        createdAtMs: T0,
        expiresAtMs: T0 + 1,
      }),
    );
    // Resolves although the completion never does.
    await t.press({ data: signer.sign("approve", nonce), fromId: 424242, chatId: 424242 });
    expect(t.answers.at(-1)?.text).toBe("working");
  });

  it("refuses a malformed chat id", () => {
    expect(() =>
      createTelegramApprover({
        transport,
        chatId: "@mychannel",
        store,
        onDecision: () => Promise.resolve({ answer: "" }),
      }),
    ).toThrow(RangeError);
  });
});
