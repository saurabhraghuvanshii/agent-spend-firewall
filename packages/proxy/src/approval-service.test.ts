import { err, ok, type Result } from "@asf/core";
import { openApprovalStore, type ApprovalRow, type ApprovalStore } from "@asf/approvals";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { argsForDisplay, reasonForDisplay, type PendingApprovalRequest } from "./approval-port.js";
import {
  checkResult,
  createApprovalService,
  DECISION_ANSWERS,
  type ApprovalNotifier,
  type ApprovalService,
} from "./approval-service.js";
import type {
  ExecuteApprovedRequest,
  ExecuteApprovedResult,
  ResolveApprovalRequest,
} from "./interceptor.js";
import { denyResult, type OpenDirectCall } from "./server.js";
import { jsonOf } from "./test-support/fake-upstream.js";

const ARGS = { payment_id: "pay_1", amount: 300_000 };
const MIN = 60_000;
const APR = "apr_11111111-1111-4111-8111-111111111111";

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

function req(over: Partial<PendingApprovalRequest> = {}): PendingApprovalRequest {
  return {
    attemptId: "att-1",
    tool: "create_refund",
    finalArgs: ARGS,
    finalArgsRedacted: argsForDisplay(ARGS),
    argsHash: "a".repeat(64),
    untrustedReason: "double charge on this order",
    reasonForDisplay: reasonForDisplay("double charge on this order"),
    sessionId: "sess",
    ruleId: "refund.approval",
    message: "needs approval",
    via: "telegram",
    timeoutMin: 30,
    matchedRules: ["refund.approval"],
    ...over,
  };
}

interface Fakes {
  store: ApprovalStore;
  service: ApprovalService;
  now: { ms: number };
  notified: string[];
  shown: ApprovalRow[];
  executed: ExecuteApprovedRequest[];
  resolved: ResolveApprovalRequest[];
  logs: string[];
  notifyResult: { value: Result<{ messageId: number }> };
  execResult: { value: ExecuteApprovedResult | "throw" };
  showThrows: { value: boolean };
}

let f: Fakes;
const openCall: OpenDirectCall = () => Promise.resolve(err("x", "unused"));

function make(attach = true, clockThrows = false): Fakes {
  const store = unwrap(openApprovalStore({ path: ":memory:" }));
  const now = { ms: 10 * MIN };
  const notified: string[] = [];
  const shown: ApprovalRow[] = [];
  const executed: ExecuteApprovedRequest[] = [];
  const resolved: ResolveApprovalRequest[] = [];
  const logs: string[] = [];
  const notifyResult: Fakes["notifyResult"] = { value: ok({ messageId: 7 }) };
  const execResult: Fakes["execResult"] = {
    value: {
      status: "executed",
      attemptId: "att-1",
      upstreamRef: "rfnd_ABCDEF123",
      result: { content: [] },
    },
  };
  const showThrows = { value: false };
  const notifier: ApprovalNotifier = {
    notify: (n) => {
      notified.push(n.approvalId);
      return Promise.resolve(notifyResult.value);
    },
    showResolution: (row) => {
      shown.push(row);
      if (showThrows.value) return Promise.reject(new TypeError("boom"));
      return Promise.resolve(ok(null));
    },
  };
  let n = 0;
  const service = createApprovalService({
    store,
    notifier,
    clock: {
      nowMs: () => {
        if (clockThrows) throw new Error("clock");
        return now.ms;
      },
    },
    logger: (l) => logs.push(l),
    idGen: () => `apr_11111111-1111-4111-8111-${String(++n).padStart(12, "0")}`,
  });
  if (attach) {
    service.attach({
      openCall,
      pipeline: {
        executeApproved: (r) => {
          executed.push(r);
          const v = execResult.value;
          return v === "throw" ? Promise.reject(new Error("boom")) : Promise.resolve(v);
        },
        resolveApproval: (r) => {
          resolved.push(r);
          return ok(null);
        },
      },
    });
  }
  return {
    store,
    service,
    now,
    notified,
    shown,
    executed,
    resolved,
    logs,
    notifyResult,
    execResult,
    showThrows,
  };
}

beforeEach(() => {
  f = make();
});
afterEach(() => {
  f.store.close();
});

async function created(): Promise<string> {
  return unwrap(await f.service.create(req())).approvalId;
}

describe("approval service", () => {
  it("create stores a pending row with the policy deadline and notifies", async () => {
    const id = await created();
    const row = unwrap(f.store.get(id));
    expect(row).toMatchObject({ state: "pending", attemptId: "att-1", expiresAtMs: 40 * MIN });
    expect(f.notified).toEqual([id]);
    expect(f.service.approvalIdOf("att-1")).toBe(id);
    expect(f.service.approvalIdOf("att-x")).toBeUndefined();
  });

  it("create fails closed: bad timeout, clock error, duplicate attempt, notification failure", async () => {
    expect((await f.service.create(req({ timeoutMin: 0 }))).ok).toBe(false);
    expect((await f.service.create(req({ timeoutMin: 1.5 }))).ok).toBe(false);
    const broken = make(true, true);
    expect((await broken.service.create(req())).ok).toBe(false);
    broken.store.close();
    await created();
    expect((await f.service.create(req())).ok).toBe(false); // same attempt twice
    f.notifyResult.value = err("telegram.send_failed", "x");
    const r = await f.service.create(req({ attemptId: "att-2" }));
    expect(!r.ok && r.error.code).toBe("approval.notify_failed");
    const row = unwrap(f.store.getByAttempt("att-2"));
    expect(row?.state).toBe("expired");
  });

  it("M1: a notification error after the human already approved ⇒ ok (the decision stands)", async () => {
    let approvedDuringNotify: Promise<unknown> | undefined;
    const g = make();
    // Re-create with a notifier that approves the row before reporting a (late) send error.
    const store = g.store;
    const service = createApprovalService({
      store,
      clock: { nowMs: () => g.now.ms },
      notifier: {
        notify: (n) => {
          approvedDuringNotify = service
            .decide({ approvalId: n.approvalId, decision: "approved", approver: "telegram:9" })
            .then((r) => r.completion);
          return Promise.resolve(err("telegram.send_failed", "late error"));
        },
        showResolution: () => Promise.resolve(ok(null)),
      },
    });
    const executed: string[] = [];
    service.attach({
      openCall,
      pipeline: {
        executeApproved: (r) => {
          executed.push(r.approvalId);
          return Promise.resolve({
            status: "executed",
            attemptId: r.attemptId,
            result: { content: [] },
          });
        },
        resolveApproval: () => ok(null),
      },
    });
    const r = await service.create(req());
    expect(r.ok).toBe(true);
    await approvedDuringNotify;
    await service.idle();
    expect(executed).toHaveLength(1);
    expect(unwrap(store.getByAttempt("att-1"))?.state).toBe("approved");
    g.store.close();
  });

  it("approve executes with the in-memory args and records the execution", async () => {
    const id = await created();
    const reply = await f.service.decide({
      approvalId: id,
      decision: "approved",
      approver: "telegram:9",
    });
    expect(reply.answer).toBe(DECISION_ANSWERS.approved);
    await reply.completion;
    expect(f.executed).toEqual([
      expect.objectContaining({
        approvalId: id,
        attemptId: "att-1",
        finalArgs: ARGS,
        approver: "telegram:9",
        argsHash: "a".repeat(64),
      }),
    ]);
    expect(unwrap(f.store.get(id))?.execution).toEqual({
      status: "executed",
      upstreamRef: "rfnd_ABCDEF123",
    });
    expect(f.shown.at(-1)?.execution?.status).toBe("executed");
  });

  it("a background task that rejects is logged, never an unhandled rejection", async () => {
    const id = await created();
    f.showThrows.value = true;
    const reply = await f.service.decide({
      approvalId: id,
      decision: "rejected",
      approver: "telegram:9",
    });
    await expect(reply.completion).resolves.toBeUndefined();
    expect(f.logs.some((l) => l.includes("approval task threw TypeError"))).toBe(true);
  });

  it("a throwing execution is recorded as unknown, never as not executed", async () => {
    const id = await created();
    f.execResult.value = "throw";
    await (
      await f.service.decide({ approvalId: id, decision: "approved", approver: "telegram:9" })
    ).completion;
    expect(unwrap(f.store.get(id))?.execution?.status).toBe("unknown");
  });

  it("reject / expire close the audit side; double decisions change nothing", async () => {
    const id = await created();
    const r = await f.service.decide({
      approvalId: id,
      decision: "rejected",
      approver: "telegram:9",
    });
    await r.completion;
    expect(f.resolved).toEqual([
      { approvalId: id, attemptId: "att-1", decision: "rejected", approver: "telegram:9" },
    ]);
    const again = await f.service.decide({
      approvalId: id,
      decision: "approved",
      approver: "telegram:9",
    });
    expect(again.answer).toBe(DECISION_ANSWERS.alreadyDecided);
    expect(f.executed).toEqual([]);

    const id2 = unwrap(await f.service.create(req({ attemptId: "att-2" }))).approvalId;
    f.now.ms += 30 * MIN;
    const late = await f.service.decide({
      approvalId: id2,
      decision: "approved",
      approver: "telegram:9",
    });
    expect(late.answer).toBe(DECISION_ANSWERS.expired);
    await late.completion;
    expect(f.resolved.at(-1)).toEqual({ approvalId: id2, attemptId: "att-2", decision: "expired" });
    expect(f.executed).toEqual([]);
  });

  it("unattached service / clock failure / unknown approval never execute", async () => {
    const g = make(false);
    const id = unwrap(await g.service.create(req())).approvalId;
    expect(
      (await g.service.decide({ approvalId: id, decision: "approved", approver: "telegram:1" }))
        .answer,
    ).toBe(DECISION_ANSWERS.unavailable);
    expect(unwrap(g.store.get(id))?.state).toBe("pending");
    g.store.close();
    expect(
      (await f.service.decide({ approvalId: APR, decision: "approved", approver: "telegram:1" }))
        .answer,
    ).toBe(DECISION_ANSWERS.unavailable);
  });

  it("approved without in-memory args (e.g. a row from another run) ⇒ not executed", async () => {
    unwrap(
      f.store.create({
        approvalId: APR,
        attemptId: "att-old",
        sessionId: "sess",
        tool: "create_refund",
        argsHash: "b".repeat(64),
        ruleId: "r",
        callbackNonce: "A".repeat(22),
        createdAtMs: f.now.ms,
        expiresAtMs: f.now.ms + MIN,
      }),
    );
    const r = await f.service.decide({
      approvalId: APR,
      decision: "approved",
      approver: "telegram:1",
    });
    expect(r.answer).toBe(DECISION_ANSWERS.unavailable);
    expect(f.executed).toEqual([]);
    expect(unwrap(f.store.get(APR))?.execution).toEqual({
      status: "not_executed",
      code: "approval.args_unavailable",
    });
  });

  it("sweepExpired and expireStale", async () => {
    await created();
    await f.service.create(req({ attemptId: "att-2", timeoutMin: 60 }));
    f.now.ms += 31 * MIN;
    expect(await f.service.sweepExpired()).toBe(1);
    expect(f.resolved.map((r) => r.attemptId)).toEqual(["att-1"]);
    // expireStale skips approvals of THIS run (args in memory) and retires the rest.
    expect(unwrap(f.service.expireStale())).toBe(0);
    const fresh = make();
    unwrap(
      fresh.store.create({
        approvalId: APR,
        attemptId: "att-old",
        sessionId: "sess",
        tool: "create_refund",
        argsHash: "b".repeat(64),
        ruleId: "r",
        callbackNonce: "B".repeat(22),
        createdAtMs: 0,
        expiresAtMs: 99 * MIN,
      }),
    );
    const APR2 = "apr_22222222-2222-4222-8222-222222222222";
    unwrap(
      fresh.store.create({
        approvalId: APR2,
        attemptId: "att-old-2",
        sessionId: "sess",
        tool: "create_refund",
        argsHash: "b".repeat(64),
        ruleId: "r",
        callbackNonce: "D".repeat(22),
        createdAtMs: 0,
        expiresAtMs: 99 * MIN,
      }),
    );
    unwrap(fresh.store.decide(APR2, "approved", "telegram:1", 1));
    unwrap(fresh.store.setExecution(APR2, { status: "executing" }));
    expect(unwrap(fresh.service.expireStale())).toBe(1);
    expect(unwrap(fresh.store.get(APR))?.state).toBe("expired");
    expect(unwrap(fresh.store.get(APR2))?.execution).toEqual({
      status: "unknown",
      code: "approval.interrupted",
    });
    fresh.store.close();
  });

  it("attach twice throws (configuration error)", () => {
    expect(() =>
      f.service.attach({
        openCall,
        pipeline: {
          executeApproved: () => Promise.reject(new Error("x")),
          resolveApproval: () => ok(null),
        },
      }),
    ).toThrow();
  });
});

describe("checkResult", () => {
  const base: ApprovalRow = {
    approvalId: APR,
    attemptId: "att-1",
    sessionId: "s",
    tool: "create_refund",
    argsHash: "a".repeat(64),
    ruleId: "r",
    callbackNonce: "C".repeat(22),
    state: "approved",
    createdAtMs: 0,
    expiresAtMs: 1,
  };
  it("maps every state / execution status to a structured result", () => {
    expect(jsonOf(checkResult({ ...base, state: "pending" }))).toMatchObject({ status: "pending" });
    expect(jsonOf(checkResult(base))).toMatchObject({ execution: { status: "executing" } });
    const failed = checkResult({ ...base, execution: { status: "failed" } });
    expect(failed.isError).toBe(true);
    expect(jsonOf(failed)).toMatchObject({ error: "upstream_error" });
    expect(jsonOf(checkResult({ ...base, execution: { status: "unknown" } }))).toMatchObject({
      outcome: "unknown",
      flaggedForHuman: true,
    });
    expect(
      jsonOf(
        checkResult({ ...base, execution: { status: "not_executed", code: "firewall.busy" } }),
      ),
    ).toMatchObject({ decision: "deny", ruleId: "firewall.busy" });
    // An upstream ref that is not redaction-safe is never shown.
    expect(
      jsonOf(
        checkResult({
          ...base,
          execution: { status: "executed", upstreamRef: "rfnd_9876543210123456" },
        }),
      ),
    ).toEqual(expect.not.objectContaining({ upstreamRef: expect.anything() as unknown }));
  });

  it("is never confused with a deny body for pending / executed", () => {
    const pendingBody = jsonOf(checkResult({ ...base, state: "pending" }));
    expect(pendingBody["decision"]).toBeUndefined();
    expect(denyResult("x", "y").isError).toBe(true);
  });
});

describe("approval service shutdown (D-040)", () => {
  it("after beginShutdown an approve press starts nothing: the row stays pending, the answer says so", async () => {
    const id = await created();
    f.service.beginShutdown();
    f.service.beginShutdown(); // idempotent
    const reply = await f.service.decide({
      approvalId: id,
      decision: "approved",
      approver: "telegram:9",
    });
    expect(reply.answer).toBe(DECISION_ANSWERS.shuttingDown);
    expect(reply.answer).toMatch(/NOT executed/);
    expect(reply.completion).toBeUndefined();
    await f.service.idle();
    expect(f.executed).toEqual([]);
    expect(unwrap(f.store.get(id))?.state).toBe("pending");
  });

  it("rejections are still recorded during shutdown (they never execute anything)", async () => {
    const id = await created();
    f.service.beginShutdown();
    const reply = await f.service.decide({
      approvalId: id,
      decision: "rejected",
      approver: "telegram:9",
    });
    expect(reply.answer).toBe(DECISION_ANSWERS.rejected);
    await reply.completion;
    expect(unwrap(f.store.get(id))?.state).toBe("rejected");
    expect(f.resolved).toEqual([expect.objectContaining({ approvalId: id, decision: "rejected" })]);
  });

  it("no new approval is created once shutdown has begun", async () => {
    f.service.beginShutdown();
    const r = await f.service.create(req());
    expect(!r.ok && r.error.code).toBe("approval.shutting_down");
    expect(f.notified).toEqual([]);
    expect(unwrap(f.store.getByAttempt("att-1"))).toBeUndefined();
  });

  it("an execution that started BEFORE shutdown is drained by idle()", async () => {
    const id = await created();
    let release: (() => void) | undefined;
    // Hold the execution open until released.
    const held = new Promise<void>((r) => {
      release = r;
    });
    const service = createApprovalService({
      store: f.store,
      clock: { nowMs: () => f.now.ms },
      notifier: {
        notify: () => Promise.resolve(ok({ messageId: 1 })),
        showResolution: () => Promise.resolve(ok(null)),
      },
    });
    service.attach({
      openCall,
      pipeline: {
        executeApproved: async (r) => {
          await held;
          return { status: "executed", attemptId: r.attemptId, result: { content: [] } };
        },
        resolveApproval: () => ok(null),
      },
    });
    const id2 = unwrap(await service.create(req({ attemptId: "att-2" }))).approvalId;
    const reply = await service.decide({
      approvalId: id2,
      decision: "approved",
      approver: "telegram:9",
    });
    expect(reply.answer).toBe(DECISION_ANSWERS.approved);
    service.beginShutdown();
    let idle = false;
    const drained = service.idle().then(() => {
      idle = true;
    });
    await Promise.resolve();
    expect(idle).toBe(false);
    release?.();
    await drained;
    expect(unwrap(f.store.get(id2))?.execution?.status).toBe("executed");
    expect(unwrap(f.store.get(id))?.state).toBe("pending");
  });

  it("expireAllPending retires every approval still pending (audit closed, message updated); decided rows untouched", async () => {
    const a = await created();
    const b = unwrap(await f.service.create(req({ attemptId: "att-2" }))).approvalId;
    const c = unwrap(await f.service.create(req({ attemptId: "att-3" }))).approvalId;
    await (
      await f.service.decide({ approvalId: c, decision: "approved", approver: "telegram:9" })
    ).completion;
    f.service.beginShutdown();
    f.showThrows.value = true; // a failing message update never stops the sweep
    expect(await f.service.expireAllPending()).toBe(2);
    expect(unwrap(f.store.get(a))?.state).toBe("expired");
    expect(unwrap(f.store.get(b))?.state).toBe("expired");
    expect(unwrap(f.store.get(c))?.state).toBe("approved");
    expect(f.resolved.map((r) => [r.approvalId, r.decision])).toEqual([
      [a, "expired"],
      [b, "expired"],
    ]);
    // A press after the sweep changes nothing and executes nothing.
    const late = await f.service.decide({
      approvalId: a,
      decision: "approved",
      approver: "telegram:9",
    });
    expect(late.answer).toBe(DECISION_ANSWERS.shuttingDown);
    expect(f.executed.map((e) => e.approvalId)).toEqual([c]);
    expect(await f.service.expireAllPending()).toBe(0);
  });

  it("expireAllPending with a broken clock expires nothing (the next start's expireStale does it)", async () => {
    const g = make(true, true);
    expect(await g.service.expireAllPending()).toBe(0);
    expect(g.logs.some((l) => l.includes("clock unavailable"))).toBe(true);
    g.store.close();
  });
});
