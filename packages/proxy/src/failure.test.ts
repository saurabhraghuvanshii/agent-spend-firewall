/**
 * T010 unit tests: notes marker rules, the action verifier (refund marker pagination, capture status, unsupported
 * tools), the late-response tracker, `handleUnsettled` and `reconcileAtStartup` — fake upstream port, in-memory audit
 * store, fake timers (no real waits).
 */
import type { AuditRecord, Timer, TimerHandle } from "@asf/core";
import { describe, expect, it, vi } from "vitest";
import { openAuditStore, type AuditStore, type AuditVerificationRecord } from "./audit-store.js";
import type { UpstreamPaymentPort } from "./context-adapters.js";
import {
  ATTEMPT_MARKER_KEY,
  createActionVerifier,
  createLateResponseTracker,
  handleUnsettled,
  MAX_AGENT_NOTES,
  MAX_REFUND_PAGES,
  notesProblem,
  reconcileAtStartup,
  REFUND_LIST_SHORT_PAGE,
  REFUND_LIST_TOOL,
  REFUND_PAGE_SIZE,
  REJECTED_ERROR_CODE,
  stampAttemptMarker,
  startupFailureOf,
  STARTUP_MAX_CONSECUTIVE_TIMEOUTS,
  type ActionVerifier,
  type Finding,
  type LateResponseSource,
} from "./failure.js";
import type { CallOptions, LateResponse, UpstreamCallOutcome } from "./upstream.js";
import type { UpstreamFailure } from "./upstream-failure.js";

const ATT = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";
const OTHER = "6fa459ea-ee8a-4ca4-894e-db77e160355e";
const PAY = "pay_FAIL1";

function unwrap<T>(r: { ok: true; value: T } | { ok: false; error: { code: string } }): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}

const okJson = (json: unknown): UpstreamCallOutcome => ({
  kind: "ok",
  result: { content: [{ type: "text", text: JSON.stringify(json) }] },
});

interface PortCall {
  readonly name: string;
  readonly args: Record<string, unknown>;
  readonly opts: CallOptions | undefined;
}

function port(
  answer: (name: string, args: Record<string, unknown>) => UpstreamCallOutcome,
): UpstreamPaymentPort & { calls: PortCall[] } {
  const calls: PortCall[] = [];
  return {
    calls,
    callTool: (name, args, opts) => {
      calls.push({ name, args, opts });
      return Promise.resolve(answer(name, args));
    },
  };
}

function refund(
  id: string,
  amount: number,
  marker?: string,
  status: string | null = "processed",
): Record<string, unknown> {
  return {
    id,
    entity: "refund",
    amount,
    payment_id: PAY,
    ...(status === null ? {} : { status }),
    notes: marker === undefined ? [] : { [ATTEMPT_MARKER_KEY]: marker, order: "o1" },
  };
}

/** Refund list port: `pages[i]` is the items of page i (skip = i·100). */
function refundPages(pages: unknown[][]): UpstreamPaymentPort & { calls: PortCall[] } {
  return port((name, args) => {
    if (name !== REFUND_LIST_TOOL) return okJson({});
    const skip = typeof args["skip"] === "number" ? args["skip"] : 0;
    const items = pages[skip / REFUND_PAGE_SIZE] ?? [];
    return okJson({ entity: "collection", count: items.length, items });
  });
}

function fillers(n: number, start = 0): unknown[] {
  return Array.from({ length: n }, (_, i) => refund(`rfnd_F${String(start + i)}abcdef`, 100));
}

const refundArgs = (marker = ATT, amount = 5_000): Record<string, unknown> => ({
  payment_id: PAY,
  amount,
  notes: { [ATTEMPT_MARKER_KEY]: marker },
});

const verifyRefund = (
  v: ActionVerifier,
  over: { failure?: UpstreamFailure; args?: unknown; maxLookups?: number } = {},
): Promise<Finding> =>
  v.verify({
    attemptId: ATT,
    tool: "create_refund",
    args: over.args ?? refundArgs(),
    failure: over.failure ?? "none",
    ...(over.maxLookups === undefined ? {} : { maxLookups: over.maxLookups }),
  });

const immediateTimer: Timer = {
  after: (): TimerHandle => ({ promise: Promise.resolve(), cancel: () => undefined }),
};
const neverTimer: Timer = {
  after: (): TimerHandle => ({
    promise: new Promise<void>(() => undefined),
    cancel: () => undefined,
  }),
};

function lateSource(): LateResponseSource & { emit(e: LateResponse): void } {
  const ls = new Set<(e: LateResponse) => void>();
  return {
    onLateResponse: (l) => {
      ls.add(l);
      return () => ls.delete(l);
    },
    emit: (e) => {
      for (const l of ls) l(e);
    },
  };
}

/** A late answer; a failure is an (ambiguous) JSON-RPC error unless `failure` says otherwise. */
const late = (
  requestId: number,
  isError: boolean,
  generation = 1,
  failure: UpstreamFailure = isError ? "ambiguous" : "none",
): LateResponse => ({
  requestId,
  tool: "create_refund",
  generation,
  sentAt: 1,
  receivedAt: 2,
  responseType: isError && failure === "ambiguous" ? "error" : "result",
  isError,
  failure,
});
const lateRejected = (requestId: number): LateResponse =>
  late(requestId, true, 1, "definite_rejection");

// ---------------------------------------------------------------------------------------------------------------

describe("notes marker rules", () => {
  it("asf_* keys (any case) and more than 14 notes are refused; 14 is fine", () => {
    expect(notesProblem("create_refund", { notes: { asf_attempt: "x" } })).toMatch(/reserved/);
    expect(notesProblem("create_refund", { notes: { ASF_x: "x" } })).toMatch(/reserved/);
    expect(notesProblem("create_payment_link", { notes: { Asf_Foo: "x" } })).toMatch(/reserved/);
    const many = Object.fromEntries(
      Array.from({ length: MAX_AGENT_NOTES + 1 }, (_, i) => [`k${String(i)}`, "v"]),
    );
    expect(notesProblem("create_refund", { notes: many })).toMatch(/at most 14/);
    const ok14 = Object.fromEntries(
      Array.from({ length: MAX_AGENT_NOTES }, (_, i) => [`k${String(i)}`, "v"]),
    );
    expect(notesProblem("create_refund", { notes: ok14 })).toBeUndefined();
    expect(notesProblem("create_refund", { amount: 1 })).toBeUndefined();
    expect(
      notesProblem("create_refund", { notes: { asfx: "fine", my_asf_: "fine" } }),
    ).toBeUndefined();
  });

  it("any arg string containing a rejection code (any case / depth / tool) is refused", () => {
    expect(notesProblem("create_refund", { notes: { memo: "BAD_REQUEST_ERROR" } })).toMatch(
      /error code/,
    );
    expect(notesProblem("create_payment_link", { description: "bad_request_error" })).toMatch(
      /error code/,
    );
    expect(notesProblem("create_refund", { receipt: { x: ["Bad_Request_Error"] } })).toMatch(
      /error code/,
    );
    expect(notesProblem("create_refund", { receipt: "BAD REQUEST" })).toBeUndefined();
  });

  it("non-object notes: refused on a marked tool only", () => {
    expect(notesProblem("create_refund", { notes: "text" })).toMatch(/object/);
    expect(notesProblem("create_refund", { notes: [] })).toMatch(/object/);
    expect(notesProblem("create_payment_link", { notes: "text" })).toBeUndefined();
  });

  it("stamps the marker into a fresh copy, keeping existing notes; other tools unchanged", () => {
    const args = { payment_id: PAY, amount: 100, notes: { order: "o1" } };
    const stamped = unwrap(stampAttemptMarker("create_refund", args, ATT));
    expect(stamped).toEqual({
      payment_id: PAY,
      amount: 100,
      notes: { order: "o1", asf_attempt: ATT },
    });
    expect(args.notes).toEqual({ order: "o1" });
    expect(unwrap(stampAttemptMarker("create_refund", { amount: 1 }, ATT))).toEqual({
      amount: 1,
      notes: { asf_attempt: ATT },
    });
    expect(unwrap(stampAttemptMarker("capture_payment", { amount: 1 }, ATT))).toEqual({
      amount: 1,
    });
    expect(stampAttemptMarker("create_refund", { notes: "x" }, ATT).ok).toBe(false);
  });
});

describe("verifier: create_refund (notes marker)", () => {
  it("marker found with the same amount ⇒ happened with the refund id; asks for 100 per page", async () => {
    const p = refundPages([
      [refund("rfnd_OTHER0001", 5_000, OTHER), refund("rfnd_MINE00001", 5_000, ATT)],
    ]);
    const f = await verifyRefund(createActionVerifier({ upstream: p }));
    expect(f).toMatchObject({
      result: "happened",
      method: "refund_notes_marker",
      upstreamRef: "rfnd_MINE00001",
    });
    expect(p.calls).toEqual([
      {
        name: REFUND_LIST_TOOL,
        args: { payment_id: PAY, count: 100, skip: 0 },
        opts: { timeoutMs: 5_000 },
      },
    ]);
  });

  it("marker found with a different amount ⇒ unknown (never inferred)", async () => {
    const p = refundPages([[refund("rfnd_MINE00001", 4_000, ATT)]]);
    const f = await verifyRefund(createActionVerifier({ upstream: p }));
    expect(f).toMatchObject({ result: "unknown", errorCode: "verify.amount_mismatch" });
  });

  it("complete list without marker ⇒ not_happened only with a DEFINITE rejection; ambiguous ⇒ unknown", async () => {
    const p = refundPages([[refund("rfnd_OTHER0001", 5_000, OTHER)]]);
    const v = createActionVerifier({ upstream: p });
    expect(await verifyRefund(v)).toMatchObject({
      result: "unknown",
      absent: true,
      errorCode: "verify.not_found",
    });
    expect(await verifyRefund(v, { failure: "definite_rejection" })).toMatchObject({
      result: "not_happened",
      absent: true,
    });
    expect(await verifyRefund(v, { failure: "ambiguous" })).toMatchObject({
      result: "unknown",
      absent: true,
      errorCode: "verify.ambiguous_failure",
    });
  });

  it("refund status: processed / pending ⇒ happened (status kept); failed / other / missing ⇒ unknown", async () => {
    const withStatus = (st: string | null): Promise<Finding> =>
      verifyRefund(
        createActionVerifier({
          upstream: refundPages([[refund("rfnd_MINE00001", 5_000, ATT, st)]]),
        }),
        { failure: "definite_rejection" },
      );
    expect(await withStatus("processed")).toMatchObject({
      result: "happened",
      refundStatus: "processed",
      upstreamRef: "rfnd_MINE00001",
    });
    expect(await withStatus("pending")).toMatchObject({
      result: "happened",
      refundStatus: "pending",
    });
    expect(await withStatus("failed")).toMatchObject({
      result: "unknown",
      errorCode: "verify.refund_failed",
    });
    expect(await withStatus("weird")).toMatchObject({
      result: "unknown",
      errorCode: "verify.unexpected_status",
    });
    expect(await withStatus(null)).toMatchObject({
      result: "unknown",
      errorCode: "verify.unexpected_status",
    });
  });

  it("a page of exactly 10 items (server ignoring count=100) ⇒ incomplete ⇒ unknown, even with a rejection", async () => {
    const p = refundPages([fillers(REFUND_LIST_SHORT_PAGE)]);
    const f = await verifyRefund(createActionVerifier({ upstream: p }), {
      failure: "definite_rejection",
    });
    expect(f).toMatchObject({ result: "unknown", errorCode: "verify.incomplete" });
    const nine = refundPages([fillers(REFUND_LIST_SHORT_PAGE - 1)]);
    expect(
      await verifyRefund(createActionVerifier({ upstream: nine }), {
        failure: "definite_rejection",
      }),
    ).toMatchObject({ result: "not_happened" });
  });

  it("paginates: a full page of 100 is not complete; the marker on page 2 is found", async () => {
    const p = refundPages([fillers(100), [refund("rfnd_MINE00001", 5_000, ATT)]]);
    const f = await verifyRefund(createActionVerifier({ upstream: p }));
    expect(f).toMatchObject({ result: "happened", lookups: 2 });
    expect(p.calls.map((c) => c.args["skip"])).toEqual([0, 100]);
  });

  it("exactly 100 refunds then an empty page ⇒ complete (absent)", async () => {
    const p = refundPages([fillers(100), []]);
    const f = await verifyRefund(createActionVerifier({ upstream: p }), {
      failure: "definite_rejection",
    });
    expect(f).toMatchObject({ result: "not_happened", lookups: 2 });
  });

  it("five full pages ⇒ unknown (incomplete), never not_happened", async () => {
    const p = refundPages(Array.from({ length: 6 }, (_, i) => fillers(100, i * 100)));
    const f = await verifyRefund(createActionVerifier({ upstream: p }), {
      failure: "definite_rejection",
    });
    expect(f).toMatchObject({ result: "unknown", errorCode: "verify.incomplete" });
    expect(p.calls).toHaveLength(MAX_REFUND_PAGES);
  });

  it("an unreadable refund item, a malformed page, a lookup timeout, a credential leak ⇒ unknown", async () => {
    const bad = refundPages([[{ id: "rfnd_X1abcdef", amount: 1.5 }]]);
    expect(
      await verifyRefund(createActionVerifier({ upstream: bad }), {
        failure: "definite_rejection",
      }),
    ).toMatchObject({
      result: "unknown",
      errorCode: "verify.malformed",
    });
    const notList = port(() => okJson({ entity: "collection" }));
    expect(await verifyRefund(createActionVerifier({ upstream: notList }))).toMatchObject({
      result: "unknown",
      errorCode: "verify.malformed",
    });
    const timeout = port(() => ({
      kind: "error",
      error: "upstream_timeout",
      message: "t",
      forwarded: true,
    }));
    expect(await verifyRefund(createActionVerifier({ upstream: timeout }))).toMatchObject({
      result: "unknown",
      errorCode: "verify.timeout",
    });
    const leak = refundPages([[{ ...refund("rfnd_MINE00001", 5_000, ATT), x: "rzp_test_SECRET" }]]);
    const v = createActionVerifier({
      upstream: leak,
      redact: (s) => s.replaceAll("rzp_test_SECRET", "[KEY]"),
    });
    expect(await verifyRefund(v)).toMatchObject({
      result: "unknown",
      errorCode: "verify.credential_leak",
    });
    const isErr = port(() => ({
      kind: "ok",
      result: { isError: true, content: [{ type: "text", text: "{}" }] },
    }));
    expect(await verifyRefund(createActionVerifier({ upstream: isErr }))).toMatchObject({
      result: "unknown",
    });
  });

  it("no marker in what was sent, or a bad payment id ⇒ unknown without any lookup", async () => {
    const p = refundPages([[]]);
    const v = createActionVerifier({ upstream: p });
    expect(await verifyRefund(v, { args: { payment_id: PAY, amount: 5_000 } })).toMatchObject({
      result: "unknown",
      errorCode: "verify.no_marker",
    });
    expect(
      await verifyRefund(v, { args: { ...refundArgs(), payment_id: "[REDACTED]" } }),
    ).toMatchObject({
      result: "unknown",
      errorCode: "verify.bad_args",
    });
    expect(p.calls).toHaveLength(0);
  });

  it("respects a lookup budget", async () => {
    const p = refundPages([fillers(100), fillers(100, 100), []]);
    const f = await verifyRefund(createActionVerifier({ upstream: p }), { maxLookups: 2 });
    expect(f).toMatchObject({ result: "unknown", errorCode: "verify.budget", lookups: 2 });
  });

  it("an upstream port that throws ⇒ unknown, never throws", async () => {
    const v = createActionVerifier({
      upstream: { callTool: () => Promise.reject(new Error("boom")) },
    });
    expect(await verifyRefund(v)).toMatchObject({ result: "unknown", errorCode: "verify.failed" });
  });
});

describe("verifier: capture_payment (payment status) and other tools", () => {
  const capture = (v: ActionVerifier, rejected: boolean | "ambiguous"): Promise<Finding> =>
    v.verify({
      attemptId: ATT,
      tool: "capture_payment",
      args: { payment_id: PAY, amount: 5_000, currency: "INR" },
      failure: rejected === "ambiguous" ? "ambiguous" : rejected ? "definite_rejection" : "none",
    });
  const status = (s: string, id = PAY): UpstreamPaymentPort =>
    port((name) =>
      name === "fetch_payment" ? okJson({ id, status: s, amount: 5_000 }) : okJson({}),
    );

  it("captured ⇒ happened; authorized ⇒ not_happened only with a definite rejection; else unknown", async () => {
    expect(
      await capture(createActionVerifier({ upstream: status("captured") }), false),
    ).toMatchObject({
      result: "happened",
      method: "payment_status",
      upstreamRef: PAY,
    });
    expect(
      await capture(createActionVerifier({ upstream: status("authorized") }), true),
    ).toMatchObject({
      result: "not_happened",
    });
    expect(
      await capture(createActionVerifier({ upstream: status("authorized") }), false),
    ).toMatchObject({
      result: "unknown",
    });
    expect(
      await capture(createActionVerifier({ upstream: status("authorized") }), "ambiguous"),
    ).toMatchObject({
      result: "unknown",
      errorCode: "verify.ambiguous_failure",
    });
    expect(
      await capture(createActionVerifier({ upstream: status("refunded") }), true),
    ).toMatchObject({
      result: "unknown",
    });
    expect(
      await capture(createActionVerifier({ upstream: status("captured", "pay_OTHER") }), false),
    ).toMatchObject({
      result: "unknown",
      errorCode: "verify.payment_mismatch",
    });
  });

  it("a non-verifiable tool ⇒ unknown (method none), no lookup", async () => {
    const p = port(() => okJson({}));
    const f = await createActionVerifier({ upstream: p }).verify({
      attemptId: ATT,
      tool: "create_payment_link",
      args: { amount: 100 },
      failure: "definite_rejection",
    });
    expect(f).toMatchObject({ result: "unknown", method: "none" });
    expect(p.calls).toHaveLength(0);
  });
});

describe("late-response tracker", () => {
  it("delivers a late answer to a waiter; a buffered one is returned at once; other generations don't match", async () => {
    const src = lateSource();
    const t = createLateResponseTracker({ source: src, timer: neverTimer });
    const waiting = t.waitFor(1, 7, 1_000);
    src.emit(late(7, false, 2)); // other generation: buffered, not delivered
    src.emit(late(7, true, 1));
    await expect(waiting).resolves.toMatchObject({ requestId: 7, isError: true });
    await expect(t.waitFor(2, 7, 1_000)).resolves.toMatchObject({ generation: 2 });
    t.close();
  });

  it("times out ⇒ undefined; unclaimed events reach listeners; take() removes", async () => {
    const src = lateSource();
    const t = createLateResponseTracker({ source: src, timer: immediateTimer });
    await expect(t.waitFor(1, 9, 1_000)).resolves.toBeUndefined();
    const seen: LateResponse[] = [];
    t.onUnclaimed((e) => seen.push(e));
    src.emit(late(9, false));
    expect(seen).toHaveLength(1);
    expect(t.take(1, 9)).toMatchObject({ requestId: 9 });
    expect(t.take(1, 9)).toBeUndefined();
  });

  it("no source ⇒ never waits", async () => {
    const t = createLateResponseTracker({ source: undefined, timer: neverTimer });
    await expect(t.waitFor(1, 1, 60_000)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------------------------------------------

function memStore(maxScanRows?: number): AuditStore {
  return unwrap(
    openAuditStore({ path: ":memory:", ...(maxScanRows === undefined ? {} : { maxScanRows }) }),
  );
}

function sentRefund(
  s: AuditStore,
  id: string,
  outcome?: { outcome: "timeout" | "upstream_error" | "success"; errorCode?: string },
  decision: "allow" | "require_approval" = "allow",
  tool = "create_refund",
): void {
  unwrap(
    s.recordAttempt({
      id,
      sessionId: "s",
      tool,
      args: tool === "create_refund" ? refundArgs(id) : { amount: 100 },
      reason: "a reason that is long enough",
      decision,
      matchedRules: ["r"],
    }),
  );
  if (outcome !== undefined) {
    unwrap(
      s.recordOutcome({
        attemptId: id,
        outcome: outcome.outcome,
        latencyMs: 1,
        ...(outcome.errorCode === undefined ? {} : { errorCode: outcome.errorCode }),
      }),
    );
  }
}

function verifications(s: AuditStore): AuditVerificationRecord[] {
  const out: AuditVerificationRecord[] = [];
  for (const r of unwrap(s.readAll()))
    if (!("invalid" in r) && r.kind === "verification") out.push(r);
  return out;
}

describe("handleUnsettled", () => {
  it("absent + waitLate ⇒ waits; a late DEFINITE rejection ⇒ not_happened (lateRejection) recorded, needsHuman false", async () => {
    const s = memStore();
    sentRefund(s, ATT, { outcome: "timeout", errorCode: "upstream.timeout" });
    const src = lateSource();
    const tracker = createLateResponseTracker({ source: src, timer: neverTimer });
    const verifier = createActionVerifier({ upstream: refundPages([[]]) });
    const p = handleUnsettled(
      { store: s, verifier, tracker, verifyWaitMs: 15_000 },
      {
        attemptId: ATT,
        tool: "create_refund",
        args: refundArgs(),
        trigger: "timeout",
        failure: "none",
        waitLate: { generation: 1, requestId: 3 },
      },
    );
    await vi.waitFor(() => {
      src.emit(lateRejected(3));
    });
    const r = await p;
    expect(r).toMatchObject({
      lateRejection: true,
      auditFailed: false,
      finding: { result: "not_happened" },
    });
    expect(verifications(s)).toEqual([
      expect.objectContaining({
        attemptId: ATT,
        trigger: "timeout",
        result: "not_happened",
        needsHuman: false,
      }),
    ]);
    expect(unwrap(s.verify()).ok).toBe(true);
  });

  it.each([
    ["an ambiguous isError result (e.g. context canceled)", late(3, true, 1, "ambiguous")],
    ["a JSON-RPC error", late(3, true)],
  ])("absent + waitLate + %s ⇒ unknown + needsHuman, no lateRejection", async (_label, answer) => {
    const s = memStore();
    sentRefund(s, ATT, { outcome: "timeout", errorCode: "upstream.timeout" });
    const src = lateSource();
    const tracker = createLateResponseTracker({ source: src, timer: neverTimer });
    const p = handleUnsettled(
      {
        store: s,
        verifier: createActionVerifier({ upstream: refundPages([[]]) }),
        tracker,
        verifyWaitMs: 15_000,
      },
      {
        attemptId: ATT,
        tool: "create_refund",
        args: refundArgs(),
        trigger: "timeout",
        failure: "none",
        waitLate: { generation: 1, requestId: 3 },
      },
    );
    await vi.waitFor(() => {
      src.emit(answer);
    });
    const r = await p;
    expect(r).toMatchObject({
      lateRejection: false,
      finding: { result: "unknown", errorCode: "verify.ambiguous_failure" },
    });
    expect(verifications(s)).toEqual([
      expect.objectContaining({ result: "unknown", needsHuman: true }),
    ]);
  });

  it("a direct tool error: ambiguous ⇒ unknown + flagged; definite rejection ⇒ not_happened (no wait)", async () => {
    for (const [failure, result] of [
      ["ambiguous", "unknown"],
      ["definite_rejection", "not_happened"],
    ] as const) {
      const s = memStore();
      sentRefund(s, ATT, { outcome: "upstream_error", errorCode: "upstream.tool_error" });
      const r = await handleUnsettled(
        {
          store: s,
          verifier: createActionVerifier({ upstream: refundPages([[]]) }),
          tracker: createLateResponseTracker({ source: lateSource(), timer: neverTimer }),
          verifyWaitMs: 15_000,
        },
        {
          attemptId: ATT,
          tool: "create_refund",
          args: refundArgs(),
          trigger: "upstream_error",
          failure,
        },
      );
      expect(r.finding.result).toBe(result);
      expect(verifications(s)).toEqual([
        expect.objectContaining({ result, needsHuman: result === "unknown" }),
      ]);
    }
  });

  it("settleLate-style: a late ambiguous answer never settles an absent refund; a late rejection does", async () => {
    const s = memStore();
    sentRefund(s, ATT, { outcome: "timeout" });
    const deps = {
      store: s,
      verifier: createActionVerifier({ upstream: refundPages([[]]) }),
      tracker: createLateResponseTracker({ source: undefined, timer: immediateTimer }),
      verifyWaitMs: 1,
    };
    const base = {
      attemptId: ATT,
      tool: "create_refund",
      args: refundArgs(),
      trigger: "late_response" as const,
      failure: "none" as const,
      recordUnknown: false,
    };
    const amb = await handleUnsettled(deps, { ...base, late: late(3, true, 1, "ambiguous") });
    expect(amb.finding.result).toBe("unknown");
    expect(amb.record).toBeUndefined();
    const rpc = await handleUnsettled(deps, { ...base, late: late(3, true) });
    expect(rpc.finding.result).toBe("unknown");
    const rej = await handleUnsettled(deps, { ...base, late: lateRejected(3) });
    expect(rej.finding.result).toBe("not_happened");
    expect(verifications(s)).toEqual([expect.objectContaining({ result: "not_happened" })]);
  });

  it("an ambiguous answer in hand stays ambiguous even if a late rejection follows (mergeFailure)", async () => {
    const s = memStore();
    sentRefund(s, ATT, { outcome: "timeout" });
    const r = await handleUnsettled(
      {
        store: s,
        verifier: createActionVerifier({ upstream: refundPages([[]]) }),
        tracker: createLateResponseTracker({ source: undefined, timer: immediateTimer }),
        verifyWaitMs: 1,
      },
      {
        attemptId: ATT,
        tool: "create_refund",
        args: refundArgs(),
        trigger: "late_response",
        failure: "ambiguous",
        late: lateRejected(3),
        recordUnknown: false,
      },
    );
    expect(r).toMatchObject({ lateRejection: false, finding: { result: "unknown" } });
  });

  it("no late answer ⇒ unknown, needsHuman, logged without payload", async () => {
    const s = memStore();
    sentRefund(s, ATT, { outcome: "timeout" });
    const logs: string[] = [];
    const tracker = createLateResponseTracker({ source: lateSource(), timer: immediateTimer });
    const r = await handleUnsettled(
      {
        store: s,
        verifier: createActionVerifier({ upstream: refundPages([[]]) }),
        tracker,
        verifyWaitMs: 15_000,
        logger: (l) => logs.push(l),
      },
      {
        attemptId: ATT,
        tool: "create_refund",
        args: refundArgs(),
        trigger: "timeout",
        failure: "none",
        waitLate: { generation: 1, requestId: 3 },
      },
    );
    expect(r).toMatchObject({ lateRejection: false, finding: { result: "unknown" } });
    expect(verifications(s)).toEqual([
      expect.objectContaining({
        result: "unknown",
        needsHuman: true,
        errorCode: "verify.not_found",
      }),
    ]);
    expect(logs.join("\n")).toContain(`NEEDS A HUMAN: create_refund attempt ${ATT}`);
    expect(logs.join("\n")).not.toContain(PAY);
  });

  it("recordUnknown:false writes nothing for unknown; a late SUCCESS settles a non-verifiable tool as happened", async () => {
    const s = memStore();
    sentRefund(s, ATT, { outcome: "timeout" }, "allow", "create_payment_link");
    const deps = {
      store: s,
      verifier: createActionVerifier({ upstream: port(() => okJson({})) }),
      tracker: createLateResponseTracker({ source: undefined, timer: immediateTimer }),
      verifyWaitMs: 1,
    };
    const base = {
      attemptId: ATT,
      tool: "create_payment_link",
      args: { amount: 100 },
      trigger: "late_response" as const,
      failure: "none" as const,
      recordUnknown: false,
    };
    expect(
      (await handleUnsettled(deps, { ...base, late: { isError: true, failure: "ambiguous" } }))
        .record,
    ).toBeUndefined();
    expect(verifications(s)).toHaveLength(0);
    const r = await handleUnsettled(deps, { ...base, late: { isError: false, failure: "none" } });
    expect(r.finding).toMatchObject({ result: "happened", method: "none" });
    expect(verifications(s)).toEqual([
      expect.objectContaining({ result: "happened", method: "none" }),
    ]);
  });

  it("verification write failure ⇒ auditFailed", async () => {
    const s = memStore();
    // No outcome for the attempt ⇒ the store refuses the verification.
    sentRefund(s, ATT);
    const r = await handleUnsettled(
      {
        store: s,
        verifier: createActionVerifier({ upstream: refundPages([[]]) }),
        tracker: createLateResponseTracker({ source: undefined, timer: immediateTimer }),
        verifyWaitMs: 1,
      },
      {
        attemptId: ATT,
        tool: "create_refund",
        args: refundArgs(),
        trigger: "timeout",
        failure: "definite_rejection",
      },
    );
    expect(r.auditFailed).toBe(true);
  });
});

describe("reconcileAtStartup", () => {
  const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const D = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const E = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

  it("orphans get firewall.orphaned; timeout / upstream_error verified; require_approval and success untouched", async () => {
    const s = memStore();
    sentRefund(s, A); // open allow ⇒ orphan
    sentRefund(s, B, { outcome: "timeout", errorCode: "upstream.timeout" }); // refund exists ⇒ happened
    sentRefund(s, C, { outcome: "upstream_error", errorCode: REJECTED_ERROR_CODE }); // absent + definite rejection ⇒ not_happened
    sentRefund(s, D, undefined, "require_approval"); // pending approval: untouched
    sentRefund(s, E, { outcome: "success" }); // settled
    const verifier = createActionVerifier({
      upstream: refundPages([[refund("rfnd_B00000001", 5_000, B)]]),
    });
    const r = unwrap(await reconcileAtStartup({ store: s, verifier }));
    expect(r).toMatchObject({ orphaned: 1, happened: 1, notHappened: 1 });
    expect(r.unresolved.map((a) => a.attempt.id)).toEqual([A]);
    const rows: AuditRecord[] = [];
    for (const x of unwrap(s.readAll())) if (!("invalid" in x)) rows.push(x);
    expect(rows).toContainEqual(
      expect.objectContaining({
        kind: "outcome",
        attemptId: A,
        outcome: "upstream_error",
        errorCode: "firewall.orphaned",
      }),
    );
    expect(verifications(s).map((v) => [v.attemptId, v.result, v.trigger])).toEqual([
      [A, "unknown", "startup"],
      [B, "happened", "startup"],
      [C, "not_happened", "startup"],
    ]);
    expect(rows.some((x) => "attemptId" in x && x.attemptId === D)).toBe(false);
    expect(rows.some((x) => x.kind === "verification" && x.attemptId === E)).toBe(false);
    expect(unwrap(s.verify()).ok).toBe(true);
    // Nothing is retried at startup: only read lookups.
  });

  it("an ambiguous tool error (upstream.tool_error) + absent ⇒ unknown + flagged at startup", async () => {
    const s = memStore();
    sentRefund(s, A, { outcome: "upstream_error", errorCode: "upstream.tool_error" });
    const r = unwrap(
      await reconcileAtStartup({
        store: s,
        verifier: createActionVerifier({ upstream: refundPages([[]]) }),
      }),
    );
    expect(r).toMatchObject({ notHappened: 0 });
    expect(r.unresolved.map((a) => a.attempt.id)).toEqual([A]);
    expect(verifications(s)).toEqual([
      expect.objectContaining({
        result: "unknown",
        needsHuman: true,
        errorCode: "verify.ambiguous_failure",
      }),
    ]);
    expect(startupFailureOf(REJECTED_ERROR_CODE)).toBe("definite_rejection");
    expect(startupFailureOf("upstream.tool_error")).toBe("ambiguous");
    expect(startupFailureOf("upstream.timeout")).toBe("none");
    expect(startupFailureOf(undefined)).toBe("none");
  });

  it(`${String(STARTUP_MAX_CONSECUTIVE_TIMEOUTS)} lookup timeouts in a row ⇒ upstream treated as down; the rest unknown without lookups`, async () => {
    const s = memStore();
    const ids = [A, B, C, D, E];
    for (const id of ids) sentRefund(s, id, { outcome: "timeout" });
    const slow = port(() => ({
      kind: "error",
      error: "upstream_timeout",
      message: "t",
      forwarded: true,
    }));
    const logs: string[] = [];
    const r = unwrap(
      await reconcileAtStartup({
        store: s,
        verifier: createActionVerifier({ upstream: slow }),
        logger: (l) => logs.push(l),
      }),
    );
    expect(slow.calls).toHaveLength(STARTUP_MAX_CONSECUTIVE_TIMEOUTS);
    expect(r.unresolved).toHaveLength(ids.length);
    expect(verifications(s).map((v) => v.errorCode)).toEqual([
      "verify.timeout",
      "verify.timeout",
      "verify.timeout",
      "verify.unavailable",
      "verify.unavailable",
    ]);
    expect(logs.join("\n")).toContain("timed out in a row");
  });

  it("a successful lookup resets the consecutive-timeout count", async () => {
    const s = memStore();
    const ids = [A, B, C, D, E];
    for (const id of ids) sentRefund(s, id, { outcome: "timeout" });
    let n = 0;
    const flaky = port(() => {
      n++;
      // timeout, timeout, ok, timeout, timeout
      return n === 3
        ? okJson({ entity: "collection", count: 0, items: [] })
        : { kind: "error", error: "upstream_timeout", message: "t", forwarded: true };
    });
    unwrap(
      await reconcileAtStartup({ store: s, verifier: createActionVerifier({ upstream: flaky }) }),
    );
    expect(flaky.calls).toHaveLength(5);
  });

  it("upstream down ⇒ every action unknown + flagged after ONE failed lookup; a re-run writes nothing new", async () => {
    const s = memStore();
    sentRefund(s, A, { outcome: "timeout" });
    sentRefund(s, B, { outcome: "timeout" });
    const down = port(() => ({
      kind: "error",
      error: "upstream_unavailable",
      message: "x",
      forwarded: false,
    }));
    const r = unwrap(
      await reconcileAtStartup({ store: s, verifier: createActionVerifier({ upstream: down }) }),
    );
    expect(r.unresolved).toHaveLength(2);
    expect(down.calls).toHaveLength(1);
    expect(verifications(s).map((v) => v.errorCode)).toEqual([
      "verify.unavailable",
      "verify.unavailable",
    ]);
    const again = unwrap(
      await reconcileAtStartup({ store: s, verifier: createActionVerifier({ upstream: down }) }),
    );
    expect(again.unresolved).toHaveLength(2);
    expect(verifications(s)).toHaveLength(2);
  });

  it("lookup budget ⇒ the rest are unknown (verify.budget)", async () => {
    const s = memStore();
    sentRefund(s, A, { outcome: "timeout" });
    sentRefund(s, B, { outcome: "timeout" });
    const p = refundPages([[]]);
    const r = unwrap(
      await reconcileAtStartup({
        store: s,
        verifier: createActionVerifier({ upstream: p }),
        lookupBudget: 1,
      }),
    );
    expect(p.calls).toHaveLength(1);
    expect(r.unresolved).toHaveLength(2);
    expect(verifications(s).map((v) => v.errorCode)).toEqual(["verify.not_found", "verify.budget"]);
  });

  it("row cap exceeded ⇒ err (caller latches degraded)", async () => {
    const s = memStore(3);
    sentRefund(s, A, { outcome: "timeout" });
    sentRefund(s, B, { outcome: "timeout" });
    const r = await reconcileAtStartup({
      store: s,
      verifier: createActionVerifier({ upstream: refundPages([[]]) }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("audit.scan_too_large");
  });
});
