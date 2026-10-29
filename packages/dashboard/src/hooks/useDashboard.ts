/**
 * All dashboard data: initial audit page, the live `/events` stream (fetch-based SSE, reconnect with backoff, aborted
 * on unmount), pending approvals, mode and chain verification. Every event payload is zod-validated; a malformed one
 * is reported, not applied.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { describeError, type ApiClient } from "../api/client";
import {
  approvalsEventSchema,
  auditEventSchema,
  errorEventSchema,
  type ModeState,
  type RecordView,
} from "../api/schemas";
import type { ApprovalsLoad } from "../components/ApprovalsPanel";
import type { VerifyState } from "../components/ChainBadge";
import type { ModeLoad } from "../components/ModeControls";
import { runEventStream, type SseEvent, type StreamStatus } from "../lib/sse";
import { buildTimeline, mergeRecords, sessionIdsOf } from "../lib/timeline";

export const INITIAL_PAGE = 200;
const VERIFY_THROTTLE_MS = 5000;

function parseJson(data: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(data) };
  } catch (e: unknown) {
    console.warn(`asf: event is not JSON (${e instanceof Error ? e.name : "error"})`);
    return { ok: false };
  }
}

export function useDashboard(client: ApiClient) {
  const [records, setRecords] = useState<RecordView[]>([]);
  const [timelineError, setTimelineError] = useState<string | undefined>();
  const [streamError, setStreamError] = useState<string | undefined>();
  const [status, setStatus] = useState<StreamStatus>({ state: "connecting" });
  const [approvals, setApprovals] = useState<ApprovalsLoad>({ state: "loading" });
  const [mode, setMode] = useState<ModeLoad>({ state: "loading" });
  const [verify, setVerify] = useState<VerifyState>({ state: "loading" });
  const lastVerify = useRef(0);
  const verifySeq = useRef(0);
  const verifyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const loadApprovals = useCallback(async () => {
    const r = await client.getApprovals();
    setApprovals(
      r.ok
        ? { state: "ok", approvals: r.value }
        : { state: "error", message: describeError(r.error) },
    );
  }, [client]);

  const loadMode = useCallback(async () => {
    const r = await client.getMode();
    setMode(
      r.ok ? { state: "ok", mode: r.value } : { state: "error", message: describeError(r.error) },
    );
  }, [client]);

  const runVerify = useCallback(async () => {
    lastVerify.current = Date.now();
    // Only the newest request may set the badge: a slow older "ok" must not overwrite a newer "broken".
    verifySeq.current += 1;
    const mine = verifySeq.current;
    const r = await client.verify();
    if (mine !== verifySeq.current) return;
    setVerify(
      r.ok
        ? {
            state: "done",
            result: r.value,
            at: new Date().toLocaleTimeString("en-IN", { hour12: false }),
          }
        : { state: "error", message: describeError(r.error) },
    );
  }, [client]);

  /** Re-verify after new records, at most every VERIFY_THROTTLE_MS. */
  const scheduleVerify = useCallback(() => {
    if (verifyTimer.current !== undefined) return;
    const wait = Math.max(0, lastVerify.current + VERIFY_THROTTLE_MS - Date.now());
    verifyTimer.current = setTimeout(() => {
      verifyTimer.current = undefined;
      void runVerify();
    }, wait);
  }, [runVerify]);

  const loadAudit = useCallback(async () => {
    const r = await client.getAudit(INITIAL_PAGE);
    if (r.ok) {
      setTimelineError(undefined);
      setRecords((old) => mergeRecords(old, r.value.records));
    } else {
      setTimelineError(`Could not load the audit log: ${describeError(r.error)}`);
    }
  }, [client]);

  useEffect(() => {
    void loadAudit();
    void loadApprovals();
    void loadMode();
    void runVerify();
  }, [loadAudit, loadApprovals, loadMode, runVerify]);

  useEffect(() => {
    const ctrl = new AbortController();
    let opened = false;
    const onEvent = (e: SseEvent): void => {
      if (e.event === "ping") return;
      if (e.event === "ready") {
        setStreamError(undefined);
        // Catch up on anything that happened while disconnected.
        if (opened) {
          void loadAudit();
          void loadApprovals();
          void loadMode();
        }
        opened = true;
        return;
      }
      const json = parseJson(e.data);
      if (!json.ok) {
        setStreamError("Ignored a malformed live event.");
        return;
      }
      if (e.event === "audit") {
        const p = auditEventSchema.safeParse(json.value);
        if (!p.success) {
          setStreamError("Ignored a malformed live event (audit records failed validation).");
          return;
        }
        setRecords((old) => mergeRecords(old, p.data.records));
        if (p.data.records.some((r) => r.kind === "mode")) void loadMode();
        if (
          p.data.records.some(
            (r) =>
              r.kind === "approval" || (r.kind === "attempt" && r.decision === "require_approval"),
          )
        ) {
          void loadApprovals();
        }
        scheduleVerify();
      } else if (e.event === "approvals") {
        if (!approvalsEventSchema.safeParse(json.value).success) {
          setStreamError("Ignored a malformed live event (approvals).");
          return;
        }
        void loadApprovals();
      } else if (e.event === "error") {
        const p = errorEventSchema.safeParse(json.value);
        setStreamError(
          `The firewall reported a live-feed error: ${p.success ? p.data.code : "unknown"}. Data may be stale.`,
        );
      }
    };
    void runEventStream({
      url: `${client.baseUrl}/events`,
      token: client.token,
      signal: ctrl.signal,
      fetchImpl: client.fetchImpl,
      onEvent,
      onStatus: setStatus,
    });
    return () => {
      ctrl.abort();
      if (verifyTimer.current !== undefined) clearTimeout(verifyTimer.current);
      verifyTimer.current = undefined;
    };
  }, [client, loadAudit, loadApprovals, loadMode, scheduleVerify]);

  const entries = useMemo(() => buildTimeline(records), [records]);
  const sessionIds = useMemo(() => sessionIdsOf(records), [records]);

  return {
    entries,
    sessionIds,
    status,
    timelineError: timelineError ?? streamError,
    approvals,
    mode,
    verify,
    reloadApprovals: () => {
      void loadApprovals();
    },
    refreshVerify: () => {
      void runVerify();
    },
    setModeState: (m: ModeState) => {
      setMode({ state: "ok", mode: m });
    },
  };
}
