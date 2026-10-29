/**
 * Joins audit records into timeline entries: one per `attempt` (newest first) with the outcome / approval /
 * verification records that reference it, plus `mode` changes and `invalid` rows as their own entries.
 */
import type {
  ApprovalRecordView,
  AttemptView,
  InvalidView,
  ModeRecordView,
  OutcomeView,
  RecordView,
  VerificationView,
} from "../api/schemas";

export interface AttemptEntry {
  readonly kind: "attempt";
  readonly seq: number;
  readonly attempt: AttemptView;
  readonly outcome?: OutcomeView;
  readonly approval?: ApprovalRecordView;
  readonly verification?: VerificationView;
}

export type TimelineEntry =
  | AttemptEntry
  | { readonly kind: "mode"; readonly seq: number; readonly record: ModeRecordView }
  | { readonly kind: "invalid"; readonly seq: number; readonly record: InvalidView };

/** Merge `incoming` into `existing` by seq (dedupe), keep at most `max` newest. Returned newest first. */
export function mergeRecords(
  existing: readonly RecordView[],
  incoming: readonly RecordView[],
  max = 1000,
): RecordView[] {
  const bySeq = new Map<number, RecordView>();
  for (const r of existing) bySeq.set(r.seq, r);
  for (const r of incoming) bySeq.set(r.seq, r);
  return [...bySeq.values()].sort((a, b) => b.seq - a.seq).slice(0, max);
}

export function buildTimeline(records: readonly RecordView[]): TimelineEntry[] {
  const outcomes = new Map<string, OutcomeView>();
  const approvals = new Map<string, ApprovalRecordView>();
  const verifications = new Map<string, VerificationView>();
  const ordered = [...records].sort((a, b) => a.seq - b.seq);
  for (const r of ordered) {
    // Oldest first, so the latest related record wins.
    if (r.kind === "outcome") outcomes.set(r.attemptId, r);
    else if (r.kind === "approval") approvals.set(r.attemptId, r);
    else if (r.kind === "verification") verifications.set(r.attemptId, r);
  }
  const out: TimelineEntry[] = [];
  for (const r of ordered) {
    if (r.kind === "attempt") {
      const outcome = outcomes.get(r.id);
      const approval = approvals.get(r.id);
      const verification = verifications.get(r.id);
      out.push({
        kind: "attempt",
        seq: r.seq,
        attempt: r,
        ...(outcome === undefined ? {} : { outcome }),
        ...(approval === undefined ? {} : { approval }),
        ...(verification === undefined ? {} : { verification }),
      });
    } else if (r.kind === "mode") out.push({ kind: "mode", seq: r.seq, record: r });
    else if (r.kind === "invalid") out.push({ kind: "invalid", seq: r.seq, record: r });
  }
  return out.reverse();
}

/** Attempts only, oldest first (session replay order). */
export function attemptsOf(entries: readonly TimelineEntry[]): AttemptEntry[] {
  return entries.filter((e): e is AttemptEntry => e.kind === "attempt").reverse();
}

/** Distinct session ids, most recently active first. */
export function sessionIdsOf(records: readonly RecordView[]): string[] {
  const seen = new Set<string>();
  for (const r of [...records].sort((a, b) => b.seq - a.seq)) {
    if (r.kind === "attempt") seen.add(r.sessionId);
  }
  return [...seen];
}

export function formatTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "invalid time";
  return d.toLocaleTimeString("en-IN", { hour12: false });
}
