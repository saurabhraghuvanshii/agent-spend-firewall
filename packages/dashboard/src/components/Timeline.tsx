/**
 * Live timeline of money actions: time, tool, ₹ amount, agent reason (untrusted), decision badge (with shadow
 * "would" decision), matched rules, outcome. Denials are red; shadow "would deny" is amber.
 */
import type { OutcomeView } from "../api/schemas";
import type { StreamStatus } from "../lib/sse";
import { formatTime, type AttemptEntry, type TimelineEntry } from "../lib/timeline";
import { displayId } from "../lib/untrusted";
import { Amount, Chip, DecisionBadge } from "./Badges";
import { UntrustedArgs, UntrustedReason } from "./Untrusted";

const OUTCOME_TONE: Record<OutcomeView["outcome"], "slate" | "red" | "amber" | "emerald"> = {
  success: "emerald",
  denied: "red",
  not_forwarded: "slate",
  timeout: "amber",
  upstream_error: "amber",
};

export function StreamIndicator({ status }: { status: StreamStatus }) {
  const map: Record<StreamStatus["state"], { dot: string; text: string }> = {
    connecting: { dot: "bg-slate-400", text: "connecting…" },
    open: { dot: "bg-emerald-500", text: "live" },
    reconnecting: { dot: "bg-amber-500", text: "reconnecting" },
    unauthorized: { dot: "bg-red-500", text: "unauthorized" },
    stopped: { dot: "bg-slate-400", text: "stopped" },
  };
  const m = map[status.state];
  const title =
    status.state === "reconnecting"
      ? `${status.reason}; retrying in ${String(Math.round(status.delayMs / 1000))} s`
      : status.state === "unauthorized"
        ? `HTTP ${String(status.status)}: check the admin token`
        : m.text;
  return (
    <span
      data-testid="stream-status"
      className="inline-flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400"
      title={title}
    >
      <span className={`h-2 w-2 rounded-full ${m.dot}`} aria-hidden="true" />
      {m.text}
    </span>
  );
}

export function AttemptRow({
  entry,
  onPickSession,
  compact = false,
}: {
  entry: AttemptEntry;
  onPickSession?: (id: string) => void;
  /** Stacked two-column layout for narrow containers (the replay sidebar), regardless of viewport width. */
  compact?: boolean;
}) {
  const a = entry.attempt;
  const rulesText = a.matchedRules.map(displayId).join(", ");
  // Full: fixed column widths so badges / rules line up across rows whatever the amount width.
  const wide = (cls: string): string => (compact ? "" : cls);
  const denied = a.decision === "deny";
  const wouldDeny = a.shadow === true && a.wouldDecision === "deny";
  const tone = denied
    ? "border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/60"
    : wouldDeny
      ? "border-dashed border-amber-400 bg-amber-50/60 dark:border-amber-700 dark:bg-amber-950/40"
      : "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900";
  return (
    <li
      data-testid="timeline-row"
      data-decision={a.decision}
      data-variant={compact ? "compact" : "full"}
      className={`rounded-md border p-3 ${tone}`}
    >
      <div
        className={`grid grid-cols-2 items-center gap-x-3 gap-y-1 text-sm ${wide("md:grid-cols-[4.5rem_minmax(0,1fr)_7rem_8rem_minmax(0,1.4fr)_6rem]")}`}
      >
        <time
          dateTime={a.ts}
          title={a.ts}
          className="text-xs text-slate-500 tabular-nums dark:text-slate-400"
        >
          {formatTime(a.ts)}
        </time>
        <span
          className={`truncate text-right font-mono font-semibold ${wide("md:text-left")}`}
          title={displayId(a.tool)}
        >
          {displayId(a.tool)}
        </span>
        <span className={wide("md:text-right")}>
          <Amount amountPaise={a.amountPaise} />
        </span>
        <span className={`text-right ${wide("md:text-left")}`}>
          <DecisionBadge decision={a.decision} wouldDecision={a.wouldDecision} />
        </span>
        <span
          data-testid="matched-rules"
          title={a.matchedRules.length === 0 ? undefined : rulesText}
          className={`col-span-2 font-mono text-xs break-words text-slate-600 dark:text-slate-300 ${wide("md:col-span-1 md:truncate")}`}
        >
          {a.matchedRules.length === 0 ? (
            <span className="text-slate-400">no rule matched</span>
          ) : (
            <span className={denied ? "font-semibold text-red-700 dark:text-red-300" : ""}>
              {rulesText}
            </span>
          )}
        </span>
        <span className={`col-span-2 flex flex-wrap gap-1 ${wide("md:col-span-1 md:justify-end")}`}>
          {entry.approval !== undefined && <Chip tone="amber">{entry.approval.decision}</Chip>}
          {entry.outcome !== undefined && (
            <Chip tone={OUTCOME_TONE[entry.outcome.outcome]}>{entry.outcome.outcome}</Chip>
          )}
          {entry.verification !== undefined && (
            <Chip tone={entry.verification.result === "unknown" ? "amber" : "slate"}>
              verified: {entry.verification.result}
            </Chip>
          )}
        </span>
      </div>
      <div className="mt-2 text-sm">
        <UntrustedReason reason={a.reason} />
      </div>
      <details className="mt-1 text-xs text-slate-500 dark:text-slate-400">
        <summary className="cursor-pointer select-none">
          details · session <span className="font-mono">{displayId(a.sessionId)}</span>
        </summary>
        <div className="mt-2 flex flex-col gap-2">
          <UntrustedArgs
            args={a.argsRedacted}
            title={a.originalArgsRedacted === undefined ? "Arguments" : "Forwarded arguments"}
          />
          {a.originalArgsRedacted !== undefined && (
            <UntrustedArgs args={a.originalArgsRedacted} title="Agent's original arguments" />
          )}
          {a.approver !== undefined && <span>approver {displayId(a.approver)}</span>}
          {entry.outcome?.errorCode !== undefined && (
            <span>error {displayId(entry.outcome.errorCode)}</span>
          )}
          {onPickSession !== undefined && (
            <button
              type="button"
              onClick={() => {
                onPickSession(a.sessionId);
              }}
              className="self-start text-sky-700 underline-offset-2 hover:underline dark:text-sky-300"
            >
              Replay this session
            </button>
          )}
        </div>
      </details>
    </li>
  );
}

function SystemRow({ entry }: { entry: Exclude<TimelineEntry, AttemptEntry> }) {
  if (entry.kind === "invalid") {
    return (
      <li className="rounded-md border border-red-400 bg-red-50 p-2 text-sm text-red-800 dark:bg-red-950 dark:text-red-300">
        Invalid audit row at seq {entry.seq} (could not be parsed by the firewall)
      </li>
    );
  }
  const r = entry.record;
  return (
    <li className="flex flex-wrap items-center gap-2 rounded-md border border-slate-200 bg-slate-100 px-3 py-2 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-800/50 dark:text-slate-300">
      <time dateTime={r.ts} title={r.ts} className="tabular-nums">
        {formatTime(r.ts)}
      </time>
      <span className="font-semibold">Mode change</span>
      <span>kill switch {r.killSwitch ? "ON" : "off"}</span>·
      <span>{r.shadow ? "shadow" : "enforce"}</span>
      <span>by {displayId(r.actor)}</span>
    </li>
  );
}

export function Timeline({
  entries,
  status,
  error,
  onPickSession,
}: {
  entries: readonly TimelineEntry[];
  status: StreamStatus;
  error: string | undefined;
  onPickSession: (id: string) => void;
}) {
  return (
    <section aria-labelledby="timeline-title" className="min-w-0">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 id="timeline-title" className="text-base font-semibold">
          Live timeline
        </h2>
        <StreamIndicator status={status} />
      </div>
      {error !== undefined && (
        <p
          role="alert"
          className="mb-3 rounded-md border border-red-300 bg-red-50 p-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-300"
        >
          {error}
        </p>
      )}
      {entries.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">No money actions yet.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {entries.map((e) =>
            e.kind === "attempt" ? (
              <AttemptRow key={e.seq} entry={e} onPickSession={onPickSession} />
            ) : (
              <SystemRow key={e.seq} entry={e} />
            ),
          )}
        </ul>
      )}
    </section>
  );
}
