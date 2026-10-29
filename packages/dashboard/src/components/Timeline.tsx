/**
 * Live timeline of money actions: time, tool, ₹ amount, agent reason (untrusted), decision badge (with shadow
 * "would" decision), matched rules, outcome. Denials are red; shadow "would deny" is amber.
 */
import type { OutcomeView } from "../api/schemas";
import type { StreamStatus } from "../lib/sse";
import { formatTime, type AttemptEntry, type TimelineEntry } from "../lib/timeline";
import { displayId } from "../lib/untrusted";
import { Amount, Chip, DecisionBadge, type Tone } from "./Badges";
import { UntrustedArgs, UntrustedReason } from "./Untrusted";

const OUTCOME_TONE: Record<OutcomeView["outcome"], Tone> = {
  success: "ok",
  denied: "danger",
  not_forwarded: "neutral",
  timeout: "warn",
  upstream_error: "warn",
};

export function StreamIndicator({ status }: { status: StreamStatus }) {
  const map: Record<StreamStatus["state"], { dot: string; text: string }> = {
    connecting: { dot: "bg-faint", text: "connecting…" },
    open: { dot: "bg-ok", text: "live" },
    reconnecting: { dot: "bg-warn", text: "reconnecting" },
    unauthorized: { dot: "bg-danger", text: "unauthorized" },
    stopped: { dot: "bg-faint", text: "stopped" },
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
      className="inline-flex items-center gap-2 text-[10.5px] font-medium tracking-[0.12em] text-muted uppercase"
      title={title}
    >
      <span className="relative inline-flex h-2 w-2" aria-hidden="true">
        {status.state === "open" && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-50 motion-reduce:hidden" />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${m.dot}`} />
      </span>
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
    ? "row-deny bg-danger/[0.07]"
    : wouldDeny
      ? "row-would-deny bg-warn/[0.05]"
      : "";
  const bar = denied
    ? "bg-danger"
    : wouldDeny
      ? "bg-warn"
      : a.decision === "require_approval"
        ? "bg-accent"
        : "bg-transparent";
  return (
    <li
      data-testid="timeline-row"
      data-decision={a.decision}
      data-variant={compact ? "compact" : "full"}
      className={`relative min-w-0 py-4 pr-4 pl-5 ${tone}`}
    >
      <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-[3px] ${bar}`} />
      <div className={`grid grid-cols-2 items-center gap-x-3 gap-y-2 ${wide(COLS)}`}>
        <time
          dateTime={a.ts}
          title={a.ts}
          className="font-mono text-[11.5px] text-muted tabular-nums"
        >
          {formatTime(a.ts)}
        </time>
        <span
          className={`truncate text-right font-mono text-[13px] font-medium ${wide("md:text-left")}`}
          title={displayId(a.tool)}
        >
          {displayId(a.tool)}
        </span>
        <span className={wide("md:text-right")}>
          <Amount amountPaise={a.amountPaise} />
        </span>
        <span className={`min-w-0 text-right ${wide("md:text-left")}`}>
          <DecisionBadge decision={a.decision} wouldDecision={a.wouldDecision} />
        </span>
        <span
          data-testid="matched-rules"
          title={a.matchedRules.length === 0 ? undefined : rulesText}
          className={`col-span-2 flex min-w-0 flex-wrap gap-1 ${wide("md:col-span-1")}`}
        >
          {a.matchedRules.length === 0 ? (
            <span className="font-mono text-[11.5px] text-faint">no rule matched</span>
          ) : (
            a.matchedRules.map((r, i) => (
              <span
                key={`${String(i)}-${r}`}
                title={displayId(r)}
                className={`inline-block max-w-full truncate rounded-full border px-1.5 py-px font-mono text-[10px] leading-4 whitespace-nowrap ${
                  denied
                    ? "border-danger/50 bg-danger/10 text-danger"
                    : "border-line-strong text-muted"
                }`}
              >
                {displayId(r)}
              </span>
            ))
          )}
        </span>
        <span className={`col-span-2 flex flex-wrap gap-1 ${wide("md:col-span-1 md:justify-end")}`}>
          {entry.approval !== undefined && <Chip tone="accent">{entry.approval.decision}</Chip>}
          {entry.outcome !== undefined ? (
            <Chip tone={OUTCOME_TONE[entry.outcome.outcome]}>{entry.outcome.outcome}</Chip>
          ) : (
            <Chip tone="warn" title="No outcome recorded yet (awaiting approval or in flight)">
              pending
            </Chip>
          )}
          {entry.verification !== undefined && (
            <Chip tone={entry.verification.result === "unknown" ? "warn" : "neutral"}>
              verified: {entry.verification.result}
            </Chip>
          )}
        </span>
      </div>
      <div className="mt-3 text-sm">
        <UntrustedReason reason={a.reason} />
      </div>
      <details className="group mt-2 text-xs text-muted">
        <summary className="cursor-pointer list-none select-none hover:text-fg">
          <span className="mr-1 inline-block transition-transform group-open:rotate-90 motion-reduce:transition-none">
            ›
          </span>
          Details · session <span className="font-mono">{displayId(a.sessionId)}</span>
        </summary>
        <div className="mt-3 flex min-w-0 flex-col gap-3">
          <UntrustedArgs
            args={a.argsRedacted}
            title={a.originalArgsRedacted === undefined ? "Arguments" : "Forwarded arguments"}
          />
          {a.originalArgsRedacted !== undefined && (
            <UntrustedArgs args={a.originalArgsRedacted} title="Agent's original arguments" />
          )}
          {a.approver !== undefined && (
            <span>
              approver <span className="font-mono">{displayId(a.approver)}</span>
            </span>
          )}
          {entry.outcome?.errorCode !== undefined && (
            <span>
              error <span className="font-mono">{displayId(entry.outcome.errorCode)}</span>
            </span>
          )}
          {onPickSession !== undefined && (
            <button
              type="button"
              onClick={() => {
                onPickSession(a.sessionId);
              }}
              className="btn-secondary h-8 self-start px-3 text-xs"
            >
              Replay this session →
            </button>
          )}
        </div>
      </details>
    </li>
  );
}

/** Shared column template so the header, money rows and mode-change rows line up. */
const COLS = "md:grid-cols-[4.5rem_minmax(0,1fr)_7.5rem_10rem_minmax(0,1.35fr)_6.5rem]";

function SystemRow({ entry }: { entry: Exclude<TimelineEntry, AttemptEntry> }) {
  if (entry.kind === "invalid") {
    return (
      <li className="relative bg-danger/[0.08] py-3 pr-4 pl-5 text-sm text-danger">
        <span aria-hidden="true" className="absolute inset-y-0 left-0 w-[3px] bg-danger" />
        Invalid audit row at seq {entry.seq} (could not be parsed by the firewall)
      </li>
    );
  }
  const r = entry.record;
  return (
    <li className="bg-surface-2/60 py-2.5 pr-4 pl-5 text-xs text-muted">
      <div className={`grid grid-cols-2 items-center gap-x-3 gap-y-1.5 ${COLS}`}>
        <time dateTime={r.ts} title={r.ts} className="font-mono text-muted tabular-nums">
          {formatTime(r.ts)}
        </time>
        <span className="eyebrow text-muted">Mode change</span>
        <span aria-hidden="true" className="hidden md:block" />
        <span>
          <Chip tone={r.shadow ? "warn" : "neutral"}>{r.shadow ? "shadow" : "enforce"}</Chip>
        </span>
        <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <Chip tone={r.killSwitch ? "danger" : "neutral"}>
            kill switch {r.killSwitch ? "ON" : "off"}
          </Chip>
          <span className="truncate">
            by <span className="font-mono">{displayId(r.actor)}</span>
          </span>
        </span>
      </div>
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
    <section aria-labelledby="timeline-title" className="card">
      <div className="card-head">
        <div className="min-w-0">
          <p className="eyebrow">Every money action, newest first</p>
          <h2 id="timeline-title" className="card-title mt-1.5 text-3xl">
            Live <em>timeline</em>
          </h2>
        </div>
        <StreamIndicator status={status} />
      </div>
      {entries.length > 0 && (
        <div
          aria-hidden="true"
          className={`hidden ${COLS} gap-x-3 border-b border-line py-2 pr-4 pl-5 eyebrow md:grid`}
        >
          <span>Time</span>
          <span>Tool</span>
          <span className="text-right">Amount</span>
          <span>Decision</span>
          <span>Rules</span>
          <span className="text-right">Outcome</span>
        </div>
      )}
      {error !== undefined && (
        <p
          role="alert"
          className="mx-5 my-4 border border-danger/50 bg-danger/10 p-3 text-sm break-words text-danger"
        >
          {error}
        </p>
      )}
      {entries.length === 0 ? (
        <p className="px-5 py-12 text-center font-display text-2xl text-muted italic">
          No money actions yet.
        </p>
      ) : (
        <ul className="divide-y divide-line">
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
