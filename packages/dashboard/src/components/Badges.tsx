import type { ReactNode } from "react";
import type { DecisionKind } from "../api/schemas";
import { formatPaise } from "../lib/money";

const DECISION_STYLE: Record<DecisionKind, string> = {
  allow:
    "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
  deny: "border-red-400 bg-red-100 text-red-800 dark:border-red-700 dark:bg-red-950 dark:text-red-300",
  require_approval:
    "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-700 dark:bg-sky-950 dark:text-sky-300",
  transform:
    "border-violet-300 bg-violet-50 text-violet-800 dark:border-violet-700 dark:bg-violet-950 dark:text-violet-300",
};

const DECISION_LABEL: Record<DecisionKind, string> = {
  allow: "allow",
  deny: "deny",
  require_approval: "approval",
  transform: "transform",
};

/** Shadow "would" labels: short enough to fit the timeline's badge column, and read as a sentence. */
const WOULD_LABEL: Record<DecisionKind, string> = {
  allow: "would allow",
  deny: "would deny",
  require_approval: "would ask",
  transform: "would modify",
};

const WOULD_TITLE: Record<DecisionKind, string> = {
  allow: "allow",
  deny: "deny",
  require_approval: "require human approval",
  transform: "transform the arguments",
};

const pill = "inline-block rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap";

export function DecisionBadge({
  decision,
  wouldDecision,
}: {
  decision: DecisionKind;
  wouldDecision?: DecisionKind | undefined;
}) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className={`${pill} ${DECISION_STYLE[decision]}`}>{DECISION_LABEL[decision]}</span>
      {wouldDecision !== undefined && (
        <span
          title={`Shadow mode: the policy would ${WOULD_TITLE[wouldDecision]}, but it was NOT enforced`}
          className={`${pill} border-dashed ${DECISION_STYLE[wouldDecision]}`}
        >
          {WOULD_LABEL[wouldDecision]}
        </span>
      )}
    </span>
  );
}

export function Amount({ amountPaise }: { amountPaise: number | undefined }) {
  if (amountPaise === undefined) return <span className="text-slate-400">—</span>;
  const s = formatPaise(amountPaise);
  if (s === undefined) return <span className="text-red-600">invalid amount</span>;
  return (
    <span className="font-semibold tabular-nums" title={`${String(amountPaise)} paise`}>
      {s}
    </span>
  );
}

export function Chip({
  children,
  tone = "slate",
}: {
  children: ReactNode;
  tone?: "slate" | "red" | "amber" | "emerald";
}) {
  const tones = {
    slate: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    red: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
    amber: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
    emerald: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  } as const;
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs ${tones[tone]}`}>{children}</span>
  );
}
