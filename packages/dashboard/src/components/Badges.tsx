import type { ReactNode } from "react";
import type { DecisionKind } from "../api/schemas";
import { formatPaise } from "../lib/money";

export type Tone = "neutral" | "ok" | "danger" | "warn" | "accent";

const TONE_CLASS: Record<Tone, string> = {
  neutral: "",
  ok: "chip-ok",
  danger: "chip-danger",
  warn: "chip-warn",
  accent: "chip-accent",
};

export const DECISION_TONE: Record<DecisionKind, Tone> = {
  allow: "ok",
  deny: "danger",
  require_approval: "accent",
  transform: "warn",
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

export function Chip({
  children,
  tone = "neutral",
  dashed = false,
  title,
}: {
  children: ReactNode;
  tone?: Tone;
  dashed?: boolean;
  title?: string;
}) {
  return (
    <span
      data-tone={tone}
      title={title}
      className={`chip ${TONE_CLASS[tone]} ${dashed ? "chip-dashed" : ""}`}
    >
      {children}
    </span>
  );
}

export function DecisionBadge({
  decision,
  wouldDecision,
}: {
  decision: DecisionKind;
  wouldDecision?: DecisionKind | undefined;
}) {
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-1">
      <Chip tone={DECISION_TONE[decision]}>{DECISION_LABEL[decision]}</Chip>
      {wouldDecision !== undefined && (
        <Chip
          tone={DECISION_TONE[wouldDecision]}
          dashed
          title={`Shadow mode: the policy would ${WOULD_TITLE[wouldDecision]}, but it was NOT enforced`}
        >
          {WOULD_LABEL[wouldDecision]}
        </Chip>
      )}
    </span>
  );
}

export function Amount({
  amountPaise,
  size = "md",
}: {
  amountPaise: number | undefined;
  size?: "md" | "lg";
}) {
  if (amountPaise === undefined) return <span className="font-mono text-faint">—</span>;
  const s = formatPaise(amountPaise);
  if (s === undefined) return <span className="font-mono text-danger">invalid amount</span>;
  return (
    <span
      className={`font-mono font-medium tracking-tight tabular-nums ${size === "lg" ? "text-lg" : "text-sm"}`}
      title={`${String(amountPaise)} paise`}
    >
      {s}
    </span>
  );
}
