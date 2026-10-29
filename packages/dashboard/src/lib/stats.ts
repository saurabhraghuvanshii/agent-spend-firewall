/**
 * Numbers for the header ticker, computed by the dashboard itself from validated records. Output strings are built
 * only from integers, enums and fixed words — never from agent-supplied text.
 */
import type { ChainStatus } from "../components/ChainBadge";
import { formatPaise } from "./money";
import type { TimelineEntry } from "./timeline";

export interface TickerStats {
  /** Paise of enforced denials whose attempt is from today (local time). */
  readonly blockedPaiseToday: bigint;
  readonly deniedToday: number;
  readonly allowedToday: number;
  readonly actionsToday: number;
  readonly pendingApprovals: number | undefined;
  readonly chain: ChainStatus;
  readonly shadow: boolean | undefined;
  readonly killSwitch: boolean | undefined;
}

const sameLocalDay = (ts: string, now: Date): boolean => {
  const d = new Date(ts);
  return (
    !Number.isNaN(d.getTime()) &&
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  );
};

export function computeStats(
  entries: readonly TimelineEntry[],
  extra: Pick<TickerStats, "pendingApprovals" | "chain" | "shadow" | "killSwitch">,
  now: Date = new Date(),
): TickerStats {
  let blocked = 0n;
  let denied = 0;
  let allowed = 0;
  let actions = 0;
  for (const e of entries) {
    if (e.kind !== "attempt" || !sameLocalDay(e.attempt.ts, now)) continue;
    actions += 1;
    if (e.attempt.decision === "deny") {
      denied += 1;
      blocked += BigInt(e.attempt.amountPaise ?? 0);
    } else if (e.attempt.decision === "allow") allowed += 1;
  }
  return {
    blockedPaiseToday: blocked,
    deniedToday: denied,
    allowedToday: allowed,
    actionsToday: actions,
    ...extra,
  };
}

const CHAIN_TEXT: Record<ChainStatus, string> = {
  loading: "chain checking",
  ok: "chain OK",
  pending: "chain OK, outcomes pending",
  broken: "chain BROKEN",
  error: "chain unverified",
};

export function tickerItems(s: TickerStats): string[] {
  return [
    `${formatPaise(s.blockedPaiseToday) ?? "₹0.00"} blocked today`,
    `${String(s.deniedToday)} denied`,
    `${String(s.allowedToday)} allowed`,
    `${String(s.actionsToday)} money actions today`,
    s.pendingApprovals === undefined
      ? "approvals unknown"
      : `${String(s.pendingApprovals)} pending approval`,
    CHAIN_TEXT[s.chain],
    s.killSwitch === undefined
      ? "kill switch unknown"
      : s.killSwitch
        ? "KILL SWITCH ON"
        : "kill switch off",
    s.shadow === undefined ? "mode unknown" : s.shadow ? "shadow mode" : "enforcing",
    "Razorpay test mode",
  ];
}
