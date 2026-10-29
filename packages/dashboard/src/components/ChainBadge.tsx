/**
 * Hash-chain integrity from `GET /audit/verify`. Three distinct states: `ok` (green), `broken` (red, where), `error`
 * (could not verify — amber, NEVER shown as ok). Loading is neutral.
 */
import type { VerifyView } from "../api/schemas";
import { displayId } from "../lib/untrusted";

export type VerifyState =
  | { readonly state: "loading" }
  | { readonly state: "done"; readonly result: VerifyView; readonly at: string }
  | { readonly state: "error"; readonly message: string };

export function ChainBadge({ verify, onRefresh }: { verify: VerifyState; onRefresh: () => void }) {
  let cls: string;
  let label: string;
  let title: string;
  if (verify.state === "loading") {
    cls = "border-slate-300 text-slate-600 dark:border-slate-600 dark:text-slate-300";
    label = "Chain: checking…";
    title = "Verifying the audit hash chain";
  } else if (verify.state === "error") {
    cls = "border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-200";
    label = "Chain: unverified";
    title = `Could not verify the audit chain: ${verify.message}`;
  } else if (verify.result.ok && verify.result.danglingAttempts > 0) {
    // Intact chain, but some money actions have no recorded outcome yet: not all-clear.
    cls = "border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-200";
    label = `Chain OK · ${String(verify.result.danglingAttempts)} pending outcome`;
    title = `Verified at ${verify.at}. ${String(verify.result.danglingAttempts)} attempt(s) without outcome.`;
  } else if (verify.result.ok) {
    cls =
      "border-emerald-500 bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300";
    label = `Chain OK · ${String(verify.result.count)} records`;
    title = `Verified at ${verify.at}. Head ${verify.result.headHash?.slice(0, 12) ?? "-"}…`;
  } else {
    const b = verify.result.brokenAt;
    cls = "border-red-500 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300";
    label = `Chain BROKEN at seq ${String(b.seq)}`;
    title = `Tamper evidence: ${displayId(b.reason)} at record ${b.id === null ? "?" : displayId(b.id)}`;
  }
  return (
    <button
      type="button"
      data-testid="chain-badge"
      data-state={
        verify.state !== "done"
          ? verify.state
          : !verify.result.ok
            ? "broken"
            : verify.result.danglingAttempts > 0
              ? "pending"
              : "ok"
      }
      onClick={onRefresh}
      title={`${title} (click to re-verify)`}
      className={`rounded-full border px-3 py-1 text-xs font-semibold whitespace-nowrap ${cls}`}
    >
      {label}
    </button>
  );
}
