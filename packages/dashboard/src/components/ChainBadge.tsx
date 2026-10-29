/**
 * Hash-chain integrity from `GET /audit/verify`. Distinct states: `ok` (green), `pending` (intact but some attempts
 * have no outcome yet — amber), `broken` (red, where), `error` (could not verify — amber, NEVER shown as ok).
 */
import type { VerifyView } from "../api/schemas";
import { displayId } from "../lib/untrusted";
import type { Tone } from "./Badges";

export type VerifyState =
  | { readonly state: "loading" }
  | { readonly state: "done"; readonly result: VerifyView; readonly at: string }
  | { readonly state: "error"; readonly message: string };

export type ChainStatus = "loading" | "ok" | "pending" | "broken" | "error";

export function chainStatus(verify: VerifyState): ChainStatus {
  if (verify.state !== "done") return verify.state;
  if (!verify.result.ok) return "broken";
  return verify.result.danglingAttempts > 0 ? "pending" : "ok";
}

const TONE: Record<ChainStatus, Tone> = {
  loading: "neutral",
  ok: "ok",
  pending: "warn",
  broken: "danger",
  error: "warn",
};

const TONE_CLASS: Record<Tone, string> = {
  neutral: "",
  ok: "chip-ok",
  danger: "chip-solid-danger",
  warn: "chip-warn",
  accent: "chip-accent",
};

export function ChainBadge({ verify, onRefresh }: { verify: VerifyState; onRefresh: () => void }) {
  const status = chainStatus(verify);
  let label: string;
  let title: string;
  if (verify.state === "loading") {
    label = "Chain: checking…";
    title = "Verifying the audit hash chain";
  } else if (verify.state === "error") {
    label = "Chain: unverified";
    title = `Could not verify the audit chain: ${verify.message}`;
  } else if (verify.result.ok && verify.result.danglingAttempts > 0) {
    label = `Chain OK · ${String(verify.result.danglingAttempts)} pending outcome`;
    title = `Verified at ${verify.at}. ${String(verify.result.danglingAttempts)} attempt(s) without outcome.`;
  } else if (verify.result.ok) {
    label = `Chain OK · ${String(verify.result.count)} records`;
    title = `Verified at ${verify.at}. Head ${verify.result.headHash?.slice(0, 12) ?? "-"}…`;
  } else {
    const b = verify.result.brokenAt;
    label = `Chain BROKEN at seq ${String(b.seq)}`;
    title = `Tamper evidence: ${displayId(b.reason)} at record ${b.id === null ? "?" : displayId(b.id)}`;
  }
  const tone = TONE[status];
  return (
    <button
      type="button"
      data-testid="chain-badge"
      data-state={status}
      data-tone={tone}
      onClick={onRefresh}
      title={`${title} (click to re-verify)`}
      className={`chip h-8 cursor-pointer px-3.5 ${TONE_CLASS[tone]} hover:brightness-110`}
    >
      <span
        aria-hidden="true"
        className={`h-1.5 w-1.5 rounded-full ${
          status === "ok"
            ? "bg-ok"
            : status === "broken"
              ? "bg-bg"
              : status === "loading"
                ? "bg-faint"
                : "bg-warn"
        }`}
      />
      {label}
    </button>
  );
}
