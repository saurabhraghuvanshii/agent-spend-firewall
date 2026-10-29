/**
 * Firewall mode (enforce / shadow) and the kill switch. Both changes need a confirm; the UI only shows the new state
 * once the API confirmed it (no optimistic toggle) and shows every failure. An unreadable mode is shown as unknown.
 */
import { useState } from "react";
import { describeError, type ApiClient, type ApiResult } from "../api/client";
import type { ModeState } from "../api/schemas";
import { ConfirmDialog } from "./ConfirmDialog";

export type ModeLoad =
  | { readonly state: "loading" }
  | { readonly state: "ok"; readonly mode: ModeState }
  | { readonly state: "error"; readonly message: string };

type Pending = { kind: "kill"; on: boolean } | { kind: "mode"; mode: "enforce" | "shadow" };

export function ModeControls({
  client,
  mode,
  onChanged,
}: {
  client: ApiClient;
  mode: ModeLoad;
  onChanged: (m: ModeState) => void;
}) {
  const [pending, setPending] = useState<Pending | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  const confirm = async (p: Pending): Promise<void> => {
    setBusy(true);
    setError(undefined);
    const r: ApiResult<ModeState> =
      p.kind === "kill" ? await client.setKillSwitch(p.on) : await client.setMode(p.mode);
    setBusy(false);
    setPending(undefined);
    if (r.ok) onChanged(r.value);
    else setError(`Change NOT applied: ${describeError(r.error)}`);
  };

  const known = mode.state === "ok" ? mode.mode : undefined;
  const kill = known?.killSwitch;
  const shadow = known?.shadow;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        data-testid="mode-toggle"
        disabled={known === undefined}
        onClick={() => {
          setPending({ kind: "mode", mode: shadow === true ? "enforce" : "shadow" });
        }}
        title="Shadow mode logs what the policy WOULD do but does not enforce it"
        className={`rounded-full border px-3 py-1 text-xs font-semibold whitespace-nowrap disabled:opacity-60 ${
          shadow === true
            ? "border-dashed border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-200"
            : "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200"
        }`}
      >
        Mode: {shadow === undefined ? "unknown" : shadow ? "SHADOW" : "enforce"}
      </button>
      <button
        type="button"
        role="switch"
        aria-checked={kill === true}
        data-testid="kill-switch"
        disabled={known === undefined}
        onClick={() => {
          setPending({ kind: "kill", on: kill !== true });
        }}
        className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold whitespace-nowrap disabled:opacity-60 ${
          kill === true
            ? "border-red-600 bg-red-600 text-white"
            : "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200"
        }`}
      >
        <span
          className={`h-2 w-2 rounded-full ${kill === true ? "bg-white" : "bg-slate-400"}`}
          aria-hidden="true"
        />
        Kill switch: {kill === undefined ? "unknown" : kill ? "ON" : "off"}
      </button>
      {mode.state === "error" && (
        <span role="alert" className="text-xs text-red-700 dark:text-red-300">
          Mode unreadable: {mode.message}
        </span>
      )}
      {error !== undefined && (
        <span role="alert" className="text-xs text-red-700 dark:text-red-300">
          {error}
        </span>
      )}
      {pending !== undefined && (
        <ConfirmDialog
          title={
            pending.kind === "kill"
              ? pending.on
                ? "Turn the kill switch ON?"
                : "Turn the kill switch off?"
              : pending.mode === "shadow"
                ? "Switch to SHADOW mode?"
                : "Switch to enforce mode?"
          }
          confirmLabel={
            pending.kind === "kill" ? (pending.on ? "Block all money actions" : "Resume") : "Switch"
          }
          danger={pending.kind === "kill" ? pending.on : pending.mode === "shadow"}
          busy={busy}
          onCancel={() => {
            setPending(undefined);
          }}
          onConfirm={() => {
            void confirm(pending);
          }}
        >
          {pending.kind === "kill"
            ? pending.on
              ? "Every money action will be denied until you turn it off. Pending approvals stay pending."
              : "Money actions will be evaluated by the policy again."
            : pending.mode === "shadow"
              ? "Policies will be OBSERVED ONLY: denials and approvals are logged as “would”, and money actions go through."
              : "Policies will be enforced again."}
        </ConfirmDialog>
      )}
    </div>
  );
}
