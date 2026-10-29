/**
 * Firewall mode (enforce / shadow) and the kill switch, as switches. Both changes need a confirm; the UI only shows
 * the new state once the API confirmed it (no optimistic toggle) and shows every failure. An unreadable mode is
 * shown as unknown (switch disabled), never as "off".
 */
import { useState } from "react";
import { describeError, type ApiClient, type ApiResult } from "../api/client";
import type { ModeState } from "../api/schemas";
import { ConfirmDialog } from "./ConfirmDialog";
import { Switch } from "./Switch";

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
    <>
      <Switch
        testId="mode-toggle"
        label="Shadow mode"
        stateText={
          shadow === undefined ? "unknown" : shadow ? "on · observe only" : "off · enforcing"
        }
        checked={shadow}
        tone="warn"
        onToggle={() => {
          setPending({ kind: "mode", mode: shadow === true ? "enforce" : "shadow" });
        }}
      />
      <Switch
        testId="kill-switch"
        label="Kill switch"
        stateText={kill === undefined ? "unknown" : kill ? "ON · all blocked" : "off"}
        checked={kill}
        tone="danger"
        onToggle={() => {
          setPending({ kind: "kill", on: kill !== true });
        }}
      />
      {mode.state === "error" && (
        <span role="alert" className="basis-full text-xs text-danger">
          Mode unreadable: {mode.message}
        </span>
      )}
      {error !== undefined && (
        <span role="alert" className="basis-full text-xs break-words text-danger">
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
    </>
  );
}
