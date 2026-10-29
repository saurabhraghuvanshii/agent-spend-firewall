/**
 * Pending approvals with approve / reject. Never optimistic: an approval leaves the list only when the API reports a
 * decision and the list is re-fetched. Known failures get plain explanations:
 * - 403 `api.approvals_disabled` ⇒ "Approve via Telegram" (dashboard approvals are off by default, D-036);
 * - 409 `kill-switch` ⇒ the approval stays pending until the kill switch is off;
 * - 409 expired / already decided, 404, 5xx, network, malformed ⇒ the error, verbatim.
 */
import { useState } from "react";
import { describeError, type ApiClient, type ApiError } from "../api/client";
import type { PendingApproval } from "../api/schemas";
import { formatPaise } from "../lib/money";
import { formatTime } from "../lib/timeline";
import { displayId } from "../lib/untrusted";
import { Amount } from "./Badges";
import { ConfirmDialog } from "./ConfirmDialog";
import { UntrustedArgs, UntrustedReason } from "./Untrusted";

export type ApprovalsLoad =
  | { readonly state: "loading" }
  | { readonly state: "ok"; readonly approvals: readonly PendingApproval[] }
  | { readonly state: "error"; readonly message: string };

type RowStatus =
  | { readonly state: "busy"; readonly action: "approve" | "reject" }
  | { readonly state: "error"; readonly message: string }
  | { readonly state: "done"; readonly message: string };

export function explainDecisionError(e: ApiError): string {
  if (e.kind === "http") {
    if (e.status === 403 && e.code === "api.approvals_disabled") {
      return "Dashboard approvals are disabled on this firewall. Approve via Telegram.";
    }
    if (e.status === 409 && e.code === "kill-switch") {
      return "The kill switch is ON: the approval was left pending. Turn the kill switch off first.";
    }
  }
  return describeError(e);
}

export function ApprovalsPanel({
  client,
  approvals,
  onReload,
}: {
  client: ApiClient;
  approvals: ApprovalsLoad;
  onReload: () => void;
}) {
  const [rows, setRows] = useState<Record<string, RowStatus>>({});
  const [disabled, setDisabled] = useState(false);
  const [confirming, setConfirming] = useState<PendingApproval | undefined>();

  const decide = async (a: PendingApproval, action: "approve" | "reject"): Promise<void> => {
    setRows((r) => ({ ...r, [a.approvalId]: { state: "busy", action } }));
    const res = await client.decide(a.approvalId, action);
    if (res.ok) {
      setRows((r) => ({ ...r, [a.approvalId]: { state: "done", message: res.value.message } }));
      onReload();
      return;
    }
    if (res.error.kind === "http" && res.error.code === "api.approvals_disabled") setDisabled(true);
    const message = explainDecisionError(res.error);
    setRows((r) => ({ ...r, [a.approvalId]: { state: "error", message } }));
  };

  return (
    <section
      aria-labelledby="approvals-title"
      className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 id="approvals-title" className="text-base font-semibold">
          Pending approvals
          {approvals.state === "ok" && (
            <span className="ml-2 rounded-full bg-sky-100 px-2 py-0.5 text-xs text-sky-800 dark:bg-sky-950 dark:text-sky-300">
              {approvals.approvals.length}
            </span>
          )}
        </h2>
        <button
          type="button"
          onClick={onReload}
          className="text-xs text-slate-500 underline-offset-2 hover:underline dark:text-slate-400"
        >
          Refresh
        </button>
      </div>
      {disabled && (
        <p
          role="status"
          className="mb-3 rounded-md border border-sky-300 bg-sky-50 p-2 text-sm text-sky-900 dark:border-sky-700 dark:bg-sky-950 dark:text-sky-200"
        >
          Approve via Telegram: dashboard approvals are turned off on this firewall (set{" "}
          <code>ASF_API_APPROVALS=1</code> on the proxy host to enable them).
        </p>
      )}
      {approvals.state === "loading" && <p className="text-sm text-slate-500">Loading…</p>}
      {approvals.state === "error" && (
        <p role="alert" className="text-sm text-red-700 dark:text-red-300">
          Could not load approvals: {approvals.message}
        </p>
      )}
      {approvals.state === "ok" && approvals.approvals.length === 0 && (
        <p className="text-sm text-slate-500 dark:text-slate-400">Nothing waiting for a human.</p>
      )}
      {approvals.state === "ok" && approvals.approvals.length > 0 && (
        <ul className="flex flex-col gap-3">
          {approvals.approvals.map((a) => {
            const st = rows[a.approvalId];
            const busy = st?.state === "busy";
            return (
              <li
                key={a.approvalId}
                data-testid="approval"
                className="rounded-md border border-sky-200 p-3 dark:border-sky-900"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="font-mono text-sm font-semibold">{displayId(a.tool)}</span>
                  <Amount amountPaise={a.amountPaise} />
                </div>
                <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  rule <span className="font-mono">{displayId(a.ruleId)}</span> · session{" "}
                  <span className="font-mono">{displayId(a.sessionId)}</span> · expires{" "}
                  {formatTime(a.expiresAt)}
                </div>
                <div className="mt-2 text-sm">
                  <UntrustedReason reason={a.reason} />
                </div>
                <div className="mt-2">
                  <UntrustedArgs args={a.argsRedacted} title="Arguments" />
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={busy || disabled}
                    onClick={() => {
                      setConfirming(a);
                    }}
                    className="rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                  >
                    {busy && st.action === "approve" ? "Approving…" : "Approve"}
                  </button>
                  <button
                    type="button"
                    disabled={busy || disabled}
                    onClick={() => {
                      void decide(a, "reject");
                    }}
                    className="rounded-md border border-red-400 px-3 py-1.5 text-sm font-semibold text-red-700 hover:bg-red-50 disabled:opacity-50 dark:text-red-300 dark:hover:bg-red-950"
                  >
                    {busy && st.action === "reject" ? "Rejecting…" : "Reject"}
                  </button>
                  {disabled && (
                    <span className="text-xs text-sky-800 dark:text-sky-300">
                      Approve via Telegram
                    </span>
                  )}
                </div>
                {st?.state === "error" && (
                  <p role="alert" className="mt-2 text-sm text-red-700 dark:text-red-300">
                    {st.message}
                  </p>
                )}
                {st?.state === "done" && (
                  <p role="status" className="mt-2 text-sm text-emerald-700 dark:text-emerald-300">
                    {st.message}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {confirming !== undefined && (
        <ConfirmDialog
          title="Approve this money action?"
          confirmLabel="Approve"
          onCancel={() => {
            setConfirming(undefined);
          }}
          onConfirm={() => {
            const a = confirming;
            setConfirming(undefined);
            void decide(a, "approve");
          }}
        >
          <span className="font-mono">{displayId(confirming.tool)}</span> for{" "}
          <strong>
            {confirming.amountPaise === undefined
              ? "an unknown amount"
              : (formatPaise(confirming.amountPaise) ?? "an invalid amount")}
          </strong>
          . The firewall re-checks the policy and the kill switch before executing.
        </ConfirmDialog>
      )}
    </section>
  );
}
