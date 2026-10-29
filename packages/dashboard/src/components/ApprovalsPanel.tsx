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

  const count = approvals.state === "ok" ? approvals.approvals.length : undefined;
  return (
    <section aria-labelledby="approvals-title" className="card">
      <div className="card-head">
        <div className="min-w-0">
          <p className="eyebrow">Waiting for a human</p>
          <h2 id="approvals-title" className="card-title mt-1.5">
            Pending <em>approvals</em>
            {count !== undefined && (
              <span
                className={`ml-3 inline-flex h-6 min-w-6 items-center justify-center rounded-full px-2 align-middle font-mono text-xs not-italic ${
                  count > 0 ? "bg-accent text-accent-ink" : "border border-line-strong text-muted"
                }`}
              >
                {count}
              </span>
            )}
          </h2>
        </div>
        <button type="button" onClick={onReload} className="btn-link">
          Refresh
        </button>
      </div>
      <div className="px-5 py-4">
        {disabled && (
          <p
            role="status"
            className="mb-4 border border-accent/50 bg-accent/10 p-3 text-sm leading-relaxed"
          >
            <strong className="font-medium">Approve via Telegram:</strong> dashboard approvals are
            turned off on this firewall (set{" "}
            <code className="font-mono text-xs">ASF_API_APPROVALS=1</code> on the proxy host to
            enable them).
          </p>
        )}
        {approvals.state === "loading" && <p className="text-sm text-muted">Loading…</p>}
        {approvals.state === "error" && (
          <p role="alert" className="text-sm break-words text-danger">
            Could not load approvals: {approvals.message}
          </p>
        )}
        {approvals.state === "ok" && approvals.approvals.length === 0 && (
          <p className="py-4 font-display text-xl text-muted italic">
            Nothing waiting for a human.
          </p>
        )}
        {approvals.state === "ok" && approvals.approvals.length > 0 && (
          <ul className="flex flex-col gap-4">
            {approvals.approvals.map((a) => {
              const st = rows[a.approvalId];
              const busy = st?.state === "busy";
              return (
                <li
                  key={a.approvalId}
                  data-testid="approval"
                  className="relative min-w-0 border border-line bg-bg/60 p-4"
                >
                  <span aria-hidden="true" className="absolute inset-x-0 top-0 h-[2px] bg-accent" />
                  <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                    <span
                      className="min-w-0 truncate font-mono text-[13px] font-medium"
                      title={displayId(a.tool)}
                    >
                      {displayId(a.tool)}
                    </span>
                    <Amount amountPaise={a.amountPaise} size="lg" />
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs text-muted">
                    <dt className="text-faint">rule</dt>
                    <dd className="truncate font-mono" title={displayId(a.ruleId)}>
                      {displayId(a.ruleId)}
                    </dd>
                    <dt className="text-faint">session</dt>
                    <dd className="truncate font-mono" title={displayId(a.sessionId)}>
                      {displayId(a.sessionId)}
                    </dd>
                    <dt className="text-faint">expires</dt>
                    <dd className="font-mono">{formatTime(a.expiresAt)}</dd>
                  </dl>
                  <div className="mt-3 text-sm">
                    <UntrustedReason reason={a.reason} />
                  </div>
                  <div className="mt-3">
                    <UntrustedArgs args={a.argsRedacted} title="Arguments" />
                  </div>
                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={busy || disabled}
                      onClick={() => {
                        setConfirming(a);
                      }}
                      className="btn-primary"
                    >
                      {busy && st.action === "approve" ? "Approving…" : "Approve"}
                    </button>
                    <button
                      type="button"
                      disabled={busy || disabled}
                      onClick={() => {
                        void decide(a, "reject");
                      }}
                      className="btn-danger"
                    >
                      {busy && st.action === "reject" ? "Rejecting…" : "Reject"}
                    </button>
                    {disabled && <span className="chip chip-accent">Approve via Telegram</span>}
                  </div>
                  {st?.state === "error" && (
                    <p
                      role="alert"
                      className="mt-3 border-l-2 border-danger pl-3 text-sm break-words text-danger"
                    >
                      {st.message}
                    </p>
                  )}
                  {st?.state === "done" && (
                    <p role="status" className="mt-3 border-l-2 border-ok pl-3 text-sm text-ok">
                      {st.message}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
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
          <span className="font-mono text-fg">{displayId(confirming.tool)}</span> for{" "}
          <strong className="font-mono font-medium text-fg">
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
