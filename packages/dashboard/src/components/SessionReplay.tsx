/** Session replay: pick a session, then step prev / next through its money actions (`GET /sessions/:id`). */
import { useEffect, useState } from "react";
import { describeError, SESSION_ID_RE, type ApiClient } from "../api/client";
import { formatPaise } from "../lib/money";
import { attemptsOf, buildTimeline, type AttemptEntry } from "../lib/timeline";
import { displayId } from "../lib/untrusted";
import { AttemptRow } from "./Timeline";

type Load =
  | { readonly state: "idle" }
  | { readonly state: "loading" }
  | { readonly state: "ok"; readonly steps: readonly AttemptEntry[]; readonly truncated: boolean }
  | { readonly state: "error"; readonly message: string };

export function SessionReplay({
  client,
  sessionIds,
  selected,
  onSelect,
}: {
  client: ApiClient;
  sessionIds: readonly string[];
  selected: string | undefined;
  onSelect: (id: string | undefined) => void;
}) {
  const [load, setLoad] = useState<Load>({ state: "idle" });
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (selected === undefined) {
      setLoad({ state: "idle" });
      return;
    }
    let live = true;
    setLoad({ state: "loading" });
    setStep(0);
    void client.getSession(selected).then((r) => {
      if (!live) return;
      if (!r.ok) {
        setLoad({ state: "error", message: describeError(r.error) });
        return;
      }
      setLoad({
        state: "ok",
        steps: attemptsOf(buildTimeline(r.value.records)),
        truncated: r.value.truncated,
      });
    });
    return () => {
      live = false;
    };
  }, [client, selected]);

  const options =
    selected !== undefined && !sessionIds.includes(selected)
      ? [selected, ...sessionIds]
      : sessionIds;
  const steps = load.state === "ok" ? load.steps : [];
  const current = steps[step];
  // BigInt: summing many integer paise amounts must never lose precision.
  const total = steps.reduce(
    (n, s) => (s.outcome?.outcome === "success" ? n + BigInt(s.attempt.amountPaise ?? 0) : n),
    0n,
  );

  return (
    <section aria-labelledby="replay-title" className="card">
      <div className="card-head">
        <div className="min-w-0">
          <p className="eyebrow">Step through one agent run</p>
          <h2 id="replay-title" className="card-title mt-1.5">
            Session <em>replay</em>
          </h2>
        </div>
      </div>
      <div className="px-5 py-4">
        <label className="eyebrow block" htmlFor="replay-session">
          Session
        </label>
        <select
          id="replay-session"
          value={selected ?? ""}
          onChange={(e) => {
            const v = e.target.value;
            onSelect(v === "" || !SESSION_ID_RE.test(v) ? undefined : v);
          }}
          className="input mt-2"
        >
          <option value="">Choose a session…</option>
          {options.map((id) => (
            <option key={id} value={id}>
              {displayId(id)}
            </option>
          ))}
        </select>

        {load.state === "loading" && <p className="mt-4 text-sm text-muted">Loading…</p>}
        {load.state === "error" && (
          <p role="alert" className="mt-4 text-sm break-words text-danger">
            Could not load the session: {load.message}
          </p>
        )}
        {load.state === "ok" && steps.length === 0 && (
          <p className="mt-4 text-sm text-muted">No money actions in this session.</p>
        )}
      </div>
      {load.state === "ok" && current !== undefined && (
        <div className="border-t border-line">
          <div className="flex items-center justify-between gap-2 px-5 pt-4">
            <button
              type="button"
              disabled={step === 0}
              onClick={() => {
                setStep((s) => Math.max(0, s - 1));
              }}
              className="btn-secondary h-8 px-3 text-xs"
            >
              ← Prev
            </button>
            <span
              className="font-mono text-xs text-muted tabular-nums"
              data-testid="replay-position"
            >
              Step {step + 1} of {steps.length}
            </span>
            <button
              type="button"
              disabled={step >= steps.length - 1}
              onClick={() => {
                setStep((s) => Math.min(steps.length - 1, s + 1));
              }}
              className="btn-secondary h-8 px-3 text-xs"
            >
              Next →
            </button>
          </div>
          <div className="flex flex-wrap gap-1 px-5 pt-3 pb-1" aria-label="Steps">
            {steps.map((s, i) => (
              <button
                key={s.seq}
                type="button"
                aria-label={`Step ${String(i + 1)}: ${s.attempt.decision}`}
                aria-current={i === step}
                onClick={() => {
                  setStep(i);
                }}
                className={`h-1.5 w-7 transition-opacity ${
                  s.attempt.decision === "deny"
                    ? "bg-danger"
                    : s.attempt.decision === "allow"
                      ? "bg-ok"
                      : "bg-accent"
                } ${i === step ? "opacity-100 outline outline-offset-2 outline-fg/70" : "opacity-40 hover:opacity-80"}`}
              />
            ))}
          </div>
          <ul className="mt-2 border-y border-line">
            <AttemptRow entry={current} compact />
          </ul>
          <p className="px-5 py-3 text-xs text-muted">
            Executed in this session:{" "}
            <span className="font-mono text-fg">{formatPaise(total) ?? "—"}</span>
            {load.truncated && " (session truncated)"}
          </p>
        </div>
      )}
    </section>
  );
}
