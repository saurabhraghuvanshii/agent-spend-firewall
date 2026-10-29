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
    <section
      aria-labelledby="replay-title"
      className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
    >
      <h2 id="replay-title" className="mb-3 text-base font-semibold">
        Session replay
      </h2>
      <label className="block text-xs text-slate-500 dark:text-slate-400" htmlFor="replay-session">
        Session
      </label>
      <select
        id="replay-session"
        value={selected ?? ""}
        onChange={(e) => {
          const v = e.target.value;
          onSelect(v === "" || !SESSION_ID_RE.test(v) ? undefined : v);
        }}
        className="mt-1 w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-slate-700 dark:bg-slate-950"
      >
        <option value="">Choose a session…</option>
        {options.map((id) => (
          <option key={id} value={id}>
            {displayId(id)}
          </option>
        ))}
      </select>

      {load.state === "loading" && <p className="mt-3 text-sm text-slate-500">Loading…</p>}
      {load.state === "error" && (
        <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">
          Could not load the session: {load.message}
        </p>
      )}
      {load.state === "ok" && steps.length === 0 && (
        <p className="mt-3 text-sm text-slate-500">No money actions in this session.</p>
      )}
      {load.state === "ok" && current !== undefined && (
        <div className="mt-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <button
              type="button"
              disabled={step === 0}
              onClick={() => {
                setStep((s) => Math.max(0, s - 1));
              }}
              className="rounded-md border border-slate-300 px-3 py-1 text-sm disabled:opacity-40 dark:border-slate-700"
            >
              ← Prev
            </button>
            <span className="text-sm tabular-nums" data-testid="replay-position">
              Step {step + 1} of {steps.length}
            </span>
            <button
              type="button"
              disabled={step >= steps.length - 1}
              onClick={() => {
                setStep((s) => Math.min(steps.length - 1, s + 1));
              }}
              className="rounded-md border border-slate-300 px-3 py-1 text-sm disabled:opacity-40 dark:border-slate-700"
            >
              Next →
            </button>
          </div>
          <div className="mb-2 flex flex-wrap gap-1" aria-label="Steps">
            {steps.map((s, i) => (
              <button
                key={s.seq}
                type="button"
                aria-label={`Step ${String(i + 1)}: ${s.attempt.decision}`}
                aria-current={i === step}
                onClick={() => {
                  setStep(i);
                }}
                className={`h-2.5 w-6 rounded-full ${
                  s.attempt.decision === "deny"
                    ? "bg-red-500"
                    : s.attempt.decision === "allow"
                      ? "bg-emerald-500"
                      : "bg-sky-500"
                } ${i === step ? "ring-2 ring-slate-900 ring-offset-1 dark:ring-white dark:ring-offset-slate-900" : "opacity-60"}`}
              />
            ))}
          </div>
          <ul>
            <AttemptRow entry={current} compact />
          </ul>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Executed in this session: {formatPaise(total) ?? "—"}
            {load.truncated && " (session truncated)"}
          </p>
        </div>
      )}
    </section>
  );
}
