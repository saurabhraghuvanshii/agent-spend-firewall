import { useEffect, useMemo, useState } from "react";
import { createApiClient, type ApiClient, type FetchLike } from "./api/client";
import { ApprovalsPanel } from "./components/ApprovalsPanel";
import { ChainBadge } from "./components/ChainBadge";
import { ModeControls } from "./components/ModeControls";
import { SessionReplay } from "./components/SessionReplay";
import { Timeline } from "./components/Timeline";
import { TokenForm } from "./components/TokenForm";
import { useDashboard } from "./hooks/useDashboard";
import { applyTheme, nextTheme, readThemePref, saveThemePref, type ThemePref } from "./theme";
import { clearToken, readToken } from "./token";

function ThemeToggle() {
  const [pref, setPref] = useState<ThemePref>(readThemePref);
  useEffect(() => {
    applyTheme(pref);
    if (pref !== "system" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = (): void => {
      applyTheme("system");
    };
    mq.addEventListener("change", on);
    return () => {
      mq.removeEventListener("change", on);
    };
  }, [pref]);
  return (
    <button
      type="button"
      onClick={() => {
        const n = nextTheme(pref);
        saveThemePref(n);
        setPref(n);
      }}
      title="Theme: system / light / dark"
      className="rounded-full border border-slate-300 px-3 py-1 text-xs dark:border-slate-600"
    >
      Theme: {pref}
    </button>
  );
}

function Dashboard({ client, onSignOut }: { client: ApiClient; onSignOut: () => void }) {
  const d = useDashboard(client);
  const [session, setSession] = useState<string | undefined>();
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <h1 className="mr-auto text-lg font-semibold">
            Agent Spend Firewall
            <span className="ml-2 align-middle text-xs font-normal text-slate-500 dark:text-slate-400">
              Razorpay test mode
            </span>
          </h1>
          <ChainBadge verify={d.verify} onRefresh={d.refreshVerify} />
          <ModeControls client={client} mode={d.mode} onChanged={d.setModeState} />
          <ThemeToggle />
          <button
            type="button"
            onClick={onSignOut}
            className="text-xs text-slate-500 underline-offset-2 hover:underline dark:text-slate-400"
          >
            Forget token
          </button>
        </div>
      </header>
      {d.status.state === "unauthorized" && (
        <div role="alert" className="mx-auto mt-4 max-w-7xl px-4">
          <p className="rounded-md border border-red-300 bg-red-50 p-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
            The API rejected the admin token (HTTP {d.status.status}).{" "}
            <button type="button" onClick={onSignOut} className="font-semibold underline">
              Enter a new token
            </button>
          </p>
        </div>
      )}
      {/* Small screens: approvals, timeline, replay. lg: timeline left (2 rows), approvals + replay right. */}
      <main className="mx-auto grid max-w-7xl grid-cols-1 gap-6 px-4 py-6 lg:grid-cols-[minmax(0,1fr)_24rem] lg:grid-rows-[auto_1fr]">
        <div className="order-2 min-w-0 lg:order-none lg:col-start-1 lg:row-span-2 lg:row-start-1">
          <Timeline
            entries={d.entries}
            status={d.status}
            error={d.timelineError}
            onPickSession={setSession}
          />
        </div>
        <div className="order-1 min-w-0 lg:order-none lg:col-start-2 lg:row-start-1">
          <ApprovalsPanel client={client} approvals={d.approvals} onReload={d.reloadApprovals} />
        </div>
        <div className="order-3 min-w-0 lg:order-none lg:col-start-2 lg:row-start-2 lg:self-start">
          <SessionReplay
            client={client}
            sessionIds={d.sessionIds}
            selected={session}
            onSelect={setSession}
          />
        </div>
      </main>
    </div>
  );
}

export function App({ apiUrl, fetchImpl }: { apiUrl: string; fetchImpl?: FetchLike }) {
  // Remount the dashboard per sign-in with a counter (never key React elements on the secret token).
  const [generation, setGeneration] = useState(0);
  const [token, setToken] = useState<string | undefined>(() => {
    const r = readToken();
    return r.ok ? r.value : undefined;
  });
  const client = useMemo(
    () =>
      token === undefined
        ? undefined
        : createApiClient({
            baseUrl: apiUrl,
            token,
            ...(fetchImpl === undefined ? {} : { fetchImpl }),
          }),
    [apiUrl, token, fetchImpl],
  );
  if (client === undefined) {
    return (
      <TokenForm
        apiUrl={apiUrl}
        onSaved={(t) => {
          setGeneration((g) => g + 1);
          setToken(t);
        }}
      />
    );
  }
  return (
    <Dashboard
      key={generation}
      client={client}
      onSignOut={() => {
        clearToken();
        setToken(undefined);
      }}
    />
  );
}
