import { useEffect, useMemo, useState } from "react";
import { createApiClient, type ApiClient, type FetchLike } from "./api/client";
import { ApprovalsPanel } from "./components/ApprovalsPanel";
import { AsciiField } from "./components/AsciiField";
import { BrandMark } from "./components/Brand";
import { ChainBadge, chainStatus } from "./components/ChainBadge";
import { ModeControls } from "./components/ModeControls";
import { SessionReplay } from "./components/SessionReplay";
import { Ticker } from "./components/Ticker";
import { Timeline } from "./components/Timeline";
import { TokenForm } from "./components/TokenForm";
import { useDashboard } from "./hooks/useDashboard";
import { computeStats } from "./lib/stats";
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
      title="Theme: dark / light / system"
      aria-label={`Theme: ${pref} (switch)`}
      className="btn-link whitespace-nowrap"
    >
      <span
        aria-hidden="true"
        className="inline-block h-3.5 w-3.5 rounded-full border border-current bg-[linear-gradient(90deg,currentColor_50%,transparent_50%)] align-middle sm:hidden"
      />
      <span className="hidden sm:inline">Theme · {pref}</span>
    </button>
  );
}

function Dashboard({ client, onSignOut }: { client: ApiClient; onSignOut: () => void }) {
  const d = useDashboard(client);
  const [session, setSession] = useState<string | undefined>();
  const stats = computeStats(d.entries, {
    pendingApprovals: d.approvals.state === "ok" ? d.approvals.approvals.length : undefined,
    chain: chainStatus(d.verify),
    shadow: d.mode.state === "ok" ? d.mode.mode.shadow : undefined,
    killSwitch: d.mode.state === "ok" ? d.mode.mode.killSwitch : undefined,
  });
  return (
    <div className="relative isolate min-h-dvh">
      <AsciiField />
      <header className="sticky top-0 z-20 border-b border-line bg-bg/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl flex-nowrap items-center gap-x-3 px-4 py-3.5 sm:gap-x-5 sm:px-8">
          <span className="mr-auto min-w-0 truncate">
            <BrandMark />
          </span>
          <span className="chip h-5 px-2 text-[9px] sm:h-6 sm:px-2.5 sm:text-[10.5px]">
            <span className="sm:hidden">Test mode</span>
            <span className="hidden sm:inline">Razorpay test mode</span>
          </span>
          <ThemeToggle />
          <button
            type="button"
            onClick={onSignOut}
            aria-label="Forget token"
            className="btn-link whitespace-nowrap"
          >
            <span className="sm:hidden">Sign out</span>
            <span className="hidden sm:inline">Forget token</span>
          </button>
        </div>
      </header>

      {/* Compact hero after sign-in: one-line title + subtitle, status chips to the right on xl. */}
      <section className="mx-auto flex max-w-7xl flex-col gap-4 px-5 pt-6 pb-5 sm:px-8 xl:flex-row xl:items-end xl:justify-between xl:gap-8">
        <div className="min-w-0">
          <h1 className="font-display text-[clamp(2.25rem,4.6vw,3.75rem)] leading-[0.95] tracking-[-0.02em] text-fg/90 sm:whitespace-nowrap">
            Agent Spend <em className="text-fg">Firewall</em>
          </h1>
          <p className="mt-2 text-sm text-muted xl:truncate">
            Every money-moving agent action: explainable, bounded, gated, audited.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2.5" aria-label="Firewall status">
          <ChainBadge verify={d.verify} onRefresh={d.refreshVerify} />
          <ModeControls client={client} mode={d.mode} onChanged={d.setModeState} />
        </div>
      </section>

      <Ticker stats={stats} />

      {d.status.state === "unauthorized" && (
        <div role="alert" className="mx-auto mt-6 max-w-7xl px-5 sm:px-8">
          <p className="border border-danger/50 bg-danger/10 p-3 text-sm text-danger">
            The API rejected the admin token (HTTP {d.status.status}).{" "}
            <button
              type="button"
              onClick={onSignOut}
              className="font-medium underline underline-offset-4"
            >
              Enter a new token
            </button>
          </p>
        </div>
      )}

      {/* Small screens: approvals, timeline, replay. lg: timeline left (2 rows), approvals + replay right. */}
      <main className="mx-auto grid max-w-7xl grid-cols-1 gap-6 px-5 py-8 sm:px-8 lg:grid-cols-[minmax(0,1fr)_24rem] lg:grid-rows-[auto_1fr]">
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
      <footer className="mx-auto flex max-w-7xl flex-wrap justify-between gap-2 px-5 pt-4 pb-10 text-xs text-faint sm:px-8">
        <span>
          Agent-supplied text is shown escaped and labelled untrusted. Arguments are redacted.
        </span>
        <span className="font-mono">{client.baseUrl}</span>
      </footer>
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
