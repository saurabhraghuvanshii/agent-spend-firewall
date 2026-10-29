/** Admin token entry. The token goes to sessionStorage only (token.ts): never localStorage, a URL or a log line. */
import { useState, type FormEvent } from "react";
import { saveToken } from "../token";
import { AsciiField } from "./AsciiField";
import { BrandMark, Hero } from "./Brand";

export function TokenForm({
  apiUrl,
  onSaved,
  notice,
}: {
  apiUrl: string;
  onSaved: (token: string) => void;
  notice?: string | undefined;
}) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | undefined>();
  const submit = (e: FormEvent): void => {
    e.preventDefault();
    const t = value.trim();
    const r = saveToken(t);
    if (!r.ok) {
      setError(r.error);
      return;
    }
    setValue("");
    onSaved(t);
  };
  return (
    <div className="relative isolate flex min-h-dvh flex-col">
      <AsciiField />
      <header className="mx-auto flex w-full max-w-7xl items-center justify-between gap-3 px-5 py-5 sm:px-8">
        <BrandMark />
        <span className="chip">Razorpay test mode</span>
      </header>
      <main className="mx-auto grid w-full max-w-7xl flex-1 items-center gap-12 px-5 py-10 sm:px-8 lg:grid-cols-[minmax(0,1fr)_26rem]">
        <Hero
          eyebrow="Operator console"
          sub="Every money-moving agent action, explainable, bounded, gated and audited. Connect with the admin token to watch the firewall live."
        >
          Agent Spend <em className="text-fg">Firewall</em>
        </Hero>
        <form onSubmit={submit} className="card flex min-w-0 flex-col gap-3 p-6" autoComplete="off">
          <p className="eyebrow">Connect</p>
          <p className="text-sm break-all text-muted">
            Firewall API <span className="font-mono text-fg">{apiUrl}</span>
          </p>
          {notice !== undefined && (
            <p
              role="alert"
              className="border border-danger/50 bg-danger/10 p-3 text-sm text-danger"
            >
              {notice}
            </p>
          )}
          <label htmlFor="admin-token" className="mt-2 text-sm font-medium">
            Admin token
          </label>
          <input
            id="admin-token"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
            }}
            className="input"
          />
          <p className="text-xs leading-relaxed text-faint">
            Kept in this tab&apos;s session storage only; sent as the{" "}
            <code className="font-mono">x-admin-token</code> header, never in a URL.
          </p>
          {error !== undefined && (
            <p role="alert" className="text-sm text-danger">
              {error}
            </p>
          )}
          <button type="submit" className="btn-primary mt-2 h-11 w-full">
            Connect
          </button>
        </form>
      </main>
    </div>
  );
}
