/** Admin token entry. The token goes to sessionStorage only (token.ts): never localStorage, a URL or a log line. */
import { useState, type FormEvent } from "react";
import { saveToken } from "../token";

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
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center p-6">
      <h1 className="text-xl font-semibold">Agent Spend Firewall</h1>
      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
        Connect to the firewall API at <span className="font-mono">{apiUrl}</span>
      </p>
      {notice !== undefined && (
        <p
          role="alert"
          className="mt-4 rounded-md border border-red-300 bg-red-50 p-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-300"
        >
          {notice}
        </p>
      )}
      <form onSubmit={submit} className="mt-6 flex flex-col gap-2" autoComplete="off">
        <label htmlFor="admin-token" className="text-sm font-medium">
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
          className="rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm dark:border-slate-700 dark:bg-slate-900"
        />
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Kept in this tab&apos;s session storage only; sent as the <code>x-admin-token</code>{" "}
          header.
        </p>
        {error !== undefined && (
          <p role="alert" className="text-sm text-red-700 dark:text-red-300">
            {error}
          </p>
        )}
        <button
          type="submit"
          className="mt-2 rounded-md bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900"
        >
          Connect
        </button>
      </form>
    </main>
  );
}
