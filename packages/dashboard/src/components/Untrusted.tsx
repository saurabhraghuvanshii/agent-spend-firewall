/**
 * Agent-supplied text, rendered inert: the string is formatted by core `formatUntrustedReason` (see lib/untrusted.ts)
 * and emitted as a React TEXT node with a visible "untrusted" label. No HTML, markdown or links, ever.
 */
import type { JsonValue, UntrustedTextView } from "../api/schemas";
import { displayReason, flattenArgs, UNTRUSTED_REASON_LABEL } from "../lib/untrusted";

export function UntrustedLabel({ title = UNTRUSTED_REASON_LABEL }: { title?: string }) {
  return (
    <span
      title={title}
      className="mr-1.5 inline-block rounded border border-amber-400 bg-amber-50 px-1 py-px align-middle text-[10px] font-semibold tracking-wide text-amber-800 uppercase dark:border-amber-600 dark:bg-amber-950 dark:text-amber-300"
    >
      untrusted
    </span>
  );
}

export function UntrustedReason({ reason }: { reason: UntrustedTextView | undefined }) {
  return (
    <span data-testid="untrusted-reason" className="break-words">
      <UntrustedLabel />
      <span
        dir="ltr"
        className="font-mono text-xs [unicode-bidi:isolate] text-slate-700 dark:text-slate-300"
        aria-label={UNTRUSTED_REASON_LABEL}
      >
        {displayReason(reason)}
      </span>
    </span>
  );
}

/** Redacted args from the API (the only args the dashboard ever sees), keys and values formatted as untrusted. */
export function UntrustedArgs({ args, title }: { args: JsonValue | undefined; title: string }) {
  if (args === undefined) return null;
  const lines = flattenArgs(args);
  return (
    <div data-testid="untrusted-args" className="text-xs">
      <div className="mb-1 text-slate-500 dark:text-slate-400">
        <UntrustedLabel title="Agent-supplied arguments (untrusted, redacted)" />
        {title} <span className="text-slate-400">(redacted)</span>
      </div>
      <dl className="grid grid-cols-[minmax(0,max-content)_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono">
        {lines.map((l, i) => (
          <div key={`${l.path}-${String(i)}`} className="contents">
            <dt className="truncate text-slate-500 dark:text-slate-400" dir="ltr">
              {l.path}
            </dt>
            <dd
              className="break-all text-slate-800 [unicode-bidi:isolate] dark:text-slate-200"
              dir="ltr"
            >
              {l.value}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
