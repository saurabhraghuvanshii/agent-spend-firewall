/**
 * Agent-supplied text, rendered inert: the string is formatted by core `formatUntrustedReason` (see lib/untrusted.ts)
 * and emitted as a React TEXT node with a visible "untrusted" label. No HTML, markdown or links, ever.
 */
import type { JsonValue, UntrustedTextView } from "../api/schemas";
import { displayReason, flattenArgs, UNTRUSTED_REASON_LABEL } from "../lib/untrusted";

export function UntrustedLabel({ title = UNTRUSTED_REASON_LABEL }: { title?: string }) {
  return (
    <span title={title} className="chip chip-warn mr-2 h-5 px-2 align-[1px] text-[9.5px]">
      untrusted
    </span>
  );
}

export function UntrustedReason({ reason }: { reason: UntrustedTextView | undefined }) {
  return (
    <span data-testid="untrusted-reason" className="block min-w-0 break-words">
      <UntrustedLabel />
      <span
        dir="ltr"
        className="font-mono text-[12.5px] leading-relaxed [unicode-bidi:isolate] text-fg/85"
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
    <div data-testid="untrusted-args" className="min-w-0 text-xs">
      <div className="mb-2 flex items-center text-muted">
        <UntrustedLabel title="Agent-supplied arguments (untrusted, redacted)" />
        <span>
          {title} <span className="text-faint">· redacted</span>
        </span>
      </div>
      <dl className="grid grid-cols-[minmax(0,max-content)_minmax(0,1fr)] gap-x-4 gap-y-1 border-l border-line pl-3 font-mono text-[11.5px]">
        {lines.map((l, i) => (
          <div key={`${l.path}-${String(i)}`} className="contents">
            <dt className="max-w-[12rem] truncate text-faint" dir="ltr" title={l.path}>
              {l.path}
            </dt>
            <dd className="min-w-0 break-all text-fg/85 [unicode-bidi:isolate]" dir="ltr">
              {l.value}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
