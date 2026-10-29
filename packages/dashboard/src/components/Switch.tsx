/** Accessible toggle switch: `role="switch"` + `aria-checked`, rounded track with a sliding knob. */
export function Switch({
  checked,
  label,
  stateText,
  onToggle,
  disabled = false,
  tone = "accent",
  testId,
}: {
  /** `undefined` = state unknown (rendered unchecked, disabled). */
  checked: boolean | undefined;
  label: string;
  stateText: string;
  onToggle: () => void;
  disabled?: boolean;
  tone?: "accent" | "danger" | "warn";
  testId?: string;
}) {
  const on = checked === true;
  const track = tone === "danger" ? "bg-danger" : tone === "warn" ? "bg-warn" : "bg-accent";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      data-testid={testId}
      disabled={disabled || checked === undefined}
      onClick={onToggle}
      className="group inline-flex h-8 shrink-0 items-center gap-2.5 rounded-full border border-line-strong bg-surface/70 py-1 pr-3 pl-1 text-left transition-colors hover:border-fg/60 disabled:cursor-not-allowed disabled:opacity-55"
    >
      <span
        aria-hidden="true"
        className={`relative inline-block h-5 w-9 shrink-0 rounded-full transition-colors duration-200 ${
          on ? track : "bg-line-strong"
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full shadow transition-transform duration-200 motion-reduce:transition-none ${
            on ? "translate-x-4 bg-white" : "bg-fg"
          }`}
        />
      </span>
      <span className="text-[10.5px] leading-none font-medium tracking-[0.08em] whitespace-nowrap uppercase">
        <span className="text-muted">{label}</span>{" "}
        <span className={on ? "text-fg" : "text-faint"}>{stateText}</span>
      </span>
    </button>
  );
}
