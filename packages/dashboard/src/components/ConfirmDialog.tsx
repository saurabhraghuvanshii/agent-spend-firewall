/**
 * Modal confirm, portalled to <body> (an ancestor with a backdrop-filter / transform would otherwise become the
 * containing block of `position: fixed` and push the dialog off-screen). Centered, always inside the viewport
 * (max-height with scroll), focus trapped, Escape / Cancel / backdrop close, focus starts on Cancel and returns to
 * the opener on close.
 */
import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  // Latest onCancel without re-running the mount effect (which would steal focus on every parent render).
  const onCancelRef = useRef(onCancel);
  useEffect(() => {
    onCancelRef.current = onCancel;
  }, [onCancel]);
  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCancelRef.current();
        return;
      }
      if (e.key !== "Tab" || panelRef.current === null) return;
      const items = [...panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const first = items[0];
      const last = items.at(-1);
      if (first === undefined || last === undefined) return;
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !panelRef.current.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !panelRef.current.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
      opener?.focus();
    };
  }, []);

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        aria-hidden="true"
        className="absolute inset-0 bg-black/70 backdrop-blur-[2px]"
        onClick={onCancel}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        className="relative flex max-h-[calc(100dvh-2rem)] w-full max-w-md min-w-0 flex-col overflow-hidden border border-line-strong bg-surface text-fg shadow-2xl"
      >
        <div className={`h-1 w-full shrink-0 ${danger ? "bg-danger" : "bg-accent"}`} />
        <div className="min-h-0 overflow-y-auto px-6 pt-5 pb-2">
          <p className="eyebrow">{danger ? "Confirm · high impact" : "Confirm"}</p>
          <h2 id="confirm-title" className="mt-2 font-display text-3xl leading-tight">
            {title}
          </h2>
          <div className="mt-3 text-sm leading-relaxed break-words text-muted">{children}</div>
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-2 border-t border-line px-6 py-4">
          <button ref={cancelRef} type="button" onClick={onCancel} className="btn-secondary">
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={onConfirm}
            className={danger ? "btn-solid-danger" : "btn-primary"}
          >
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
