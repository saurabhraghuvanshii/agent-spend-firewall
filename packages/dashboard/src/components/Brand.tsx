/** Our own mark (a shield-square) + wordmark, and the shared hero block. */
import type { ReactNode } from "react";

export function BrandMark() {
  return (
    <span className="inline-flex items-center gap-2.5">
      <span aria-hidden="true" className="relative inline-block h-5 w-5 bg-accent">
        <span className="absolute inset-[5px] border border-white/90" />
      </span>
      <span className="text-[13px] font-medium tracking-tight">Agent Spend Firewall</span>
    </span>
  );
}

export function Hero({
  eyebrow,
  children,
  sub,
}: {
  eyebrow: string;
  children: ReactNode;
  sub: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <p className="eyebrow">{eyebrow}</p>
      <h1 className="mt-4 font-display text-[clamp(2.75rem,8vw,6.25rem)] leading-[0.9] tracking-[-0.02em] break-words text-fg/90">
        {children}
      </h1>
      <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-muted">{sub}</p>
    </div>
  );
}
