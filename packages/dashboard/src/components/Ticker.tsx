/**
 * Moving marquee of live stats (our own computed numbers only, see lib/stats.ts). ONE track renders the sequence
 * twice (each copy is the item list repeated so it is wider than any viewport) and animates translateX(0 → -50%):
 * copy 2 lands exactly where copy 1 started, so the loop is seamless and it starts with the first item fully visible.
 * Edges fade with a mask. Paused on hover, static under prefers-reduced-motion. Screen readers get one sentence.
 */
import { tickerItems, type TickerStats } from "../lib/stats";

export function Ticker({ stats }: { stats: TickerStats }) {
  const items = tickerItems(stats);
  const copy = [...items, ...items];
  const sequence = [...copy, ...copy];
  return (
    <div
      data-testid="ticker"
      className="asf-marquee asf-marquee-mask relative z-10 w-full overflow-hidden border-y border-line bg-bg py-2.5 font-mono text-[11px] tracking-[0.12em] text-muted uppercase"
    >
      <p className="sr-only">{items.join(". ")}</p>
      <ul aria-hidden="true" className="asf-marquee-track flex w-max items-center">
        {sequence.map((t, i) => (
          <li key={`${String(i)}-${t}`} className="flex shrink-0 items-center whitespace-nowrap">
            <span className="px-5">{t}</span>
            <span className="text-accent">✳</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
