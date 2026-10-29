/**
 * Decorative background: a dot-matrix / ASCII field drawn on one fixed canvas behind the page, with a few slowly
 * drifting electric-blue blocks. Purely visual (aria-hidden, pointer-events none, no text from the API).
 *
 * Motion budget: at most ~24 fps, only a slice of cells is redrawn per frame, the loop stops while the tab is hidden,
 * and with prefers-reduced-motion a single static frame is drawn. The canvas is `position: fixed` and sized to the
 * viewport, so it can never cause layout shift or horizontal scroll.
 */
import { useEffect, useRef } from "react";

const CELL = 14;
const FPS = 24;
const GLYPHS = " .·:-=+*%#";
const BLOCK_GLYPHS = ".,:;-=+*!|ilrjxkpq";
const CELLS_PER_FRAME = 0.06;
const MAX_DPR = 2;

interface Block {
  x: number;
  y: number;
  w: number;
  h: number;
  dx: number;
  /** Horizontal bounds (cells) the block bounces within: always a gutter outside the content column. */
  minX: number;
  maxX: number;
}

/** Content column width (Tailwind `max-w-7xl`); blue blocks stay in the gutters outside it. */
const CONTENT_PX = 1280;

function rgb(name: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v === "" ? "243 240 232" : v;
}

export function AsciiField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (canvas === null) return;
    const ctx = canvas.getContext("2d");
    if (ctx === null) return; // no canvas support (e.g. tests): nothing to draw
    const reduce =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let cols = 0;
    let rows = 0;
    let blocks: Block[] = [];
    let raf = 0;
    let last = 0;
    let t = 0;
    let resizeTimer: ReturnType<typeof setTimeout> | undefined;

    const intensity = (c: number, r: number, time: number): number => {
      const a = Math.sin(c * 0.11 + time * 0.35) + Math.sin(r * 0.17 - time * 0.22);
      const b = Math.sin((c + r) * 0.05 + time * 0.13);
      const v = (a + b + 3) / 6; // 0..1
      const fade = Math.min(1, 0.35 + (r / Math.max(1, rows)) * 0.9); // lighter at the top, denser below
      return v * fade;
    };

    const inBlock = (c: number, r: number): boolean =>
      blocks.some(
        (b) => c >= Math.floor(b.x) && c < Math.floor(b.x) + b.w && r >= b.y && r < b.y + b.h,
      );

    const drawCell = (c: number, r: number, fg: string, accent: string): void => {
      const x = c * CELL;
      const y = r * CELL;
      ctx.clearRect(x, y, CELL, CELL);
      if (inBlock(c, r)) {
        ctx.fillStyle = `rgb(${accent} / 0.9)`;
        ctx.fillRect(x, y, CELL, CELL);
        ctx.fillStyle = "rgb(10 10 12 / 0.75)";
        ctx.fillText(
          BLOCK_GLYPHS[Math.floor(Math.random() * BLOCK_GLYPHS.length)] ?? ".",
          x + CELL / 2,
          y + CELL / 2,
        );
        return;
      }
      const v = intensity(c, r, t);
      const g = GLYPHS[Math.min(GLYPHS.length - 1, Math.floor(v * GLYPHS.length))] ?? " ";
      if (g === " ") return;
      ctx.fillStyle = `rgb(${fg} / ${(0.18 + v * 0.5).toFixed(3)})`;
      ctx.fillText(g, x + CELL / 2, y + CELL / 2);
    };

    const colors = (): { fg: string; accent: string } => ({
      fg: rgb("--field"),
      accent: "47 61 255",
    });

    const full = (): void => {
      const { fg, accent } = colors();
      for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) drawCell(c, r, fg, accent);
    };

    const setup = (): void => {
      const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1);
      const w = window.innerWidth;
      const h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = `10px "JetBrains Mono Variable", ui-monospace, monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      cols = Math.ceil(w / CELL);
      rows = Math.ceil(h / CELL);
      // Blue blocks only where there is a gutter wide enough beside the content column; none otherwise.
      const gutter = Math.floor((w - CONTENT_PX) / 2 / CELL) - 1;
      blocks = [];
      if (gutter >= 6) {
        const bw = Math.min(6, gutter - 1);
        const left = (fy: number, bh: number, dx: number): Block => ({
          x: 0,
          y: Math.floor(rows * fy),
          w: bw,
          h: bh,
          dx,
          minX: 0,
          maxX: gutter - bw,
        });
        const right = (fy: number, bh: number, dx: number): Block => ({
          x: cols - gutter,
          y: Math.floor(rows * fy),
          w: bw,
          h: bh,
          dx,
          minX: cols - gutter,
          maxX: cols - bw,
        });
        blocks = [left(0.62, 4, 0.015), right(0.34, 6, -0.012), right(0.8, 3, 0.02)];
      }
      full();
    };

    const frame = (now: number): void => {
      raf = requestAnimationFrame(frame);
      if (now - last < 1000 / FPS) return;
      last = now;
      t += 1 / FPS;
      const { fg, accent } = colors();
      for (const b of blocks) {
        const before = Math.floor(b.x);
        b.x += b.dx;
        if (b.x < b.minX || b.x > b.maxX) {
          b.dx = -b.dx;
          b.x = Math.min(b.maxX, Math.max(b.minX, b.x));
        }
        if (Math.floor(b.x) !== before) {
          // Repaint the columns the block left / entered.
          for (let r = b.y; r < b.y + b.h; r++) {
            for (const c of [
              before - 1,
              before,
              before + b.w - 1,
              before + b.w,
              Math.floor(b.x),
              Math.floor(b.x) + b.w - 1,
            ]) {
              if (c >= 0 && c < cols) drawCell(c, r, fg, accent);
            }
          }
        }
      }
      const n = Math.ceil(cols * rows * CELLS_PER_FRAME);
      for (let i = 0; i < n; i++) {
        drawCell(Math.floor(Math.random() * cols), Math.floor(Math.random() * rows), fg, accent);
      }
    };

    const start = (): void => {
      if (reduce || raf !== 0 || document.hidden) return;
      raf = requestAnimationFrame(frame);
    };
    const stop = (): void => {
      if (raf !== 0) cancelAnimationFrame(raf);
      raf = 0;
    };
    const onVisibility = (): void => {
      if (document.hidden) stop();
      else start();
    };
    const onResize = (): void => {
      if (resizeTimer !== undefined) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(setup, 150);
    };
    // Theme switch changes --field: repaint everything once.
    const themeObserver = new MutationObserver(full);
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });

    setup();
    start();
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("resize", onResize);
    return () => {
      stop();
      themeObserver.disconnect();
      if (resizeTimer !== undefined) clearTimeout(resizeTimer);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      data-testid="ascii-field"
      className="pointer-events-none fixed inset-0 -z-10 h-full w-full opacity-[0.22] dark:opacity-[0.3]"
    />
  );
}
