/**
 * Theme preference. Dark is the default; `system` follows prefers-color-scheme. Not secret, so it may live in
 * localStorage.
 */
export type ThemePref = "dark" | "light" | "system";
const KEY = "asf.theme";

export function readThemePref(): ThemePref {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === "light" || v === "system" ? v : "dark";
  } catch (e: unknown) {
    console.warn(`asf: theme preference unavailable (${e instanceof Error ? e.name : "error"})`);
    return "dark";
  }
}

export function saveThemePref(p: ThemePref): void {
  try {
    if (p === "dark") window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, p);
  } catch (e: unknown) {
    console.warn(`asf: could not save the theme (${e instanceof Error ? e.name : "error"})`);
  }
}

export function systemPrefersDark(): boolean {
  return (
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

export function applyTheme(p: ThemePref): void {
  const dark = p === "dark" || (p === "system" && systemPrefersDark());
  document.documentElement.classList.toggle("dark", dark);
}

export const nextTheme = (p: ThemePref): ThemePref =>
  p === "dark" ? "light" : p === "light" ? "system" : "dark";
