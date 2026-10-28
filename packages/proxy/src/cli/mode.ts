/**
 * `asf-proxy mode …` — show or change the firewall mode (T012). Works while the proxy runs: the proxy reads the mode
 * from the audit log on every money call.
 *
 *   pnpm --filter @asf/proxy mode status
 *   pnpm --filter @asf/proxy mode kill on|off   [--actor <slug>]
 *   pnpm --filter @asf/proxy mode shadow on|off [--actor <slug>]
 *
 * (`pnpm --filter @asf/proxy start mode …` is the same entry point.)
 *
 * - The audit DB is resolved exactly like the proxy's: `ASF_AUDIT_DB` from the SHELL env only (never `.env`, which
 *   this command does not read), default `data/audit.db`, confined to `<repo>/data/` (D-031).
 * - A change is one chained `mode` record {killSwitch, shadow, actor, ts} (D-035). `actor` is `cli:<slug>`: `--actor`
 *   or the OS user name lower-cased with other characters replaced by `_` (max 32), `cli:operator` if unavailable.
 * - Kill switch ON wins over shadow mode: every money call is denied `kill-switch`; read tools still work.
 *
 * Exit codes: 0 done; 1 the mode is unreadable (status only; the proxy then treats the kill switch as ON); 2 bad
 * usage, the audit DB can't be opened or the change could not be written.
 */
import { existsSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { openAuditStore } from "../audit-store.js";
import { createModeStore, describeMode, type ModeChange } from "../modes.js";
import type { EnvLike } from "../tool-discovery.js";
import { escapeForTerminal } from "./audit-verify.js";
import { findRepoRoot } from "./discover-tools.js";
import { confineAuditDb, DEFAULT_AUDIT_DB } from "./audit-db-path.js";

export const MODE_USAGE = [
  "usage: asf-proxy mode status",
  "       asf-proxy mode kill on|off [--actor <slug>]",
  "       asf-proxy mode shadow on|off [--actor <slug>]",
  "  (<slug>: 1-32 of a-z 0-9 _ -; audit DB: shell ASF_AUDIT_DB or data/audit.db)",
].join("\n");

export interface ModeCliDeps {
  /** SHELL environment (no `.env` is read). */
  readonly env: EnvLike;
  readonly cwd: string;
  readonly moduleDir: string;
  readonly isRepoRoot: (dir: string) => boolean;
  /** OS user name for the default actor; `undefined` if unavailable. */
  readonly userName: () => string | undefined;
}

export interface ModeCliResult {
  readonly exitCode: 0 | 1 | 2;
  readonly output: string;
}

const SLUG_RE = /^[a-z0-9_-]{1,32}$/;

/** `cli:<slug>` from an OS user name; `cli:operator` when nothing usable is left. */
export function defaultActor(userName: string | undefined): string {
  const slug = (userName ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .slice(0, 32);
  return SLUG_RE.test(slug) && /[a-z0-9]/.test(slug) ? `cli:${slug}` : "cli:operator";
}

type Parsed =
  | { readonly ok: true; readonly cmd: "status" }
  | {
      readonly ok: true;
      readonly cmd: "set";
      readonly change: Omit<ModeChange, "actor">;
      readonly actor?: string;
    }
  | { readonly ok: false; readonly message: string };

export function parseModeArgs(argv: readonly string[]): Parsed {
  const args = argv.filter((a) => a !== "--");
  const positional: string[] = [];
  let actor: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    let value: string | undefined;
    if (a === "--actor") {
      value = args[i + 1];
      i++;
    } else if (a.startsWith("--actor=")) {
      value = a.slice("--actor=".length);
    } else if (a.startsWith("-")) {
      return { ok: false, message: `unknown option: ${a}` };
    } else {
      positional.push(a);
      continue;
    }
    if (value === undefined || !SLUG_RE.test(value)) {
      return { ok: false, message: "--actor requires a slug (1-32 of a-z 0-9 _ -)" };
    }
    actor = `cli:${value}`;
  }
  const [what, state, ...rest] = positional;
  if (what === "status" && state === undefined) {
    return actor === undefined
      ? { ok: true, cmd: "status" }
      : { ok: false, message: "--actor is only for changes" };
  }
  if (
    (what === "kill" || what === "shadow") &&
    (state === "on" || state === "off") &&
    rest.length === 0
  ) {
    const on = state === "on";
    const change = what === "kill" ? { killSwitch: on } : { shadow: on };
    return { ok: true, cmd: "set", change, ...(actor === undefined ? {} : { actor }) };
  }
  return { ok: false, message: "expected: status | kill on|off | shadow on|off" };
}

/** Repo root + confined audit DB path, like the proxy's `resolveProxyConfig` / `confineAuditDb`. */
function locateAuditDb(
  deps: ModeCliDeps,
): { ok: true; path: string; existed: boolean } | { ok: false; message: string } {
  const starts = [deps.env["INIT_CWD"], deps.cwd, deps.moduleDir].filter(
    (s): s is string => typeof s === "string" && s !== "",
  );
  let repoRoot: string | undefined;
  for (const s of starts) {
    repoRoot = findRepoRoot(s, deps.isRepoRoot);
    if (repoRoot !== undefined) break;
  }
  if (repoRoot === undefined)
    return { ok: false, message: "cannot find the repo root (pnpm-workspace.yaml)" };
  const raw = deps.env["ASF_AUDIT_DB"];
  const setting = raw === undefined || raw === "" ? DEFAULT_AUDIT_DB : raw;
  if (setting.includes("\0") || setting === ":memory:") {
    return { ok: false, message: "ASF_AUDIT_DB must be a file path" };
  }
  const path = isAbsolute(setting) ? resolve(setting) : resolve(join(repoRoot, setting));
  const confined = confineAuditDb(path, repoRoot);
  if (!confined.ok) return { ok: false, message: confined.error.message };
  return { ok: true, path: confined.value.path, existed: confined.value.existed };
}

export function runModeCommand(argv: readonly string[], deps: ModeCliDeps): ModeCliResult {
  try {
    return runUnsafe(argv, deps);
  } catch (e: unknown) {
    const cause = e instanceof Error ? e.name : typeof e;
    return {
      exitCode: 2,
      output: `error: mode command failed unexpectedly (${escapeForTerminal(cause)})`,
    };
  }
}

function runUnsafe(argv: readonly string[], deps: ModeCliDeps): ModeCliResult {
  const esc = escapeForTerminal;
  const parsed = parseModeArgs(argv);
  if (!parsed.ok) return { exitCode: 2, output: `error: ${esc(parsed.message)}\n${MODE_USAGE}` };
  const db = locateAuditDb(deps);
  if (!db.ok) return { exitCode: 2, output: `error: ${esc(db.message)}` };

  if (parsed.cmd === "status") {
    if (!db.existed || !existsSync(db.path)) {
      return {
        exitCode: 0,
        output: `mode: kill switch off; shadow mode off; never changed (defaults; no audit log yet at ${esc(db.path)})`,
      };
    }
    const opened = openAuditStore({ path: db.path, readonly: true });
    if (!opened.ok) {
      return {
        exitCode: 2,
        output: `error: cannot open audit log ${esc(db.path)} (${esc(opened.error.code)})`,
      };
    }
    try {
      const m = createModeStore(opened.value).read();
      if (!m.ok) {
        return {
          exitCode: 1,
          output: `mode: UNREADABLE (${esc(m.error.message)}): the proxy treats the kill switch as ON. Run audit:verify; turning the kill switch on or off writes a fresh mode record.`,
        };
      }
      return { exitCode: 0, output: `mode: ${esc(describeMode(m.value))}` };
    } finally {
      opened.value.close();
    }
  }

  const actor = parsed.actor ?? defaultActor(deps.userName());
  const opened = openAuditStore({ path: db.path });
  if (!opened.ok) {
    return {
      exitCode: 2,
      output: `error: cannot open audit log ${esc(db.path)} (${esc(opened.error.code)})`,
    };
  }
  try {
    const r = createModeStore(opened.value).set({ ...parsed.change, actor });
    if (!r.ok) {
      return { exitCode: 2, output: `error: the mode was NOT changed (${esc(r.error.code)})` };
    }
    const prefix = r.value.changed ? "mode changed" : "mode unchanged (already in force)";
    return { exitCode: 0, output: `${prefix}: ${esc(describeMode(r.value.mode))}` };
  } finally {
    opened.value.close();
  }
}
