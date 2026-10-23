/**
 * `pnpm audit:verify [--db <path>]` — verify the audit hash chain.
 *
 * DB path: `--db <path>` | `--db=<path>` | env `ASF_AUDIT_DB` | `data/audit.db`.
 * Relative paths resolve against `INIT_CWD` (the directory `pnpm` was invoked from) so that
 * `pnpm --filter @asf/proxy audit:verify` (which runs in the package dir) behaves as the user expects.
 *
 * Exit codes: 0 chain OK, 1 chain broken, 2 cannot open/read the DB, bad usage, or any unexpected error.
 *
 * Every dynamic value printed (path, ids, error messages, warnings) goes through `escapeForTerminal`, so a
 * crafted id or path cannot inject newlines or ANSI escape sequences and forge the verdict.
 */
import { realpathSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openAuditStore } from "../audit-store.js";

export const DEFAULT_AUDIT_DB = "data/audit.db";

export type VerifyExitCode = 0 | 1 | 2;

export interface RunVerifyResult {
  exitCode: VerifyExitCode;
  output: string;
}

export type CliEnv = Readonly<Record<string, string | undefined>>;

/**
 * JSON.stringify-style escaping for terminal output: a backslash becomes two backslashes, and every char
 * outside printable ASCII (0x20-0x7e) becomes a backslash-u escape with 4 hex digits (UTF-16 code units, so
 * astral chars become two escapes).
 */
export function escapeForTerminal(value: string): string {
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x5c) out += "\\\\";
    else if (code >= 0x20 && code <= 0x7e) out += value.charAt(i);
    else out += `\\u${code.toString(16).padStart(4, "0")}`;
  }
  return out;
}

const esc = escapeForTerminal;

const USAGE = "usage: audit:verify [--db <path>]   (or env ASF_AUDIT_DB; default data/audit.db)";

type ParsedArgs = { ok: true; db: string | undefined } | { ok: false; message: string };

function parseArgs(argv: readonly string[]): ParsedArgs {
  let db: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") continue; // pnpm may forward a literal separator
    if (a === "--db") {
      const v = argv[i + 1];
      if (v === undefined || v === "") return { ok: false, message: "--db requires a path" };
      db = v;
      i++;
    } else if (a !== undefined && a.startsWith("--db=")) {
      const v = a.slice("--db=".length);
      if (v === "") return { ok: false, message: "--db requires a path" };
      db = v;
    } else {
      return { ok: false, message: `unknown argument: ${String(a)}` };
    }
  }
  return { ok: true, db };
}

export function resolveDbPath(argDb: string | undefined, env: CliEnv, cwd: string): string {
  const raw = argDb ?? (env["ASF_AUDIT_DB"] || undefined) ?? DEFAULT_AUDIT_DB;
  if (isAbsolute(raw)) return raw;
  const base = env["INIT_CWD"] || cwd;
  return resolve(base, raw);
}

export function runVerify(
  argv: readonly string[],
  env: CliEnv,
  cwd: string = process.cwd(),
): RunVerifyResult {
  try {
    return runVerifyUnsafe(argv, env, cwd);
  } catch (e: unknown) {
    // Any unexpected failure means we could not verify: report it, never claim OK.
    const cause = e instanceof Error ? `${e.name}: ${e.message}` : "non-error thrown";
    return { exitCode: 2, output: `error: audit verification failed unexpectedly: ${esc(cause)}` };
  }
}

function runVerifyUnsafe(argv: readonly string[], env: CliEnv, cwd: string): RunVerifyResult {
  const args = parseArgs(argv);
  if (!args.ok) return { exitCode: 2, output: `error: ${esc(args.message)}\n${USAGE}` };

  const path = resolveDbPath(args.db, env, cwd);
  const shownPath = esc(path);
  const opened = openAuditStore({ path, readonly: true });
  if (!opened.ok) {
    return {
      exitCode: 2,
      output: `error: cannot open audit log ${shownPath}: ${esc(opened.error.message)} (${esc(opened.error.code)})`,
    };
  }
  const store = opened.value;
  try {
    const storeWarnings = store.warnings.map((w) => `WARNING: ${esc(w)}`);
    const result = store.verify();
    if (!result.ok) {
      return {
        exitCode: 2,
        output: `error: cannot read audit log ${shownPath}: ${esc(result.error.message)} (${esc(result.error.code)})`,
      };
    }
    const v = result.value;
    if (!v.ok) {
      const b = v.brokenAt;
      return {
        exitCode: 1,
        output: [
          `BROKEN: audit log ${shownPath}`,
          `first broken entry: seq ${String(b.seq)}, id ${typeof b.id === "string" ? esc(b.id) : "(unknown)"}, reason ${esc(b.reason)}`,
          ...storeWarnings,
        ].join("\n"),
      };
    }
    const lines = [
      `OK: audit log ${shownPath}`,
      `records: ${String(v.count)}`,
      `head: ${esc(v.headHash)}`,
      ...storeWarnings,
    ];
    if (v.danglingAttempts.length > 0) {
      lines.push(
        `WARNING: ${String(v.danglingAttempts.length)} attempt(s) without an outcome: ${v.danglingAttempts.map(esc).join(", ")}`,
      );
    }
    return { exitCode: 0, output: lines.join("\n") };
  } finally {
    store.close();
  }
}

function isMain(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch (e: unknown) {
    // Entry path not resolvable (e.g. stdin/eval): we are not the main module.
    if (e instanceof Error && "code" in e && e.code === "ENOENT") return false;
    throw e;
  }
}

if (isMain()) {
  const { exitCode, output } = runVerify(process.argv.slice(2), process.env);
  (exitCode === 0 ? process.stdout : process.stderr).write(`${output}\n`);
  process.exitCode = exitCode;
}
