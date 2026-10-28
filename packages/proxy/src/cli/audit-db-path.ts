/**
 * Audit DB location rules shared by the proxy (`cli/proxy.ts`) and the mode CLI (`cli/mode.ts`): the DB must live in
 * `<repo>/data/` (D-031). Its own module so `cli/mode.ts` does not import the proxy entry point.
 */
import { existsSync, lstatSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { err, ok, type Result } from "@asf/core";

export const DEFAULT_AUDIT_DB = "data/audit.db";
/** Repo-relative directory the audit DB must live in. */
export const AUDIT_DB_DIR = "data";

/** True iff `child` is `dir` itself (when `allowEqual`) or strictly below it. Both absolute, normalised. */
export function isStrictlyInside(dir: string, child: string, allowEqual = false): boolean {
  const rel = relative(dir, child);
  if (rel === "") return allowEqual;
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/**
 * Confine the audit DB to `<repo>/data/` by REAL path: `<realRepo>/data` is created if missing (and must be a
 * directory), the DB's parent directory must exist and its realpath must be `<realRepo>/data` or below, and an
 * existing DB file must be a regular file (not a symlink). Returns the real DB path and whether it already existed.
 */
export function confineAuditDb(
  auditDbPath: string,
  repoRoot: string,
): Result<{ path: string; existed: boolean }> {
  const outside = err<{ path: string; existed: boolean }>(
    "proxy.bad_audit_db",
    `ASF_AUDIT_DB must be a file inside <repo>/${AUDIT_DB_DIR}/`,
  );
  if (!isStrictlyInside(join(repoRoot, AUDIT_DB_DIR), auditDbPath)) return outside;
  try {
    const realRoot = realpathSync(repoRoot);
    const dataDir = join(realRoot, AUDIT_DB_DIR);
    if (!existsSync(dataDir)) mkdirSync(dataDir);
    if (!statSync(dataDir).isDirectory()) return outside;
    const rel = relative(repoRoot, auditDbPath);
    const parent = dirname(join(realRoot, rel));
    if (!existsSync(parent)) {
      return err("proxy.bad_audit_db", "the ASF_AUDIT_DB parent directory does not exist");
    }
    const realParent = realpathSync(parent);
    if (!isStrictlyInside(dataDir, realParent, true)) return outside;
    const path = join(realParent, basename(auditDbPath));
    let existed = false;
    try {
      const st = lstatSync(path);
      if (!st.isFile()) return err("proxy.bad_audit_db", "ASF_AUDIT_DB is not a regular file");
      existed = true;
    } catch (e: unknown) {
      if (!(e instanceof Error && "code" in e && e.code === "ENOENT")) throw e;
    }
    return ok({ path, existed });
  } catch (e: unknown) {
    return err("proxy.bad_audit_db", "the ASF_AUDIT_DB location cannot be checked", {
      cause: e instanceof Error ? e.name : typeof e,
    });
  }
}
