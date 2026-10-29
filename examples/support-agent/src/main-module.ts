import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** True iff the module at `metaUrl` is the process entry point (so importing a CLI module from tests is inert). */
export function isMainModule(metaUrl: string): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(metaUrl));
  } catch (e: unknown) {
    if (e instanceof Error && "code" in e && e.code === "ENOENT") return false;
    throw e;
  }
}
