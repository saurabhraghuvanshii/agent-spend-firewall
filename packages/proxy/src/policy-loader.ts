/**
 * Load the firewall policy file (T008, `ASF_POLICY`).
 *
 * - Path: `rawPath` (relative to `repoRoot`, or absolute), default `policies/default.ts`; empty ⇒ default.
 * - The REAL path (symlinks resolved) must be a regular file inside the real `repoRoot`, with extension `.ts`, `.js`
 *   or `.mjs`. (`.ts` needs a TypeScript-aware loader: the CLI runs under `tsx`.)
 * - The module's `default` export (or, failing that, a named `defaultPolicy`) must look like a policy spec
 *   (`{ default, rules[], timeoutMs? }`) and pass `compilePolicy`.
 * - A policy whose `default` is not `"deny"` is refused (D-016: the proxy never runs an allow-by-default policy).
 *
 * Importing a policy file EXECUTES it: policy files are trusted operator code (D-013), which is why the path is
 * confined to the repo. Never throws; every failure is an `err` whose message names no file contents.
 */
import { realpathSync, statSync } from "node:fs";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  compilePolicy,
  err,
  type CompiledPolicy,
  type PolicySpec,
  type Result,
  type Rule,
} from "@asf/core";
import { z } from "zod";

export const DEFAULT_POLICY_PATH = "policies/default.ts";
export const POLICY_EXTENSIONS: ReadonlySet<string> = new Set([".ts", ".js", ".mjs"]);

const ruleShape = z.custom<Rule>(
  (v) => typeof v === "object" && v !== null && (v as { kind?: unknown }).kind === "rule",
);
const specShape = z.object({
  default: z.enum(["deny", "allow"]),
  rules: z.array(ruleShape),
  timeoutMs: z.number().optional(),
});

function causeOf(e: unknown): string {
  if (e instanceof Error) {
    const code = (e as { code?: unknown }).code;
    return typeof code === "string" ? `${e.name} (${code})` : e.name;
  }
  return typeof e;
}

/** Real, confined, regular-file path of the policy, or an error. */
export function resolvePolicyPath(rawPath: string | undefined, repoRoot: string): Result<string> {
  const p = rawPath === undefined || rawPath === "" ? DEFAULT_POLICY_PATH : rawPath;
  if (p.includes("\0")) return err("policy.bad_path", "ASF_POLICY contains a NUL byte");
  let realRoot: string;
  let real: string;
  try {
    realRoot = realpathSync(repoRoot);
  } catch (e: unknown) {
    return err("policy.bad_path", "repo root cannot be resolved", { cause: causeOf(e) });
  }
  try {
    real = realpathSync(isAbsolute(p) ? p : resolve(realRoot, p));
  } catch (e: unknown) {
    return err("policy.not_found", "policy file not found", { cause: causeOf(e) });
  }
  const rel = relative(realRoot, real);
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    return err("policy.outside_repo", "policy file must be inside the repository");
  }
  if (!POLICY_EXTENSIONS.has(extname(real))) {
    return err("policy.bad_extension", "policy file must be a .ts, .js or .mjs file");
  }
  try {
    if (!statSync(real).isFile())
      return err("policy.not_a_file", "policy path is not a regular file");
  } catch (e: unknown) {
    return err("policy.not_found", "policy file cannot be read", { cause: causeOf(e) });
  }
  return { ok: true, value: real };
}

/** Validate an imported module and compile its policy. Exported for tests. */
export function policyFromModule(mod: unknown): Result<CompiledPolicy> {
  if (typeof mod !== "object" || mod === null) {
    return err("policy.no_export", "policy module has no exports");
  }
  const m = mod as Record<string, unknown>;
  const candidate = m["default"] ?? m["defaultPolicy"];
  if (candidate === undefined) {
    return err("policy.no_export", "policy module must export a default policy (or defaultPolicy)");
  }
  const shape = specShape.safeParse(candidate);
  if (!shape.success) return err("policy.invalid_spec", "exported value is not a policy spec");
  const spec: PolicySpec =
    shape.data.timeoutMs === undefined
      ? { default: shape.data.default, rules: shape.data.rules }
      : { default: shape.data.default, rules: shape.data.rules, timeoutMs: shape.data.timeoutMs };
  const compiled = compilePolicy(spec);
  if (!compiled.ok) return compiled;
  if (compiled.value.default !== "deny") {
    return err(
      "policy.allow_default",
      'refusing a policy whose default is "allow": the firewall policy must default to "deny"',
    );
  }
  return compiled;
}

export async function loadPolicy(
  rawPath: string | undefined,
  repoRoot: string,
): Promise<Result<CompiledPolicy>> {
  const path = resolvePolicyPath(rawPath, repoRoot);
  if (!path.ok) return path;
  let mod: unknown;
  try {
    mod = await import(pathToFileURL(path.value).href);
  } catch (e: unknown) {
    return err("policy.load_failed", "policy file failed to load", { cause: causeOf(e) });
  }
  try {
    return policyFromModule(mod);
  } catch (e: unknown) {
    return err("policy.load_failed", "policy export could not be read", { cause: causeOf(e) });
  }
}
