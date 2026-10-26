import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { definePolicy, rule } from "@asf/core";
import {
  DEFAULT_POLICY_PATH,
  loadPolicy,
  policyFromModule,
  resolvePolicyPath,
} from "./policy-loader.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

let root: string;
let outside: string;

beforeEach(() => {
  outside = mkdtempSync(join(tmpdir(), "asf-policy-"));
  root = join(outside, "repo");
  mkdirSync(root);
});

afterEach(() => {
  rmSync(outside, { recursive: true, force: true });
});

const DENY_SPEC = `{ default: "deny", rules: [{ kind: "rule", id: "r.allow", tools: ["create_refund"], action: { kind: "allow" } }] }`;

function write(rel: string, content: string): void {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
}

async function code(rawPath: string | undefined, repoRoot = root): Promise<string> {
  const r = await loadPolicy(rawPath, repoRoot);
  return r.ok ? "ok" : r.error.code;
}

describe("loadPolicy", () => {
  it("loads the repo's policies/default.ts by default", async () => {
    expect(DEFAULT_POLICY_PATH).toBe("policies/default.ts");
    const r = await loadPolicy(undefined, REPO_ROOT);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.kind).toBe("compiled-policy");
    expect(r.value.default).toBe("deny");
    expect(r.value.rules.map((x) => x.id)).toContain("refund.velocity");
    expect((await loadPolicy("", REPO_ROOT)).ok).toBe(true);
  });

  it("loads a default export (.mjs, .js, .ts) and a named defaultPolicy fallback", async () => {
    write("p/a.mjs", `export default ${DENY_SPEC};\n`);
    write("p/b.ts", `const p = ${DENY_SPEC};\nexport default p;\n`);
    write("p/c.mjs", `export const defaultPolicy = ${DENY_SPEC};\n`);
    write("package.json", '{"type":"module"}');
    write("p/d.js", `export default ${DENY_SPEC};\n`);
    for (const f of ["p/a.mjs", "p/b.ts", "p/c.mjs", "p/d.js"]) expect(await code(f)).toBe("ok");
    // absolute paths inside the repo are fine too
    expect(await code(join(root, "p/a.mjs"))).toBe("ok");
  });

  it('refuses a policy whose default is "allow"', async () => {
    write("open.mjs", 'export default { default: "allow", rules: [] };\n');
    expect(await code("open.mjs")).toBe("policy.allow_default");
  });

  it("refuses a spec that fails compilePolicy (reserved rule id)", async () => {
    write(
      "bad.mjs",
      'export default { default: "deny", rules: [{ kind: "rule", id: "policy-x", tools: ["a"], action: { kind: "allow" } }] };\n',
    );
    expect(await code("bad.mjs")).toBe("policy.reserved_rule_id");
  });

  it.each([
    ["no export", "export const x = 1;\n", "policy.no_export"],
    ["not a spec", 'export default { rules: "nope" };\n', "policy.invalid_spec"],
    [
      "unfinished rule",
      'export default { default: "deny", rules: [{ id: "x" }] };\n',
      "policy.invalid_spec",
    ],
    ["throws on import", 'throw new Error("boom");\n', "policy.load_failed"],
    ["syntax error", "export default {;\n", "policy.load_failed"],
  ])("refuses a module with %s", async (_name, content, expected) => {
    write("m.mjs", content);
    expect(await code("m.mjs")).toBe(expected);
  });

  it("confines the path to the repo (.., absolute outside, symlink out)", async () => {
    writeFileSync(join(outside, "evil.mjs"), `export default ${DENY_SPEC};\n`);
    expect(await code("../evil.mjs")).toBe("policy.outside_repo");
    expect(await code(join(outside, "evil.mjs"))).toBe("policy.outside_repo");
    symlinkSync(join(outside, "evil.mjs"), join(root, "link.mjs"));
    expect(await code("link.mjs")).toBe("policy.outside_repo");
    expect(await code(".")).toBe("policy.outside_repo");
  });

  it("requires an existing regular file with an allowed extension", async () => {
    expect(await code("missing.ts")).toBe("policy.not_found");
    mkdirSync(join(root, "dir.ts"));
    expect(await code("dir.ts")).toBe("policy.not_a_file");
    write("p.json", "{}");
    expect(await code("p.json")).toBe("policy.bad_extension");
    expect(await code("a\0b.ts")).toBe("policy.bad_path");
  });

  it("resolvePolicyPath returns the real path", () => {
    write("x.mjs", "");
    const r = resolvePolicyPath("x.mjs", root);
    expect(r.ok && r.value.endsWith("x.mjs")).toBe(true);
  });
});

describe("policyFromModule", () => {
  it("compiles a DSL policy (default export wins over defaultPolicy)", () => {
    const deny = definePolicy({
      default: "deny",
      rules: [rule("r.a").on("create_refund").allow()],
    });
    const allow = definePolicy({ default: "allow", rules: [] });
    expect(policyFromModule({ default: deny, defaultPolicy: allow }).ok).toBe(true);
    expect(policyFromModule({ defaultPolicy: allow }).ok).toBe(false);
  });

  it.each([null, 42, "x"])("refuses %j", (m) => {
    expect(policyFromModule(m).ok).toBe(false);
  });

  it("refuses an export whose getter throws (no throw escapes loadPolicy)", async () => {
    write("g.mjs", 'export default { get default() { throw new Error("x"); }, rules: [] };\n');
    expect(await code("g.mjs")).not.toBe("ok");
  });
});
