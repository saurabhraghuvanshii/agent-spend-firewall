import { describe, expect, it } from "vitest";
import { DEFAULT_RAZORPAY_MCP_IMAGE } from "@asf/proxy";
import { allowedAgentTools, buildMcpServer, mcpToolName, parseTarget } from "./mcp-target.js";

const OPTS = {
  repoRoot: "/repo",
  image: DEFAULT_RAZORPAY_MCP_IMAGE,
  randomHex: () => "0123456789abcdef",
};

describe("parseTarget", () => {
  it("firewall | direct only", () => {
    expect(parseTarget("firewall")).toEqual({ ok: true, value: "firewall" });
    expect(parseTarget("direct")).toEqual({ ok: true, value: "direct" });
    for (const bad of [undefined, "", "FIREWALL", "proxy"]) expect(parseTarget(bad).ok).toBe(false);
  });
});

describe("buildMcpServer", () => {
  it("firewall: the proxy's stdio start command, silent pnpm, repo root dir", () => {
    const r = buildMcpServer("firewall", OPTS);
    expect(r).toEqual({
      ok: true,
      value: {
        type: "stdio",
        command: "pnpm",
        args: ["-s", "--dir", "/repo", "--filter", "@asf/proxy", "start"],
      },
    });
  });

  it("direct: the proxy's hardened docker run args; keys by NAME only, never values; no env block", () => {
    const r = buildMcpServer("direct", OPTS);
    if (!r.ok) throw new Error(r.error.message);
    const s = r.value;
    expect(s.command).toBe("docker");
    expect(s).not.toHaveProperty("env");
    expect(s.args).toContain("--pull=never");
    expect(s.args).toContain("--read-only");
    expect(s.args).toContain("asf-upstream-0123456789abcdef");
    expect(s.args.at(-1)).toBe(DEFAULT_RAZORPAY_MCP_IMAGE);
    const eIdx = s.args.flatMap((a, i) => (a === "-e" ? [s.args[i + 1]] : []));
    expect(eIdx).toEqual(["RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET"]);
    expect(s.args.join(" ")).not.toMatch(/rzp_|RAZORPAY_[A-Z_]*=|TopSecret/);
  });

  it("a bad container suffix is refused", () => {
    expect(buildMcpServer("direct", { ...OPTS, randomHex: () => "XYZ" }).ok).toBe(false);
  });
});

describe("allowedAgentTools", () => {
  it("is exactly the support tools, namespaced under mcp__razorpay__", () => {
    expect(allowedAgentTools()).toEqual([
      "mcp__razorpay__fetch_payment",
      "mcp__razorpay__fetch_order",
      "mcp__razorpay__fetch_order_payments",
      "mcp__razorpay__fetch_multiple_refunds_for_payment",
      "mcp__razorpay__create_refund",
      "mcp__razorpay__firewall_check_approval",
    ]);
    expect(mcpToolName("x")).toBe("mcp__razorpay__x");
  });
});
