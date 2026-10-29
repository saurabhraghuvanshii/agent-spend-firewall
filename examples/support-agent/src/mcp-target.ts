/**
 * Which MCP server the demo agent talks to (T015):
 * - `firewall` — the Agent Spend Firewall proxy on stdio (`pnpm -s --dir <repo> --filter @asf/proxy start`); the
 *   proxy reads the Razorpay keys from `<repo>/.env` itself and starts the hardened upstream container.
 * - `direct` — the Razorpay MCP server in the same hardened container the proxy uses (`upstreamDockerRunArgs`,
 *   `--pull=never`, pinned image), WITHOUT the firewall: the baseline. Keys reach docker through the agent's env by
 *   NAME (`-e RAZORPAY_KEY_ID`), never in argv.
 *
 * The MCP server is registered as `razorpay`, so tools are `mcp__razorpay__<tool>` either way.
 */
import { err, ok, type Result } from "@asf/core";
import {
  CHECK_APPROVAL_TOOL,
  REFUND_LIST_TOOL,
  upstreamContainerName,
  upstreamDockerRunArgs,
} from "@asf/proxy";

export type Target = "firewall" | "direct";
export const MCP_SERVER_NAME = "razorpay";

/** Stdio MCP server config (structurally the Agent SDK's `McpStdioServerConfig`). No `env`: nothing secret here. */
export interface StdioServer {
  readonly type: "stdio";
  readonly command: string;
  readonly args: string[];
}

export function parseTarget(raw: string | undefined): Result<Target> {
  if (raw === "firewall" || raw === "direct") return ok(raw);
  return err("example.bad_target", "--target must be firewall or direct");
}

export function buildMcpServer(
  target: Target,
  opts: { readonly repoRoot: string; readonly image: string; readonly randomHex: () => string },
): Result<StdioServer> {
  if (target === "firewall") {
    return ok({
      type: "stdio",
      command: "pnpm",
      // `-s` is required: stdout is the MCP channel (no pnpm banner).
      args: ["-s", "--dir", opts.repoRoot, "--filter", "@asf/proxy", "start"],
    });
  }
  const name = upstreamContainerName(opts.randomHex());
  if (!name.ok) return name;
  return ok({
    type: "stdio",
    command: "docker",
    args: upstreamDockerRunArgs(opts.image, name.value),
  });
}

/** Read tools the agent may call (all `read`-classified by the proxy). */
export const AGENT_READ_TOOLS: readonly string[] = Object.freeze([
  "fetch_payment",
  "fetch_order",
  "fetch_order_payments",
  REFUND_LIST_TOOL,
]);
/** The one money tool the agent may call. */
export const AGENT_MONEY_TOOLS: readonly string[] = Object.freeze(["create_refund"]);
/** Firewall-local tool (T011) to poll an approval; only exists when the proxy has approvals configured. */
export const AGENT_FIREWALL_TOOLS: readonly string[] = Object.freeze([CHECK_APPROVAL_TOOL]);

export function mcpToolName(tool: string): string {
  return `mcp__${MCP_SERVER_NAME}__${tool}`;
}

/** Exact allow-list for the Agent SDK (`allowedTools` and `canUseTool`). */
export function allowedAgentTools(): string[] {
  return [...AGENT_READ_TOOLS, ...AGENT_MONEY_TOOLS, ...AGENT_FIREWALL_TOOLS].map(mcpToolName);
}
