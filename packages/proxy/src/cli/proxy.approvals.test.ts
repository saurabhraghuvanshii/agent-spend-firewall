/** T011 CLI wiring: TELEGRAM_* config, approval store location, startProxy with the approval workflow. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicy } from "@asf/core";
import defaultPolicy from "@asf/policies";
import { createFakeTelegramTransport } from "@asf/approvals";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CHECK_APPROVAL_TOOL } from "../approval-service.js";
import { openAuditStore } from "../audit-store.js";
import { fakeUpstream, jsonOf } from "../test-support/fake-upstream.js";
import {
  approvalsDbPath,
  openApprovals,
  parseTelegramConfig,
  resolveProxyConfig,
  startProxy,
  type ConfigDeps,
  type ProxyConfig,
} from "./proxy.js";

const ROOT = "/repo";
const SHELL = { RAZORPAY_KEY_ID: "rzp_test_Key123", RAZORPAY_KEY_SECRET: "TopSecretValue987" };
const TOKEN = "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function deps(files: Record<string, string> = {}): ConfigDeps {
  return {
    cwd: "/elsewhere",
    moduleDir: `${ROOT}/packages/proxy/src/cli`,
    isRepoRoot: (dir) => dir === ROOT,
    readFile: (p) => files[p],
    baseChildEnv: () => ({ PATH: "/usr/bin" }),
  };
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "asf-cli-approvals-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("parseTelegramConfig", () => {
  it("neither ⇒ no Telegram; both valid ⇒ config", () => {
    expect(parseTelegramConfig(undefined, undefined)).toEqual({ ok: true, value: undefined });
    expect(parseTelegramConfig("", "")).toEqual({ ok: true, value: undefined });
    expect(parseTelegramConfig(TOKEN, "-1001234")).toEqual({
      ok: true,
      value: { token: TOKEN, chatId: "-1001234" },
    });
  });

  it.each([
    [TOKEN, undefined],
    [undefined, "42"],
    ["not-a-token", "42"],
    [TOKEN, "@channel"],
    [TOKEN, "42 "],
  ])("refuses %j / %j without echoing the values", (token, chat) => {
    const r = parseTelegramConfig(token, chat);
    expect(!r.ok && r.error.code).toBe("proxy.bad_telegram");
    expect(JSON.stringify(r)).not.toContain("AAAAAAAAAAAA");
  });

  it("resolveProxyConfig reads TELEGRAM_* from the shell or .env; half a config refuses to start", () => {
    const shell = resolveProxyConfig(
      { ...SHELL, TELEGRAM_BOT_TOKEN: TOKEN, TELEGRAM_CHAT_ID: "42" },
      deps(),
    );
    expect(shell.ok && shell.value.telegram).toEqual({ token: TOKEN, chatId: "42" });
    const file = resolveProxyConfig(
      SHELL,
      deps({ [`${ROOT}/.env`]: `TELEGRAM_BOT_TOKEN=${TOKEN}\nTELEGRAM_CHAT_ID=42\n` }),
    );
    expect(file.ok && file.value.telegram?.chatId).toBe("42");
    const none = resolveProxyConfig(SHELL, deps());
    expect(none.ok && none.value.telegram).toBeUndefined();
    const half = resolveProxyConfig({ ...SHELL, TELEGRAM_CHAT_ID: "42" }, deps());
    expect(!half.ok && half.error.code).toBe("proxy.bad_telegram");
  });
});

describe("openApprovals / startProxy with approvals", () => {
  function config(): ProxyConfig {
    const r = resolveProxyConfig(
      { ...SHELL, TELEGRAM_BOT_TOKEN: TOKEN, TELEGRAM_CHAT_ID: "42" },
      deps(),
    );
    if (!r.ok) throw new Error(r.error.code);
    return { ...r.value, auditDbPath: join(dir, "data", "audit.db") };
  }

  it("puts approvals.db next to the audit DB; no Telegram ⇒ no wiring", () => {
    expect(approvalsDbPath("/repo/data/audit.db")).toBe("/repo/data/approvals.db");
    const r = resolveProxyConfig(SHELL, deps());
    if (!r.ok) throw new Error("config");
    expect(openApprovals(r.value, () => undefined)).toEqual({ ok: true, value: undefined });
  });

  it("a pending approval is posted to Telegram and pollable by the agent; shutdown closes the stores", async () => {
    const cfg = config();
    const transport = createFakeTelegramTransport();
    const wiring = openApprovals(cfg, () => undefined, transport);
    if (!wiring.ok || wiring.value === undefined) throw new Error("wiring");
    expect(wiring.value.store.path).toBe(join(dir, "data", "approvals.db"));
    const policy = compilePolicy(defaultPolicy);
    const store = openAuditStore({ path: ":memory:" });
    if (!policy.ok || !store.ok) throw new Error("firewall");
    const fake = fakeUpstream({
      handler: (name, args) =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify(
                name === "fetch_payment"
                  ? {
                      id: args?.["payment_id"],
                      status: "captured",
                      amount: 500_000,
                      amount_refunded: 0,
                      currency: "INR",
                    }
                  : { id: "rfnd_CLIAPPROVE1" },
              ),
            },
          ],
        }),
    });
    const logs: string[] = [];
    const running = startProxy({
      config: cfg,
      logger: (l) => logs.push(l),
      factory: fake.factory,
      firewall: { policy: policy.value, store: store.value },
      approvalWiring: wiring.value,
    });
    await running.reconciled;
    const [a, b] = InMemoryTransport.createLinkedPair();
    await running.proxy.connect(b);
    const agent = new Client({ name: "t", version: "0" }, { capabilities: {} });
    await agent.connect(a);
    const listed = await agent.listTools();
    expect(listed.tools.some((t) => t.name === CHECK_APPROVAL_TOOL)).toBe(true);
    const r = await agent.request(
      {
        method: "tools/call",
        params: {
          name: "create_refund",
          arguments: {
            payment_id: "pay_CLI1",
            amount: 300_000,
            reason: "customer was double charged for this order",
          },
        },
      },
      CallToolResultSchema,
    );
    const body = jsonOf(r);
    expect(body).toMatchObject({ decision: "pending_approval" });
    expect(transport.sent).toHaveLength(1);
    expect(transport.sent[0]?.chatId).toBe("42");
    const polled = await agent.request(
      {
        method: "tools/call",
        params: { name: CHECK_APPROVAL_TOOL, arguments: { approvalId: body["approvalId"] } },
      },
      CallToolResultSchema,
    );
    expect(jsonOf(polled)).toMatchObject({ status: "pending" });
    expect(fake.calls.some((c) => c.name === "create_refund")).toBe(false);
    expect(logs.join("\n")).not.toContain(TOKEN);
    await running.shutdown();
    await agent.close();
    expect(wiring.value.store.get("x").ok).toBe(false);
  });
});
