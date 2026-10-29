/**
 * T011 × T010: an APPROVED create_refund whose send times out, whose late answer is a definite Razorpay rejection and
 * whose complete refund list lacks the marker is retried exactly once — as a `require_approval` retry attempt carrying
 * the approver, `retryOf` the original — and the chain (approval inherited by the retry) verifies.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compilePolicy, definePolicy, ok, rule, type CompiledPolicy, type Result } from "@asf/core";
import { openApprovalStore } from "@asf/approvals";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { CHECK_APPROVAL_TOOL, createApprovalService } from "./approval-service.js";
import { openAuditStore, type AuditAttemptRecord } from "./audit-store.js";
import { systemClock, systemTimer } from "./context-adapters.js";
import { ATTEMPT_MARKER_KEY, REFUND_LIST_TOOL } from "./failure.js";
import { createFirewallInterceptor, createMoneyPipeline } from "./interceptor.js";
import { redactSensitiveResult } from "./result-redaction.js";
import { advertiseTool } from "./schema-rewrite.js";
import { createProxyServer } from "./server.js";
import { jsonOf, scriptedUpstream, type ScriptedReply } from "./test-support/fake-upstream.js";
import { Upstream } from "./upstream.js";

const here = dirname(fileURLToPath(import.meta.url));
const TOOLS = (
  JSON.parse(readFileSync(resolve(here, "../../../docs/razorpay-tools.json"), "utf8")) as {
    tools: Tool[];
  }
).tools;
const PAY = "pay_RETRYabcdef";

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}`);
  return r.value;
}
function compiled(): CompiledPolicy {
  const c = compilePolicy(
    definePolicy({
      default: "deny",
      rules: [
        rule("refund.approval")
          .on("create_refund")
          .requireApproval({ via: "telegram", timeoutMin: 5, message: "needs a human" }),
      ],
    }),
  );
  if (!c.ok) throw new Error(c.error.code);
  return c.value;
}
const text = (j: unknown): CallToolResult => ({
  content: [{ type: "text", text: JSON.stringify(j) }],
});

describe("approved create_refund × T010 retry", () => {
  it("timeout + late definite rejection + marker absent ⇒ exactly one retry as require_approval + approver", async () => {
    const refunds: Array<Record<string, unknown>> = [];
    let refundCalls = 0;
    const up = scriptedUpstream({
      tools: TOOLS,
      handler: (name, args): ScriptedReply => {
        if (name === "fetch_payment") {
          return {
            result: text({
              id: args["payment_id"],
              status: "captured",
              amount: 500_000,
              amount_refunded: 0,
              currency: "INR",
            }),
          };
        }
        if (name === REFUND_LIST_TOOL) {
          const items = refunds.filter((r) => r["payment_id"] === args["payment_id"]);
          return { result: text({ entity: "collection", count: items.length, items }) };
        }
        if (name === "create_refund") {
          refundCalls++;
          if (refundCalls === 1) {
            // Answers only after the firewall gave up, with a definite rejection; nothing executed.
            return {
              delayMs: 80,
              result: {
                isError: true,
                content: [
                  {
                    type: "text",
                    text: '{"error":{"code":"BAD_REQUEST_ERROR","description":"try later"}}',
                  },
                ],
              },
            };
          }
          const r = {
            id: "rfnd_RETRYabcdef",
            amount: args["amount"],
            payment_id: args["payment_id"],
            status: "processed",
            notes: args["notes"],
          };
          refunds.push(r);
          return { result: text({ id: r.id, entity: "refund" }) };
        }
        return { result: text({ id: "x" }) };
      },
    });
    const upstream = new Upstream({ factory: up.factory, sleep: () => Promise.resolve() });
    const store = unwrap(openAuditStore({ path: ":memory:" }));
    const approvalStore = unwrap(openApprovalStore({ path: ":memory:" }));
    const service = createApprovalService({
      store: approvalStore,
      clock: systemClock,
      notifier: {
        notify: () => Promise.resolve(ok({ messageId: 1 })),
        showResolution: () => Promise.resolve(ok(null)),
      },
    });
    const pipeline = createMoneyPipeline({
      policy: compiled(),
      store,
      upstream,
      approvals: service,
      clock: systemClock,
      timer: systemTimer,
      lateResponses: upstream,
      verifyWaitMs: 2_000,
    });
    const proxy = createProxyServer({
      upstream,
      interceptor: createFirewallInterceptor(pipeline),
      advertise: advertiseTool,
      resultFilter: redactSensitiveResult,
      sessionId: "sess-retry",
      moneyCallTimeoutMs: 40,
      localTools: [service.checkTool],
    });
    service.attach({ pipeline, openCall: proxy.openDirectCall });
    await upstream.connect();
    const [a, b] = InMemoryTransport.createLinkedPair();
    await proxy.connect(b);
    const agent = new Client({ name: "agent", version: "0" }, { capabilities: {} });
    await agent.connect(a);
    try {
      const r = await agent.request(
        {
          method: "tools/call",
          params: {
            name: "create_refund",
            arguments: {
              payment_id: PAY,
              amount: 5_000,
              reason: "customer was double charged for this order",
            },
          },
        },
        CallToolResultSchema,
      );
      const approvalId = jsonOf(r)["approvalId"];
      if (typeof approvalId !== "string") throw new Error("no approval");
      const reply = await service.decide({
        approvalId,
        decision: "approved",
        approver: "telegram:9",
      });
      await reply.completion;
      await service.idle();

      const sends = up.calls.filter((c) => c.name === "create_refund");
      expect(sends).toHaveLength(2);
      const attempts: AuditAttemptRecord[] = [];
      for (const rec of unwrap(store.readAll())) {
        if (!("invalid" in rec) && rec.kind === "attempt") attempts.push(rec);
      }
      const [orig, retry] = attempts;
      expect(orig?.decision).toBe("require_approval");
      expect(retry).toMatchObject({
        retryOf: orig?.id,
        decision: "require_approval",
        approver: "telegram:9",
      });
      // Each send carries its own attempt's marker.
      expect((sends[0]?.args?.["notes"] as Record<string, unknown>)[ATTEMPT_MARKER_KEY]).toBe(
        orig?.id,
      );
      expect((sends[1]?.args?.["notes"] as Record<string, unknown>)[ATTEMPT_MARKER_KEY]).toBe(
        retry?.id,
      );
      expect(unwrap(store.verify()).ok).toBe(true);
      const polled = await agent.request(
        { method: "tools/call", params: { name: CHECK_APPROVAL_TOOL, arguments: { approvalId } } },
        CallToolResultSchema,
      );
      expect(jsonOf(polled)).toMatchObject({
        execution: { status: "executed", upstreamRef: "rfnd_RETRYabcdef" },
      });
    } finally {
      await agent.close();
      await proxy.close();
      pipeline.close();
      await upstream.close();
      store.close();
      approvalStore.close();
    }
  });
});
