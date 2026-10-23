/**
 * Default firewall policy for refunds. All money values are integer paise (₹1 = 100 paise).
 *
 * Rules run in order; the most severe matching rule wins (deny > require_approval > allow) and
 * anything not explicitly allowed is denied. Rules never read `ctx.untrustedReason` (D-004).
 */
import { definePolicy, rule } from "@asf/core";

// TODO(T002): replace with the refund tool name(s) discovered from the Razorpay MCP server.
export const REFUND_TOOLS: readonly string[] = ["create_refund"];

/** ₹10,000: refunds above this are always denied. */
export const HARD_CAP_PAISE = 1_000_000;
/** ₹2,000: refunds above this need a human. */
export const APPROVAL_THRESHOLD_PAISE = 200_000;
/** ₹20,000 per rolling hour across all refund tools (executed refunds + this one). */
export const VELOCITY_MAX_PAISE = 2_000_000;
/** At most this many executed refunds per rolling hour. */
export const VELOCITY_MAX_COUNT = 10;
export const VELOCITY_WINDOW_MS = 60 * 60 * 1000;
export const DUPLICATE_WINDOW_MS = 10 * 60 * 1000;
export const APPROVAL_TIMEOUT_MIN = 30;

export const defaultPolicy = definePolicy({
  default: "deny",
  rules: [
    // Razorpay treats a missing amount as a FULL refund; force the agent to state the amount.
    rule("refund.amount_required")
      .on(REFUND_TOOLS)
      .when((ctx) => !ctx.has("amount"))
      .deny("Refund amount (in paise) is required; full refunds without an amount are not allowed"),

    // Every cap below is in INR paise; a payment in another currency (USD cents, JPY yen, KWD fils…)
    // would be compared in the wrong unit, so non-INR payments are denied before any cap runs.
    rule("refund.currency_not_inr")
      .on(REFUND_TOOLS)
      .when(async (ctx) => {
        const payment = await ctx.razorpay.payment(ctx.string("payment_id"));
        return payment.currency !== "INR";
      })
      .deny("Only INR payments can be refunded through the firewall"),

    rule("refund.hard_cap")
      .on(REFUND_TOOLS)
      .when((ctx) => ctx.amountPaise() > HARD_CAP_PAISE)
      .deny(`Refunds above ₹${HARD_CAP_PAISE / 100} are not allowed`),

    rule("refund.exceeds_paid")
      .on(REFUND_TOOLS)
      .when(async (ctx) => {
        const payment = await ctx.razorpay.payment(ctx.string("payment_id"));
        return (
          payment.status !== "captured" ||
          ctx.amountPaise() + payment.amountRefundedPaise > payment.amountPaise
        );
      })
      .deny("Refund exceeds the refundable amount, or the payment is not captured"),

    rule("refund.duplicate")
      .on(REFUND_TOOLS)
      .when((ctx) =>
        ctx.history.hasRecent({
          tool: ctx.tool,
          match: { payment_id: ctx.string("payment_id"), amount: ctx.amountPaise() },
          withinMs: DUPLICATE_WINDOW_MS,
        }),
      )
      .deny("An identical refund for this payment was made in the last 10 minutes"),

    rule("refund.velocity")
      .on(REFUND_TOOLS)
      .when(async (ctx) => {
        const recent = await ctx.stats.sumLast({
          tools: REFUND_TOOLS,
          windowMs: VELOCITY_WINDOW_MS,
        });
        return (
          recent.amountPaise + ctx.amountPaise() > VELOCITY_MAX_PAISE ||
          recent.count >= VELOCITY_MAX_COUNT
        );
      })
      .deny("Refund velocity limit reached for the last hour"),

    rule("refund.approval")
      .on(REFUND_TOOLS)
      .when((ctx) => ctx.amountPaise() > APPROVAL_THRESHOLD_PAISE)
      .requireApproval({
        via: "telegram",
        timeoutMin: APPROVAL_TIMEOUT_MIN,
        message: `Refund above ₹${APPROVAL_THRESHOLD_PAISE / 100} needs human approval`,
      }),

    rule("refund.allow").on(REFUND_TOOLS).allow(),
  ],
});

export default defaultPolicy;
