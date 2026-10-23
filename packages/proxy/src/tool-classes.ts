/**
 * Classification of upstream Razorpay MCP tools (T002, D-002).
 *
 * Source of truth: `docs/razorpay-tools.json`, discovered from `razorpay/mcp` (server `razorpay-mcp-server` 1.0.0).
 * A coverage test keeps this map in sync with that file: every discovered tool is listed and nothing else is.
 *
 * - `read`  — pure lookups, passed through without policy gating.
 * - `money` — anything that moves money, creates/changes a payment object, contacts a customer, or has any other
 *   side effect upstream. Gated by the policy engine and requires a `reason` (D-004).
 *
 * Lookup is by EXACT name. Anything not in the map (new upstream tools, renamed tools, case/whitespace variants,
 * prototype keys like `constructor`) is `money`: fail closed.
 *
 * Upstream MCP annotations are NOT used: the server marks every tool (even `fetch_payment`) as
 * `destructiveHint: true, readOnlyHint: false`, so they carry no signal and could never be trusted for gating anyway.
 */
export type ToolClass = "read" | "money";

export const TOOL_CLASSES: Readonly<Record<string, ToolClass>> = Object.freeze({
  // Payments
  capture_payment: "money",
  fetch_all_payments: "read",
  fetch_payment: "read",
  /** Read-only, but returns card metadata: output redaction is the proxy's job (T008). */
  fetch_payment_card_details: "read",
  initiate_payment: "money",
  resend_otp: "money",
  submit_otp: "money",
  update_payment: "money",

  // Payment links
  create_payment_link: "money",
  fetch_all_payment_links: "read",
  fetch_payment_link: "read",
  payment_link_notify: "money",
  payment_link_upi_create: "money",
  update_payment_link: "money",

  // Orders
  create_order: "money",
  fetch_all_orders: "read",
  fetch_order: "read",
  fetch_order_payments: "read",
  update_order: "money",

  // Refunds
  create_refund: "money",
  fetch_all_refunds: "read",
  fetch_multiple_refunds_for_payment: "read",
  fetch_refund: "read",
  fetch_specific_refund_for_payment: "read",
  update_refund: "money",

  // QR codes
  close_qr_code: "money",
  create_qr_code: "money",
  fetch_all_qr_codes: "read",
  fetch_payments_for_qr_code: "read",
  fetch_qr_code: "read",
  fetch_qr_codes_by_customer_id: "read",
  fetch_qr_codes_by_payment_id: "read",

  // Settlements
  create_instant_settlement: "money",
  fetch_all_instant_settlements: "read",
  fetch_all_settlements: "read",
  fetch_instant_settlement_with_id: "read",
  fetch_settlement_recon_details: "read",
  fetch_settlement_with_id: "read",

  // Payouts (read-only in this server version)
  fetch_all_payouts: "read",
  fetch_payout_with_id: "read",

  // Tokens
  /**
   * Named like a read, but upstream "first finds or CREATES a customer with the given contact number" and returns
   * saved cards/UPI ids. A side effect plus payment-instrument exposure ⇒ gated.
   */
  fetch_tokens: "money",
} satisfies Record<string, ToolClass>);

/** `read` only for an exact, own-property match; everything else is `money` (D-002 fail closed). */
export function classifyTool(name: string): ToolClass {
  if (typeof name !== "string" || !Object.hasOwn(TOOL_CLASSES, name)) return "money";
  return TOOL_CLASSES[name] === "read" ? "read" : "money";
}

export function isMoneyTool(name: string): boolean {
  return classifyTool(name) === "money";
}
