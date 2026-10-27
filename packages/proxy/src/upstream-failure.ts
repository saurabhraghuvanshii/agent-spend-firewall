/**
 * T010 (security review): what an upstream FAILURE answer to a money call proves.
 *
 * A failure answer is proof that Razorpay did NOT execute the action only when it is a definite Razorpay client-side
 * rejection (e.g. `BAD_REQUEST_ERROR`: validation failed, nothing was created). Everything else — a JSON-RPC error,
 * the MCP server's own HTTP-client timeout / "context canceled" after the SDK sent `notifications/cancelled`, a
 * gateway / server error, a network error, any text we don't recognise — is AMBIGUOUS: Razorpay may still be
 * processing (or have completed) the POST. Only `definite_rejection` may ever lead to `not_happened`.
 *
 * TODO(T015): the exact error text the Razorpay MCP server returns for a rejected refund must be confirmed live.
 * Until then this classifier may never return `definite_rejection` in practice, which means retries effectively
 * never fire and such actions are flagged for a human instead — the fail-safe direction.
 *
 * Only the classification is returned; the body is never kept or logged.
 */

export type UpstreamFailure = "definite_rejection" | "ambiguous" | "none";

/** Razorpay client-error codes that prove the request was rejected before anything was created. Frozen. */
export const DEFINITE_REJECTION_CODES: readonly string[] = Object.freeze(["BAD_REQUEST_ERROR"]);

/**
 * Wording that means the outcome is NOT known (server / gateway side, timeout, cancellation, transport). If any of it
 * appears — even next to a rejection code — the failure is ambiguous.
 */
const AMBIGUOUS_WORDING =
  /SERVER_ERROR|GATEWAY_ERROR|gateway|time[\s_-]*out|timed[\s_-]*out|cancel|deadline|network|connect|\beof\b|reset|refused|unavailable|unreachable|broken pipe|internal|\b(?:status|http)\D{0,12}5\d\d\b/i;

/** Max characters of error text inspected; longer ⇒ ambiguous (never scanned partially). */
export const MAX_FAILURE_TEXT = 16_384;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Classify error text. Empty / oversized / unrecognised ⇒ ambiguous. */
export function classifyFailureText(text: string): Exclude<UpstreamFailure, "none"> {
  if (text.length === 0 || text.length > MAX_FAILURE_TEXT) return "ambiguous";
  if (AMBIGUOUS_WORDING.test(text)) return "ambiguous";
  for (const code of DEFINITE_REJECTION_CODES) {
    // Only in a structured position — the JSON error `"code": "<CODE>"` or the leading token of the text. Anywhere
    // else (e.g. agent-supplied notes / description echoed back in an error) it proves nothing.
    if (new RegExp(`"code"\\s*:\\s*"${code}"`).test(text)) return "definite_rejection";
    if (new RegExp(`^\\s*${code}\\b`).test(text)) return "definite_rejection";
  }
  return "ambiguous";
}

/** Max depth walked by `containsRejectionCode` (deeper ⇒ treated as containing one: fail closed). */
const MAX_ECHO_DEPTH = 32;

/**
 * True iff any string (value or key) at any depth of `value` contains an allowlisted rejection code
 * (case-insensitive), or the structure is too deep to check. Money-call args with such text are denied so an error
 * echoing them can never look like a Razorpay rejection.
 */
export function containsRejectionCode(value: unknown, depth = 0): boolean {
  if (depth > MAX_ECHO_DEPTH) return true;
  if (typeof value === "string") {
    const upper = value.toUpperCase();
    return DEFINITE_REJECTION_CODES.some((c) => upper.includes(c));
  }
  if (Array.isArray(value)) return value.some((v) => containsRejectionCode(v, depth + 1));
  if (isRecord(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (containsRejectionCode(k, depth + 1) || containsRejectionCode(v, depth + 1)) return true;
    }
  }
  return false;
}

/**
 * Classify an MCP `tools/call` result (raw JSON-RPC `result` or a `CallToolResult`): `isError !== true` ⇒ `none`;
 * otherwise the concatenated text content is classified (no text content ⇒ ambiguous).
 */
export function classifyToolResultFailure(result: unknown): UpstreamFailure {
  if (!isRecord(result) || result["isError"] !== true) return "none";
  const content = result["content"];
  if (!Array.isArray(content)) return "ambiguous";
  let text = "";
  for (const item of content) {
    if (!isRecord(item) || item["type"] !== "text" || typeof item["text"] !== "string") {
      return "ambiguous";
    }
    text += `${item["text"]}\n`;
    if (text.length > MAX_FAILURE_TEXT) return "ambiguous";
  }
  return classifyFailureText(text.trim());
}

/** Combine two pieces of evidence: any ambiguity wins; else any definite rejection; else none. */
export function mergeFailure(a: UpstreamFailure, b: UpstreamFailure | undefined): UpstreamFailure {
  if (a === "ambiguous" || b === "ambiguous") return "ambiguous";
  if (a === "definite_rejection" || b === "definite_rejection") return "definite_rejection";
  return "none";
}
