/**
 * zod schemas for every API response the dashboard reads (T013 views, D-036). Validation happens at the boundary in
 * `client.ts` / the event stream: anything that does not match is an error state in the UI, never a crash and never
 * rendered as if it were valid.
 *
 * Money: `amountPaise` must be a non-negative SAFE INTEGER (paise); a float or unsafe number is rejected.
 */
import { z } from "zod";

export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

const decisionSchema = z.enum(["allow", "deny", "require_approval", "transform"]);
export type DecisionKind = z.infer<typeof decisionSchema>;

const seqSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const idSchema = z.string().min(1).max(256);
const paiseSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

/** The API's `{ untrusted: true, label, text }` wrapper around an agent-supplied reason. */
export const untrustedTextSchema = z.object({
  untrusted: z.literal(true),
  label: z.string().max(200),
  text: z.string().max(20_000),
});
export type UntrustedTextView = z.infer<typeof untrustedTextSchema>;

const common = {
  seq: seqSchema,
  id: idSchema,
  ts: z.string().min(1).max(64),
  hash: z.string().regex(/^[0-9a-f]{64}$/),
};

export const attemptViewSchema = z.object({
  kind: z.literal("attempt"),
  ...common,
  sessionId: idSchema,
  tool: idSchema,
  decision: decisionSchema,
  matchedRules: z.array(idSchema).max(200),
  argsRedacted: jsonValueSchema,
  originalArgsRedacted: jsonValueSchema.optional(),
  amountPaise: paiseSchema.optional(),
  reason: untrustedTextSchema,
  approver: idSchema.optional(),
  retryOf: idSchema.optional(),
  shadow: z.literal(true).optional(),
  wouldDecision: decisionSchema.optional(),
  untrustedFields: z.array(z.string().max(64)).max(20),
});
export type AttemptView = z.infer<typeof attemptViewSchema>;

export const outcomeViewSchema = z.object({
  kind: z.literal("outcome"),
  ...common,
  attemptId: idSchema,
  outcome: z.enum(["success", "upstream_error", "timeout", "denied", "not_forwarded"]),
  latencyMs: z.number().int().nonnegative(),
  errorCode: idSchema.optional(),
  upstreamRef: idSchema.optional(),
});
export type OutcomeView = z.infer<typeof outcomeViewSchema>;

export const verificationViewSchema = z.object({
  kind: z.literal("verification"),
  ...common,
  attemptId: idSchema,
  trigger: z.string().max(32),
  result: z.enum(["happened", "not_happened", "unknown"]),
  method: z.string().max(64),
  needsHuman: z.boolean(),
  upstreamRef: idSchema.optional(),
  errorCode: idSchema.optional(),
  resolver: idSchema.optional(),
});
export type VerificationView = z.infer<typeof verificationViewSchema>;

export const approvalRecordViewSchema = z.object({
  kind: z.literal("approval"),
  ...common,
  attemptId: idSchema,
  approvalId: idSchema,
  decision: z.enum(["approved", "rejected", "expired"]),
  approver: idSchema.optional(),
});
export type ApprovalRecordView = z.infer<typeof approvalRecordViewSchema>;

export const modeViewSchema = z.object({
  kind: z.literal("mode"),
  ...common,
  killSwitch: z.boolean(),
  shadow: z.boolean(),
  actor: idSchema,
});
export type ModeRecordView = z.infer<typeof modeViewSchema>;

export const invalidViewSchema = z.object({ kind: z.literal("invalid"), seq: seqSchema });
export type InvalidView = z.infer<typeof invalidViewSchema>;

export const recordViewSchema = z.discriminatedUnion("kind", [
  attemptViewSchema,
  outcomeViewSchema,
  verificationViewSchema,
  approvalRecordViewSchema,
  modeViewSchema,
  invalidViewSchema,
]);
export type RecordView = z.infer<typeof recordViewSchema>;

const recordsSchema = z.array(recordViewSchema).max(5000);

export const auditPageSchema = z.object({
  records: recordsSchema,
  nextCursor: seqSchema.nullable(),
});
export type AuditPage = z.infer<typeof auditPageSchema>;

export const sessionSchema = z.object({
  sessionId: idSchema,
  records: recordsSchema,
  truncated: z.boolean(),
});
export type SessionView = z.infer<typeof sessionSchema>;

export const verifySchema = z.union([
  z.object({
    ok: z.literal(true),
    count: z.number().int().nonnegative(),
    headHash: z
      .string()
      .regex(/^[0-9a-f]{64}$/)
      .nullable(),
    danglingAttempts: z.number().int().nonnegative(),
  }),
  z.object({
    ok: z.literal(false),
    brokenAt: z.object({
      index: z.number().int().nonnegative(),
      seq: z.number().int(),
      id: z.string().max(256).nullable(),
      reason: z.string().max(64),
    }),
  }),
]);
export type VerifyView = z.infer<typeof verifySchema>;

export const pendingApprovalSchema = z.object({
  approvalId: idSchema,
  attemptId: idSchema,
  sessionId: idSchema,
  tool: idSchema,
  ruleId: idSchema,
  state: z.enum(["pending", "approved", "rejected", "expired"]),
  createdAt: z.string().max(64),
  expiresAt: z.string().max(64),
  argsRedacted: jsonValueSchema.optional(),
  amountPaise: paiseSchema.optional(),
  reason: untrustedTextSchema.optional(),
  untrustedFields: z.array(z.string().max(64)).max(20).optional(),
});
export type PendingApproval = z.infer<typeof pendingApprovalSchema>;

export const approvalsSchema = z.object({ approvals: z.array(pendingApprovalSchema).max(1000) });

export const decisionResponseSchema = z.object({
  approvalId: idSchema,
  status: z.enum(["approved", "rejected"]),
  approver: idSchema,
  message: z.string().max(500),
});
export type DecisionResponse = z.infer<typeof decisionResponseSchema>;

export const modeStateSchema = z.object({
  killSwitch: z.boolean(),
  shadow: z.boolean(),
  changedAt: z.string().max(64).optional(),
  actor: idSchema.optional(),
  recordId: idSchema.optional(),
});
export type ModeState = z.infer<typeof modeStateSchema>;

export const modeResponseSchema = z.object({ mode: modeStateSchema });
export const setModeResponseSchema = z.object({ changed: z.boolean(), mode: modeStateSchema });

export const errorBodySchema = z.object({
  error: z.object({ code: z.string().max(100), message: z.string().max(1000) }),
});

/** Payloads of `GET /events` (`data:` of each SSE event, JSON). */
export const auditEventSchema = z.object({ type: z.literal("audit"), records: recordsSchema });
export const approvalsEventSchema = z.object({
  type: z.literal("approvals"),
  pending: z.array(idSchema).max(1000),
});
export const errorEventSchema = z.object({ type: z.literal("error"), code: z.string().max(100) });
