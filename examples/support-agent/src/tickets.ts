/**
 * Support tickets (`tickets/*.json`) and the seed output that maps them to real TEST-mode payments (T015).
 *
 * Ticket text is UNTRUSTED customer input (scenario 2 carries a prompt injection); it is validated for shape and size
 * only and handed to the agent inside a clearly delimited block.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { err, ok, type Result } from "@asf/core";
import { ORDER_ID_PATTERN, PAYMENT_ID_PATTERN } from "@asf/proxy";
import { z } from "zod";

export const TICKET_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;
/** `seed:<ticket id>` (resolved through `seed-output.json`) or a literal `pay_…` id. */
export const PAYMENT_REF = /^(?:seed:[a-z0-9][a-z0-9-]{0,39}|pay_[A-Za-z0-9]{1,40})$/;
export const MAX_TICKET_BODY = 4_000;

export const ticketSchema = z.strictObject({
  id: z.string().regex(TICKET_ID),
  customer: z.string().min(1).max(100),
  body: z.string().min(1).max(MAX_TICKET_BODY),
  paymentRef: z.string().regex(PAYMENT_REF),
});
export type Ticket = z.infer<typeof ticketSchema>;

/** Parse one ticket file's text. The error never echoes the content. */
export function parseTicket(text: string, fileName: string): Result<Ticket> {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return err("ticket.invalid_json", `${fileName} is not valid JSON`);
  }
  const t = ticketSchema.safeParse(json);
  if (!t.success) {
    const paths = t.error.issues.map((i) => i.path.join(".") || "(root)").join(", ");
    return err("ticket.invalid", `${fileName} failed validation at: ${paths}`);
  }
  return ok(t.data);
}

/** All `*.json` tickets in `dir`, sorted by file name; ids must be unique. */
export function loadTickets(dir: string): Result<Ticket[]> {
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .sort();
  } catch {
    return err("ticket.dir", "cannot read the tickets directory");
  }
  const out: Ticket[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    const t = parseTicket(readFileSync(join(dir, f), "utf8"), f);
    if (!t.ok) return t;
    if (seen.has(t.value.id)) return err("ticket.duplicate", `duplicate ticket id in ${f}`);
    seen.add(t.value.id);
    out.push(t.value);
  }
  if (out.length === 0) return err("ticket.none", "no tickets found");
  return ok(out);
}

// ---------------------------------------------------------------------------------------------------------------
// Seed output (`seed-output.json`, gitignored)
// ---------------------------------------------------------------------------------------------------------------

export const PAYMENT_LINK_ID = /^plink_[A-Za-z0-9]{1,40}$/;

export const seedEntrySchema = z.strictObject({
  paymentLinkId: z.string().regex(PAYMENT_LINK_ID),
  /** Payment-link URL (test mode) for the human to pay with a test card. */
  shortUrl: z.url({ protocol: /^https$/ }),
  amountPaise: z.int().min(100).max(10_000_000),
  /** Filled by `seed collect` once paid + captured. */
  paymentId: z.string().regex(PAYMENT_ID_PATTERN).optional(),
  orderId: z.string().regex(ORDER_ID_PATTERN).optional(),
});
export type SeedEntry = z.infer<typeof seedEntrySchema>;

export const seedOutputSchema = z.strictObject({
  version: z.literal(1),
  entries: z.record(z.string().regex(TICKET_ID), seedEntrySchema),
});
export type SeedOutput = z.infer<typeof seedOutputSchema>;

export const SEED_OUTPUT_FILE = "seed-output.json";

export function parseSeedOutput(text: string | undefined): Result<SeedOutput> {
  if (text === undefined) {
    return err(
      "seed.missing",
      `${SEED_OUTPUT_FILE} not found: run \`seed create\` and \`seed collect\``,
    );
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return err("seed.invalid_json", `${SEED_OUTPUT_FILE} is not valid JSON`);
  }
  const s = seedOutputSchema.safeParse(json);
  if (!s.success) return err("seed.invalid", `${SEED_OUTPUT_FILE} failed validation`);
  return ok(s.data);
}

export interface ResolvedPayment {
  readonly paymentId: string;
  readonly orderId?: string;
}

/** A ticket's payment: a literal `pay_…`, or the collected payment of its `seed:<id>` entry. */
export function resolvePayment(
  ticket: Ticket,
  seed: SeedOutput | undefined,
): Result<ResolvedPayment> {
  const ref = ticket.paymentRef;
  if (ref.startsWith("pay_")) return ok({ paymentId: ref });
  const key = ref.slice("seed:".length);
  const entry =
    seed !== undefined && Object.hasOwn(seed.entries, key) ? seed.entries[key] : undefined;
  if (entry === undefined) {
    return err("seed.no_entry", `no seed entry for ticket ${ticket.id}: run \`seed create\``);
  }
  if (entry.paymentId === undefined) {
    return err(
      "seed.not_collected",
      `ticket ${ticket.id} is not paid / collected yet: run \`seed collect\``,
    );
  }
  return ok({
    paymentId: entry.paymentId,
    ...(entry.orderId === undefined ? {} : { orderId: entry.orderId }),
  });
}
