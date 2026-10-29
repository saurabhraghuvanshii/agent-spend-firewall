/**
 * `pnpm --filter @asf/support-agent seed create|collect` — TEST-mode payments for the demo tickets (T015, D-039).
 *
 * Razorpay test mode can't create a captured payment by API alone, so seeding is two manual-assisted steps:
 * 1. `seed create`: one payment link per demo ticket (+ one for `verify-live`) via the `razorpay` SDK, with
 *    `notes.asf_seed = <ticket id>`. Prints the link URLs: open each and pay with a Razorpay TEST card.
 * 2. `seed collect`: fetch each link, take its payment, capture it if only `authorized`, check it is `captured`,
 *    INR and the expected amount (zod at the boundary), and write `seed-output.json` (gitignored):
 *    ticket → payment link, payment id, order id.
 *
 * TEST keys only (`rzp_test_`; any `rzp_live_` ⇒ exit 2). Nothing secret is printed; SDK errors are reduced to
 * their HTTP status and Razorpay error code.
 */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, type Result } from "@asf/core";
import { escapeForTerminal, PAYMENT_ID_PATTERN } from "@asf/proxy";
import Razorpay from "razorpay";
import { z } from "zod";
import { loadConfigOrExit, EXIT_REFUSED } from "./config.js";
import { isMainModule } from "./main-module.js";
import {
  PAYMENT_LINK_ID,
  SEED_OUTPUT_FILE,
  parseSeedOutput,
  seedOutputSchema,
  type SeedEntry,
  type SeedOutput,
} from "./tickets.js";

/** What each demo ticket's customer paid (integer paise), chosen against `policies/default.ts` (see README). */
export const SEED_PLAN: Readonly<Record<string, { amountPaise: number; description: string }>> =
  Object.freeze({
    // ₹1,200 paid; the ticket justifies ₹300 ⇒ under the ₹2,000 approval threshold ⇒ allow.
    "late-delivery": { amountPaise: 120_000, description: "ASF demo: late delivery order" },
    // ₹1,500 paid; the injected "refund ₹25,000" is over the ₹10,000 hard cap and over the paid amount ⇒ deny.
    "prompt-injection": { amountPaise: 150_000, description: "ASF demo: headphones order" },
    // ₹900 paid; ₹500 refund (allowed) whose response is delayed by ASF_DEMO_DELAY_REFUND_MS.
    timeout: { amountPaise: 90_000, description: "ASF demo: phone case + cable order" },
    // ₹6,000 paid; ₹4,500 refund ⇒ over ₹2,000, under ₹10,000 ⇒ require_approval (Telegram).
    approval: { amountPaise: 600_000, description: "ASF demo: blender order" },
    // ₹100 paid; verify-live refunds ₹1 of it and attempts an over-refund (rejected).
    "verify-live": { amountPaise: 10_000, description: "ASF verify-live payment" },
  });

/** The narrow slice of the Razorpay SDK seeding needs (results are `unknown` until zod-validated). */
export interface SeedGateway {
  createLink(body: {
    amount: number;
    currency: "INR";
    description: string;
    reference_id: string;
    notes: Record<string, string>;
    /** Fictional name only: no email / contact (no PII, and nothing to notify). */
    customer: { name: string };
    notify: { sms: false; email: false };
  }): Promise<unknown>;
  fetchLink(id: string): Promise<unknown>;
  fetchPayment(id: string): Promise<unknown>;
  capture(id: string, amountPaise: number): Promise<unknown>;
}

const createdLinkSchema = z.looseObject({
  id: z.string().regex(PAYMENT_LINK_ID),
  short_url: z.url({ protocol: /^https$/ }),
  amount: z.int(),
  currency: z.literal("INR"),
});

const fetchedLinkSchema = z.looseObject({
  id: z.string().regex(PAYMENT_LINK_ID),
  status: z.string(),
  payments: z
    .array(z.looseObject({ payment_id: z.string().regex(PAYMENT_ID_PATTERN), status: z.string() }))
    .nullable()
    .optional(),
});

/** A seeded payment must be captured, INR, the planned amount, and not refunded yet (by zod, at the boundary). */
export const seededPaymentSchema = z.looseObject({
  id: z.string().regex(PAYMENT_ID_PATTERN),
  status: z.literal("captured"),
  currency: z.literal("INR"),
  amount: z.int().positive(),
  amount_refunded: z.int().nonnegative(),
  order_id: z
    .string()
    .regex(/^order_[A-Za-z0-9]{1,40}$/)
    .nullable()
    .optional(),
});

const authorizedSchema = z.looseObject({
  id: z.string().regex(PAYMENT_ID_PATTERN),
  status: z.string(),
  amount: z.int().positive(),
  currency: z.string(),
});

/** HTTP status + Razorpay error code of an SDK error; never the description (it can echo input). */
export function describeSdkError(e: unknown): string {
  const shape = z
    .looseObject({
      statusCode: z.number().optional(),
      error: z
        .looseObject({
          code: z
            .string()
            .regex(/^[A-Z_]{1,40}$/)
            .optional(),
        })
        .optional(),
    })
    .safeParse(e);
  const name = e instanceof Error && /^[A-Za-z]{1,40}$/.test(e.name) ? e.name : "unknown error";
  if (!shape.success) return name;
  if (shape.data.statusCode === undefined && shape.data.error?.code === undefined) return name;
  const status =
    shape.data.statusCode === undefined ? "" : `HTTP ${String(shape.data.statusCode)} `;
  return `${status}${shape.data.error?.code ?? "error"}`.trim();
}

export async function seedCreate(
  gw: SeedGateway,
  existing: SeedOutput | undefined,
  randomHex: () => string,
): Promise<Result<SeedOutput>> {
  const entries: Record<string, SeedEntry> = { ...(existing?.entries ?? {}) };
  for (const [key, plan] of Object.entries(SEED_PLAN)) {
    if (Object.hasOwn(entries, key)) continue; // already created: keep (idempotent re-run)
    let raw: unknown;
    try {
      raw = await gw.createLink({
        amount: plan.amountPaise,
        currency: "INR",
        description: plan.description,
        reference_id: `asf-${key}-${randomHex()}`.slice(0, 40),
        notes: { asf_seed: key },
        customer: { name: "ASF Demo Customer" },
        notify: { sms: false, email: false },
      });
    } catch (e: unknown) {
      return err(
        "seed.create_failed",
        `creating the payment link for ${key} failed (${describeSdkError(e)})`,
      );
    }
    const link = createdLinkSchema.safeParse(raw);
    if (!link.success || link.data.amount !== plan.amountPaise) {
      return err("seed.create_malformed", `unexpected payment link response for ${key}`);
    }
    entries[key] = {
      paymentLinkId: link.data.id,
      shortUrl: link.data.short_url,
      amountPaise: plan.amountPaise,
    };
  }
  return ok({ version: 1, entries });
}

export interface CollectReport {
  readonly key: string;
  readonly status: "collected" | "already" | "unpaid" | "invalid";
  readonly detail: string;
}

export async function seedCollect(
  gw: SeedGateway,
  seed: SeedOutput,
): Promise<{ output: SeedOutput; report: CollectReport[] }> {
  const entries: Record<string, SeedEntry> = { ...seed.entries };
  const report: CollectReport[] = [];
  for (const [key, entry] of Object.entries(seed.entries)) {
    if (entry.paymentId !== undefined) {
      report.push({ key, status: "already", detail: entry.paymentId });
      continue;
    }
    try {
      const link = fetchedLinkSchema.safeParse(await gw.fetchLink(entry.paymentLinkId));
      if (!link.success || link.data.id !== entry.paymentLinkId) {
        report.push({ key, status: "invalid", detail: "unexpected payment link response" });
        continue;
      }
      const paid = (link.data.payments ?? []).filter(
        (p) => p.status === "captured" || p.status === "authorized",
      );
      const first = paid[0];
      if (first === undefined) {
        report.push({ key, status: "unpaid", detail: `link ${link.data.status}: pay it first` });
        continue;
      }
      if (paid.length > 1) {
        report.push({ key, status: "invalid", detail: "more than one payment on the link" });
        continue;
      }
      let payment: unknown = await gw.fetchPayment(first.payment_id);
      const pre = authorizedSchema.safeParse(payment);
      if (!pre.success || pre.data.id !== first.payment_id) {
        report.push({ key, status: "invalid", detail: "unexpected payment response" });
        continue;
      }
      if (pre.data.status === "authorized") {
        if (pre.data.currency !== "INR" || pre.data.amount !== entry.amountPaise) {
          report.push({
            key,
            status: "invalid",
            detail: "authorized payment is not the planned INR amount",
          });
          continue;
        }
        await gw.capture(pre.data.id, entry.amountPaise);
        payment = await gw.fetchPayment(pre.data.id);
      }
      const p = seededPaymentSchema.safeParse(payment);
      if (!p.success || p.data.id !== first.payment_id) {
        report.push({ key, status: "invalid", detail: "payment is not a captured INR payment" });
        continue;
      }
      if (p.data.amount !== entry.amountPaise) {
        report.push({ key, status: "invalid", detail: "payment amount differs from the plan" });
        continue;
      }
      const orderId = p.data.order_id ?? undefined;
      entries[key] = {
        ...entry,
        paymentId: p.data.id,
        ...(orderId === undefined ? {} : { orderId }),
      };
      report.push({ key, status: "collected", detail: p.data.id });
    } catch (e: unknown) {
      report.push({
        key,
        status: "invalid",
        detail: `Razorpay call failed (${describeSdkError(e)})`,
      });
    }
  }
  return { output: { version: 1, entries }, report };
}

export function renderSeedOutput(s: SeedOutput): string {
  // Re-validate before writing: never persist something the readers would refuse.
  return `${JSON.stringify(seedOutputSchema.parse(s), null, 2)}\n`;
}

/** ₹ display of integer paise (BigInt split: no floating-point money). */
export function rupees(paise: number): string {
  if (!Number.isSafeInteger(paise)) return "₹?";
  const b = BigInt(paise);
  const sign = b < 0n ? "-" : "";
  const abs = b < 0n ? -b : b;
  const r = abs / 100n;
  const p = abs % 100n;
  return `${sign}₹${r.toLocaleString("en-IN")}${p === 0n ? "" : `.${p.toString().padStart(2, "0")}`}`;
}

function razorpayGateway(keyId: string, keySecret: string): SeedGateway {
  const rzp = new Razorpay({ key_id: keyId, key_secret: keySecret });
  return {
    createLink: (body) => rzp.paymentLink.create(body),
    fetchLink: (id) => rzp.paymentLink.fetch(id),
    fetchPayment: (id) => rzp.payments.fetch(id),
    capture: (id, amountPaise) => rzp.payments.capture(id, amountPaise, "INR"),
  };
}

function writeAtomic(path: string, content: string): void {
  const tmp = `${path}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, content, { mode: 0o600 });
  renameSync(tmp, path);
}

export const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SEED_OUTPUT_PATH = join(PACKAGE_DIR, SEED_OUTPUT_FILE);

export function readSeedOutputFile(path: string = SEED_OUTPUT_PATH): Result<SeedOutput> {
  return parseSeedOutput(existsSync(path) ? readFileSync(path, "utf8") : undefined);
}

const USAGE = "usage: pnpm --filter @asf/support-agent seed create|collect";

async function main(argv: readonly string[]): Promise<number> {
  const cmd = argv[0] === "--" ? argv[1] : argv[0];
  if (cmd !== "create" && cmd !== "collect") {
    process.stderr.write(`${USAGE}\n`);
    return EXIT_REFUSED;
  }
  const cfg = loadConfigOrExit();
  const gw = razorpayGateway(cfg.keys.keyId, cfg.keys.keySecret);
  if (cmd === "create") {
    const prev = existsSync(SEED_OUTPUT_PATH) ? readSeedOutputFile() : undefined;
    if (prev !== undefined && !prev.ok) {
      process.stderr.write(`error: ${prev.error.message}\n`);
      return 1;
    }
    const r = await seedCreate(gw, prev?.value, () => randomBytes(4).toString("hex"));
    if (!r.ok) {
      process.stderr.write(`error: ${escapeForTerminal(r.error.message)}\n`);
      return 1;
    }
    writeAtomic(SEED_OUTPUT_PATH, renderSeedOutput(r.value));
    process.stdout.write(
      "Payment links (TEST mode). Open each and pay with a Razorpay TEST card\n" +
        "(https://razorpay.com/docs/payments/payments/test-card-details/), then run `seed collect`.\n\n",
    );
    for (const [key, e] of Object.entries(r.value.entries)) {
      const state = e.paymentId === undefined ? "to pay" : `paid (${e.paymentId})`;
      process.stdout.write(
        `  ${key.padEnd(18)} ${rupees(e.amountPaise).padStart(9)}  ${escapeForTerminal(e.shortUrl)}  ${state}\n`,
      );
    }
    process.stdout.write(`\nwrote ${SEED_OUTPUT_PATH}\n`);
    return 0;
  }
  const seed = readSeedOutputFile();
  if (!seed.ok) {
    process.stderr.write(`error: ${seed.error.message}\n`);
    return 1;
  }
  const { output, report } = await seedCollect(gw, seed.value);
  writeAtomic(SEED_OUTPUT_PATH, renderSeedOutput(output));
  for (const r of report) {
    process.stdout.write(
      `  ${r.key.padEnd(18)} ${r.status.padEnd(10)} ${escapeForTerminal(r.detail)}\n`,
    );
  }
  const missing = report.filter((r) => r.status === "unpaid" || r.status === "invalid").length;
  process.stdout.write(`\nwrote ${SEED_OUTPUT_PATH}\n`);
  return missing === 0 ? 0 : 1;
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
