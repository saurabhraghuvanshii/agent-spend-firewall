/**
 * `pnpm --filter @asf/support-agent verify-live -- --yes` — confirm the live Razorpay MCP server behaves the way the
 * firewall assumes (T015 acceptance criteria from T007 / T010). MOVES TEST MONEY (a ₹1 refund), hence `--yes`.
 *
 * Talks DIRECTLY to the Razorpay MCP server (the proxy's hardened docker upstream, `Upstream` +
 * `dockerUpstreamFactory`) as an MCP client — not through the firewall, not through an agent — and reuses the
 * proxy's own parsers so a PASS means the production code path works:
 * 1. `fetch_payment` / `fetch_order` results parse with the proxy's zod schemas (`context-adapters.ts`), both raw and
 *    through the firewall's bounded lookups (`createRazorpayLookup` / `createOrderLookup`).
 * 2. `create_refund` of ₹1 with `notes.asf_attempt = verify-<uuid>` succeeds and echoes the note.
 * 3. `fetch_multiple_refunds_for_payment` honours `count` (count:1/skip:0 ⇒ one item) and returns `notes`
 *    (count:100 contains the marker), and the T010 verifier (`createActionVerifier`) finds the refund (`happened`).
 * 4. An over-refund is rejected, and the T010 classifier (`classifyToolResultFailure`) is run on the error; the raw
 *    error text is printed REDACTED so the pinned definite-rejection shape (D-038) can be compared with reality.
 *
 * Uses the `verify-live` seed payment (₹100; `seed create` / `seed collect`). TEST keys only (exit 2 otherwise).
 * Exit codes: 0 all PASS, 1 any FAIL, 2 refused.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { err, ok, type Result } from "@asf/core";
import {
  ATTEMPT_MARKER_KEY,
  REFUND_LIST_TOOL,
  Upstream,
  buildChildEnv,
  classifyToolResultFailure,
  createActionVerifier,
  createOrderLookup,
  createRazorpayLookup,
  dockerUpstreamFactory,
  escapeForTerminal,
  parseSingleJson,
  razorpayOrderSchema,
  razorpayPaymentSchema,
  redactSecrets,
  redactSensitiveResult,
  systemClock,
  type ActivitySource,
  type TestKeys,
  type UpstreamPaymentPort,
} from "@asf/proxy";
import { z } from "zod";
import { EXIT_REFUSED, loadConfigOrExit } from "./config.js";
import { isMainModule } from "./main-module.js";
import { readSeedOutputFile, rupees } from "./seed.js";
import { cap } from "./transcript.js";

export const VERIFY_REFUND_PAISE = 100;
const CALL_TIMEOUT_MS = 30_000;
/** The firewall's lookups are bounded below the policy budget (`MAX_LOOKUP_TIMEOUT_MS`). */
const FIREWALL_LOOKUP_TIMEOUT_MS = 1_900;
export const VERIFY_SEED_KEY = "verify-live";

export interface Check {
  readonly name: string;
  readonly pass: boolean;
  readonly detail: string;
}

export interface LiveInput {
  readonly paymentId: string;
  readonly orderId: string | undefined;
  readonly marker: string;
  readonly keys: TestKeys;
}

/** History is never read by lookups; any read would be a bug here, so it fails. */
const noStore: ActivitySource = {
  readActivitySince: () => err("verify_live.no_store", "no audit store in verify-live"),
};

function issuePaths(e: z.ZodError): string {
  return e.issues.map((i) => i.path.join(".") || "(root)").join(", ");
}

const createdRefundSchema = z.looseObject({
  id: z.string().regex(/^rfnd_[A-Za-z0-9]{1,40}$/),
  amount: z.int(),
  notes: z.union([z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional(),
});
const refundListSchema = z.looseObject({
  items: z.array(
    z.looseObject({
      id: z.string(),
      notes: z.union([z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional(),
    }),
  ),
});

function hasMarker(notes: unknown, marker: string): boolean {
  return (
    typeof notes === "object" &&
    notes !== null &&
    !Array.isArray(notes) &&
    (notes as Record<string, unknown>)[ATTEMPT_MARKER_KEY] === marker
  );
}

/** Raw text of a tool result, redacted like an agent would see it + key redaction, escaped and capped. */
export function redactedText(
  tool: string,
  content: readonly { type: string; text?: string }[],
  isError: boolean,
  keys: TestKeys,
): string {
  const texts = content.map((c) =>
    c.type === "text" && typeof c.text === "string" ? c.text : "[non-text]",
  );
  const r = redactSensitiveResult(tool, {
    isError,
    content: texts.map((text) => ({ type: "text" as const, text })),
  });
  const joined = r.content.map((c) => (c.type === "text" ? c.text : "[non-text]")).join(" | ");
  return escapeForTerminal(cap(redactSecrets(joined, keys)));
}

/** All live checks, in order. `port` is the upstream (no firewall). Never throws. */
export async function runLiveChecks(port: UpstreamPaymentPort, input: LiveInput): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (name: string, pass: boolean, detail: string): void => {
    checks.push({ name, pass, detail });
  };
  const call = (tool: string, args: Record<string, unknown>) =>
    port.callTool(tool, args, { timeoutMs: CALL_TIMEOUT_MS });

  // 1. fetch_payment shape.
  let paymentAmount: number | undefined;
  let refundable = 0;
  const pay = await call("fetch_payment", { payment_id: input.paymentId });
  if (pay.kind !== "ok") {
    add("fetch_payment matches razorpayPaymentSchema", false, `call failed: ${pay.error}`);
  } else {
    const json = parseSingleJson(pay.result, "payment");
    const p = json.ok ? razorpayPaymentSchema.safeParse(json.value) : undefined;
    if (p === undefined)
      add("fetch_payment matches razorpayPaymentSchema", false, json.ok ? "" : json.error.code);
    else if (!p.success)
      add("fetch_payment matches razorpayPaymentSchema", false, `fails at: ${issuePaths(p.error)}`);
    else {
      paymentAmount = p.data.amount;
      refundable = p.data.amount - p.data.amount_refunded;
      add(
        "fetch_payment matches razorpayPaymentSchema",
        p.data.id === input.paymentId,
        `status ${p.data.status}, ${p.data.currency}, amount ${rupees(p.data.amount)}, refunded ${rupees(p.data.amount_refunded)}`,
      );
    }
  }
  const lookup = await createRazorpayLookup({
    store: noStore,
    upstream: port,
    clock: systemClock,
    lookupTimeoutMs: FIREWALL_LOOKUP_TIMEOUT_MS,
    redact: (s) => redactSecrets(s, input.keys),
  }).payment(input.paymentId);
  add(
    "firewall payment lookup (≤1.9 s) succeeds",
    lookup.ok,
    lookup.ok ? `currency ${lookup.value.currency}` : lookup.error.code,
  );

  // 2. fetch_order shape.
  if (input.orderId === undefined) {
    add("fetch_order matches razorpayOrderSchema", false, "no order id in seed-output.json");
  } else {
    const ord = await call("fetch_order", { order_id: input.orderId });
    if (ord.kind !== "ok")
      add("fetch_order matches razorpayOrderSchema", false, `call failed: ${ord.error}`);
    else {
      const json = parseSingleJson(ord.result, "order");
      const o = json.ok ? razorpayOrderSchema.safeParse(json.value) : undefined;
      if (o === undefined)
        add("fetch_order matches razorpayOrderSchema", false, json.ok ? "" : json.error.code);
      else if (!o.success)
        add("fetch_order matches razorpayOrderSchema", false, `fails at: ${issuePaths(o.error)}`);
      else
        add(
          "fetch_order matches razorpayOrderSchema",
          o.data.id === input.orderId,
          `${o.data.currency}, amount ${rupees(o.data.amount)}`,
        );
    }
    const ol = await createOrderLookup({
      store: noStore,
      upstream: port,
      clock: systemClock,
      lookupTimeoutMs: FIREWALL_LOOKUP_TIMEOUT_MS,
      redact: (s) => redactSecrets(s, input.keys),
    }).order(input.orderId);
    add(
      "firewall order lookup (≤1.9 s) succeeds",
      ol.ok,
      ol.ok ? `currency ${ol.value.currency}` : ol.error.code,
    );
  }

  // 3. ₹1 refund with the firewall's marker.
  if (paymentAmount === undefined || refundable < VERIFY_REFUND_PAISE) {
    add(
      "create_refund ₹1 with notes.asf_attempt",
      false,
      "payment unreadable or nothing left to refund; seed a new verify-live payment",
    );
    return checks;
  }
  const refundArgs = {
    payment_id: input.paymentId,
    amount: VERIFY_REFUND_PAISE,
    notes: { [ATTEMPT_MARKER_KEY]: input.marker },
  };
  const created = await call("create_refund", refundArgs);
  let refundId: string | undefined;
  if (created.kind !== "ok" || created.result.isError === true) {
    add(
      "create_refund ₹1 with notes.asf_attempt",
      false,
      created.kind === "ok" ? "tool error" : `call failed: ${created.error}`,
    );
  } else {
    const json = parseSingleJson(created.result, "refund");
    const r = json.ok ? createdRefundSchema.safeParse(json.value) : undefined;
    if (r?.success === true) {
      refundId = r.data.id;
      add("create_refund ₹1 with notes.asf_attempt", true, `refund ${r.data.id}`);
      add(
        "create_refund echoes notes.asf_attempt",
        hasMarker(r.data.notes, input.marker),
        "notes round-trip in the create response",
      );
    } else {
      add(
        "create_refund ₹1 with notes.asf_attempt",
        false,
        "unexpected create_refund result shape",
      );
    }
  }

  // 4. Listing: count honoured, notes returned.
  const one = await call(REFUND_LIST_TOOL, { payment_id: input.paymentId, count: 1, skip: 0 });
  const oneList = one.kind === "ok" ? parseSingleJson(one.result, "refunds") : undefined;
  const oneParsed = oneList?.ok === true ? refundListSchema.safeParse(oneList.value) : undefined;
  add(
    `${REFUND_LIST_TOOL} honours count:1`,
    oneParsed?.success === true && oneParsed.data.items.length === 1,
    oneParsed?.success === true
      ? `${String(oneParsed.data.items.length)} item(s) returned`
      : "unreadable listing",
  );
  const all = await call(REFUND_LIST_TOOL, { payment_id: input.paymentId, count: 100, skip: 0 });
  const allList = all.kind === "ok" ? parseSingleJson(all.result, "refunds") : undefined;
  const allParsed = allList?.ok === true ? refundListSchema.safeParse(allList.value) : undefined;
  const found =
    allParsed?.success === true ? allParsed.data.items.find((i) => i.id === refundId) : undefined;
  add(
    `${REFUND_LIST_TOOL} returns notes (marker round-trip)`,
    found !== undefined && hasMarker(found.notes, input.marker),
    allParsed?.success === true
      ? `${String(allParsed.data.items.length)} refund(s) listed with count:100`
      : "unreadable listing",
  );
  const finding = await createActionVerifier({
    upstream: port,
    redact: (s) => redactSecrets(s, input.keys),
  }).verify({ attemptId: input.marker, tool: "create_refund", args: refundArgs, failure: "none" });
  add(
    "T010 verifier finds the marked refund (happened)",
    finding.result === "happened" && finding.upstreamRef === refundId,
    `result ${finding.result}${finding.errorCode === undefined ? "" : ` (${finding.errorCode})`}`,
  );

  // 5. Over-refund: what does a definite rejection look like live?
  const over = await call("create_refund", {
    payment_id: input.paymentId,
    amount: paymentAmount + VERIFY_REFUND_PAISE,
  });
  if (over.kind !== "ok") {
    add(
      "over-refund rejected with the pinned error shape",
      false,
      `JSON-RPC / transport error: ${escapeForTerminal(cap(over.message))}`,
    );
  } else if (over.result.isError !== true) {
    add(
      "over-refund rejected with the pinned error shape",
      false,
      "NOT rejected (isError absent): investigate now",
    );
  } else {
    const cls = classifyToolResultFailure(over.result);
    const raw = redactedText("create_refund", over.result.content, true, input.keys);
    add(
      "over-refund rejected with the pinned error shape",
      cls === "definite_rejection",
      `classified ${cls}; raw (redacted): ${raw}`,
    );
  }
  return checks;
}

export function renderTable(checks: readonly Check[]): string {
  const width = Math.max(...checks.map((c) => c.name.length), 10);
  return checks
    .map(
      (c) => `${c.pass ? "PASS" : "FAIL"}  ${c.name.padEnd(width)}  ${escapeForTerminal(c.detail)}`,
    )
    .join("\n");
}

export function parseVerifyArgs(argv: readonly string[]): Result<{ yes: boolean }> {
  let yes = false;
  for (const a of argv) {
    if (a === "--") continue;
    if (a === "--yes") yes = true;
    else return err("example.bad_args", "usage: verify-live -- --yes");
  }
  return ok({ yes });
}

async function main(argv: readonly string[]): Promise<number> {
  const args = parseVerifyArgs(argv);
  if (!args.ok || !args.value.yes) {
    process.stderr.write(
      "verify-live creates a ₹1 TEST-mode refund and attempts a (rejected) over-refund on the verify-live seed\n" +
        "payment, talking to the Razorpay MCP server directly. Re-run with `-- --yes` to proceed.\n",
    );
    return EXIT_REFUSED;
  }
  const cfg = loadConfigOrExit();
  const seed = readSeedOutputFile();
  if (!seed.ok) {
    process.stderr.write(`error: ${seed.error.message}\n`);
    return EXIT_REFUSED;
  }
  const entry = Object.hasOwn(seed.value.entries, VERIFY_SEED_KEY)
    ? seed.value.entries[VERIFY_SEED_KEY]
    : undefined;
  if (entry?.paymentId === undefined) {
    process.stderr.write(
      "error: the verify-live seed payment is not collected: run `seed create` and `seed collect`\n",
    );
    return EXIT_REFUSED;
  }
  const orderId =
    entry.orderId ??
    Object.values(seed.value.entries).find((e) => e.orderId !== undefined)?.orderId;
  const redact = (s: string): string => redactSecrets(s, cfg.keys);
  const log = (l: string): void => {
    process.stderr.write(`[verify-live] ${escapeForTerminal(l)}\n`);
  };
  const base: Record<string, string> = {};
  for (const n of ["PATH", "HOME"]) {
    const v = cfg.shell[n];
    if (typeof v === "string" && v !== "") base[n] = v;
  }
  const childEnv = buildChildEnv(base, cfg.shell, cfg.keys);
  const dockerEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(childEnv)) if (!k.startsWith("RAZORPAY_")) dockerEnv[k] = v;
  const upstream = new Upstream({
    factory: dockerUpstreamFactory({
      image: cfg.image,
      childEnv,
      dockerEnv,
      randomHex: () => randomBytes(8).toString("hex"),
      redact,
      logger: log,
    }),
    logger: log,
    redact,
    callTimeoutMs: CALL_TIMEOUT_MS,
    clientInfo: { name: "asf-verify-live", version: "0.0.0" },
  });
  try {
    const c = await upstream.connect();
    if (!c.ok) {
      process.stderr.write(`error: ${escapeForTerminal(redact(c.error.message))}\n`);
      return 1;
    }
    const marker = `verify-${randomUUID()}`;
    process.stdout.write(`marker notes.${ATTEMPT_MARKER_KEY} = ${marker}\n\n`);
    const checks = await runLiveChecks(upstream, {
      paymentId: entry.paymentId,
      orderId,
      marker,
      keys: cfg.keys,
    });
    process.stdout.write(`${renderTable(checks)}\n`);
    return checks.every((c) => c.pass) ? 0 : 1;
  } finally {
    await upstream.close();
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
