import type { JsonValue } from "./types.js";

export const REDACTED = "[REDACTED]";

/**
 * Normalised keys whose whole value is replaced on an EXACT match.
 * Short / ambiguous terms live here (not in the substring list) so they cannot hit innocent keys
 * such as `company` (`pan`), `groupid` (`upi`), `account_id` or `cc` inside `success`.
 */
const DENY_EXACT: ReadonlySet<string> = new Set([
  "cc",
  "pan",
  "name",
  "customername",
  "fullname",
  "firstname",
  "lastname",
  "beneficiaryname",
  "accountholdername",
  "acno",
  "accno",
  "acctno",
  "pannumber",
  "panno",
  "upiid",
  // `customer` is exact (not a substring) so `customer_id` survives; `customername` is a substring below.
  "customer",
]);

/**
 * Normalised substrings: any key CONTAINING one of these has its whole value replaced
 * (e.g. `client_secret`, `access_token`, `razorpay_signature`, `customer_email`, `expiry_year`).
 * `account` alone is deliberately absent so Razorpay ids like `account_id` / `fund_account_id` survive.
 */
const DENY_SUBSTRINGS: readonly string[] = [
  "secret",
  "token",
  "password",
  "passwd",
  "signature",
  "apikey",
  "authorization",
  "email",
  "phone",
  "mobile",
  "contact",
  "vpa",
  "card",
  "cvv",
  "expiry",
  "ifsc",
  "accountnumber",
  "accountno",
  "bankaccount",
  "aadhaar",
  "address",
  "beneficiary",
  "holder",
  "payee",
  "customername",
];

/**
 * Razorpay reference ids that would otherwise be caught by a substring rule but are not PII.
 * Their string values are still passed through `redactText`.
 */
const ALLOW_EXACT: ReadonlySet<string> = new Set(["contactid", "cardid"]);

/**
 * EXACT normalised keys whose integer values are amounts (paise) and are exempt from the phone / 12-digit
 * card patterns (e.g. 6_000_000_000 paise looks like a 10-digit Indian mobile number). Deliberately exact:
 * `amount_note`, `max_amount`, … are NOT exempt. Even under these keys, integers with >= 13 digits are still
 * redacted (no real paise amount is >= 10^12 paise = ₹10^10; such a value is almost certainly a card number).
 */
const AMOUNT_KEYS: ReadonlySet<string> = new Set([
  "amount",
  "amountpaid",
  "amountrefunded",
  "amountdue",
  "amountpaise",
  "baseamount",
  "fee",
  "tax",
]);
const AMOUNT_MAX_DIGITS = 12;

/**
 * Account-number heuristic: a key containing `account`, or an `acc`/`acct` key (`acc`, `acct`, `acc_num`, …),
 * whose value is a 9–18 digit integer or digit-only string is treated as a bank account number.
 * Keys ending in `id` (`account_id`, `fund_account_id`, …) are Razorpay ids and exempt.
 */
const ACCOUNT_SHORT_KEY_RE = /^acc(?:t)?(?:no|num|number)?$/;
const ACCOUNT_DIGITS_RE = /^\d{9,18}$/;

/** Lowercase and strip every non-alphanumeric character (`Client-Secret`, `access.token` → `clientsecret`, `accesstoken`). */
export function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// Order matters: API keys, then email/VPA, then long digit runs (cards, accounts), then phones,
// then high-entropy tokens that follow a secret-ish word.
const RZP_KEY_RE = /rzp_(?:test|live)_[A-Za-z0-9]+/g;
const EMAIL_VPA_RE = /\S+@\S+/g;
/** 12–19 digits, optionally grouped with single spaces/hyphens (card / account numbers). */
const LONG_DIGITS_RE = /\d(?:[ .-]?\d){11,18}/g;
/**
 * Indian mobile numbers, optional +91 / 91 prefix. A letter prefix does not protect it (`mobile9876543210`),
 * but it must not sit inside a longer digit run, follow `+`, or be part of an `_`-delimited id token
 * (`pay_29QQoUBi66xm2f`, `cust_Ab9876543210`), and must not be followed by a word character.
 */
const PHONE_RE = /(?<![\d+])(?<!_[A-Za-z0-9]*)(?:\+?91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\w)/g;
/** Indian PAN (Permanent Account Number): 5 letters, 4 digits, 1 letter. */
const PAN_RE = /\b[A-Z]{5}\d{4}[A-Z]\b/g;
/**
 * A standalone run of >= 20 base62 chars appearing within 15 chars after the word
 * secret / key / token / password / passwd / signature (case-insensitive, optional plural).
 * The trigger word must not be part of a longer alphabetic word (`keyboard`, `monkey` do not trigger),
 * but `_`/digits may border it (`key_secret: …`). Razorpay ids (`pay_` + 14 chars) are too short to match.
 */
const SECRET_CONTEXT_RE =
  /(?<![A-Za-z])((?:secret|key|token|password|passwd|signature)s?)(?![A-Za-z])([^\n]{0,15}?)(?<![A-Za-z0-9])[A-Za-z0-9]{20,}(?![A-Za-z0-9])/gi;

/** Whole-value numeric patterns: card/account (12–19 digits) or Indian mobile (10 digits, 6–9, optional 91). */
const NUMERIC_CARD_RE = /^\d{12,19}$/;
const NUMERIC_PHONE_RE = /^(?:91)?[6-9]\d{9}$/;

/**
 * Scrub secrets and PII patterns out of free text (e.g. the agent's `reason`). Pure.
 *
 * Known limit: a bare high-entropy secret (e.g. a 24-char Razorpay key secret) is only caught when it follows a
 * secret-ish word (see SECRET_CONTEXT_RE). Unconditional redaction of long base62 runs is deliberately not done:
 * it would over-redact Razorpay ids and other opaque references. Callers must keep secrets out of free text.
 */
export function redactText(s: string): string {
  return s
    .replace(RZP_KEY_RE, REDACTED)
    .replace(EMAIL_VPA_RE, REDACTED)
    .replace(LONG_DIGITS_RE, REDACTED)
    .replace(PHONE_RE, REDACTED)
    .replace(PAN_RE, REDACTED)
    .replace(SECRET_CONTEXT_RE, (_m, word: string, gap: string) => `${word}${gap}${REDACTED}`);
}

export interface RedactOptions {
  /** Additional keys to deny (exact match); normalised the same way as the built-in list. */
  extraKeys?: readonly string[];
}

/**
 * Return a redacted deep copy of `value`. Does not mutate the input; deterministic.
 *
 * - Denylisted keys (exact or substring rules above, plus `extraKeys`) have their entire value replaced by `REDACTED`.
 * - Every string value is passed through `redactText`.
 * - Integer values that look like a card/account number (12–19 digits) or Indian mobile number are replaced
 *   by `REDACTED`. Exact amount keys (`amount`, `amount_refunded`, `fee`, …) are exempt, except for integers
 *   with >= 13 digits, which are always redacted. Note: millisecond timestamps (13 digits) are over-redacted by
 *   this rule; Razorpay uses second-resolution timestamps.
 * - Under account-like keys (`*account*`, `acc`, `acct_no`, … but not `*id`), a 9–18 digit integer or digit
 *   string is replaced by `REDACTED`.
 * - Object KEYS that themselves contain PII (i.e. `redactText(key) !== key`) are renamed to
 *   `[REDACTED_KEY_<n>]`, where `n` counts from 0 per object over the offending keys in sorted order
 *   (skipping names already present), so output is independent of insertion order.
 */
export function redact(value: JsonValue, opts?: RedactOptions): JsonValue {
  const extra = new Set((opts?.extraKeys ?? []).map(normaliseKey));
  return walk(value, null, extra);
}

function isDeniedKey(normKey: string, extra: ReadonlySet<string>): boolean {
  if (DENY_EXACT.has(normKey) || extra.has(normKey)) return true;
  if (ALLOW_EXACT.has(normKey)) return false;
  return DENY_SUBSTRINGS.some((s) => normKey.includes(s));
}

function isSensitiveInteger(n: number): boolean {
  if (!Number.isInteger(n)) return false;
  const digits = String(Math.abs(n));
  return NUMERIC_CARD_RE.test(digits) || NUMERIC_PHONE_RE.test(digits);
}

function isAccountKey(normKey: string | null): boolean {
  if (normKey === null || normKey.endsWith("id")) return false;
  return normKey.includes("account") || ACCOUNT_SHORT_KEY_RE.test(normKey);
}

function isAccountDigits(value: string | number): boolean {
  if (typeof value === "number" && !Number.isInteger(value)) return false;
  const s = typeof value === "number" ? String(Math.abs(value)) : value.trim();
  return ACCOUNT_DIGITS_RE.test(s);
}

function walk(value: JsonValue, normKey: string | null, extra: ReadonlySet<string>): JsonValue {
  if ((typeof value === "string" || typeof value === "number") && isAccountKey(normKey)) {
    if (isAccountDigits(value)) return REDACTED;
  }
  if (typeof value === "string") return redactText(value);
  if (typeof value === "number") {
    if (normKey !== null && AMOUNT_KEYS.has(normKey)) {
      const tooLong = Number.isInteger(value) && String(Math.abs(value)).length > AMOUNT_MAX_DIGITS;
      return tooLong ? REDACTED : value;
    }
    return isSensitiveInteger(value) ? REDACTED : value;
  }
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => walk(v, normKey, extra));

  const keys = Object.keys(value);
  const renamed = renamePiiKeys(keys);
  // Object.fromEntries uses define semantics, so a "__proto__" key cannot alter the prototype.
  return Object.fromEntries(
    keys.map((key): [string, JsonValue] => {
      const childNorm = normaliseKey(key);
      const v = value[key] as JsonValue;
      const outKey = renamed.get(key) ?? key;
      return [outKey, isDeniedKey(childNorm, extra) ? REDACTED : walk(v, childNorm, extra)];
    }),
  );
}

/** Map each PII-bearing key to a deterministic placeholder name (see `redact` docs). */
function renamePiiKeys(keys: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  const offending = keys.filter((k) => redactText(k) !== k).sort();
  if (offending.length === 0) return out;
  const taken = new Set(keys);
  let n = 0;
  for (const key of offending) {
    let name = `[REDACTED_KEY_${n}]`;
    while (taken.has(name)) name = `[REDACTED_KEY_${++n}]`;
    taken.add(name);
    out.set(key, name);
    n++;
  }
  return out;
}
