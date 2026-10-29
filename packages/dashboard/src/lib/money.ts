/**
 * ₹ formatting from INTEGER paise (AGENTS.md rule 4). No float division ever touches the amount: rupees and paise are
 * split with BigInt arithmetic, the rupee part is grouped by `Intl.NumberFormat('en-IN', { currency: 'INR' })` (which
 * formats a bigint exactly) and the two-digit paise string is spliced into its fraction slot.
 */
const INR = new Intl.NumberFormat("en-IN", {
  style: "currency",
  currency: "INR",
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});

/** `12345` ⇒ `"₹123.45"`. `undefined` for anything that is not an integer (a float, NaN, an unsafe number). */
export function formatPaise(amountPaise: number | bigint): string | undefined {
  let p: bigint;
  if (typeof amountPaise === "bigint") p = amountPaise;
  else if (Number.isSafeInteger(amountPaise)) p = BigInt(amountPaise);
  else return undefined;
  const negative = p < 0n;
  const abs = negative ? -p : p;
  const rupees = abs / 100n;
  const paise = (abs % 100n).toString().padStart(2, "0");
  const parts = INR.formatToParts(rupees);
  let sawFraction = false;
  const text = parts
    .map((part) => {
      if (part.type !== "fraction") return part.value;
      sawFraction = true;
      return paise;
    })
    .join("");
  const out = sawFraction ? text : `${text}.${paise}`;
  return negative ? `-${out}` : out;
}
