/**
 * Firewall-generated ids (audit attempt ids, stub approval ids). They are passed through the agent-facing result
 * filter only when core `redactText` leaves them unchanged (`result-redaction.ts`), and a random UUID occasionally
 * contains a digit run that `redactText` treats as a card / account / phone number. Ids are therefore drawn until
 * they are redaction-safe, so a legitimate id always stays usable while a look-alike carrying digits is redacted.
 */
import { randomUUID } from "node:crypto";
import { redactText } from "@asf/core";

/** Upper bound on draws; the chance a v4 UUID trips `redactText` is about 1 %, so this is never reached in practice. */
const MAX_DRAWS = 64;

/**
 * A lowercase v4 UUID that `redactText` leaves unchanged. `prefix` is prepended before the check (e.g. `apr_`).
 * If no draw qualifies within `MAX_DRAWS` the last draw is returned: it is still a valid unique id, it would only
 * be redacted for the agent (over-redaction, never a leak).
 */
export function redactionSafeUuid(prefix = "", gen: () => string = randomUUID): string {
  let id = `${prefix}${gen()}`;
  for (let i = 1; i < MAX_DRAWS && redactText(id) !== id; i++) id = `${prefix}${gen()}`;
  return id;
}
