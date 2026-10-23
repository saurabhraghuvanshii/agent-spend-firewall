import { createHash } from "node:crypto";
import type { Hasher } from "@asf/core";

/** Node `crypto` implementation of the core hashing port: lowercase hex SHA-256 of UTF-8 input. */
export const nodeHasher: Hasher = {
  sha256Hex(input: string): string {
    return createHash("sha256").update(input, "utf8").digest("hex");
  },
};
