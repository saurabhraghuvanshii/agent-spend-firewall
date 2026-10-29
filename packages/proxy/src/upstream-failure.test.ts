/** T010 security review: only a definite Razorpay client rejection proves non-execution. */
import { describe, expect, it } from "vitest";
import {
  containsRejectionCode,
  classifyFailureText,
  classifyToolResultFailure,
  DEFINITE_REJECTION_CODES,
  MAX_FAILURE_TEXT,
  mergeFailure,
} from "./upstream-failure.js";

const toolError = (...texts: string[]) => ({
  isError: true,
  content: texts.map((text) => ({ type: "text", text })),
});

/** Razorpay's API error envelope — the only shape that proves a rejection (D-038). */
const REJECTION = '{"error":{"code":"BAD_REQUEST_ERROR","description":"invalid amount"}}';

describe("classifyFailureText", () => {
  it("the whole text is a JSON object with top-level error.code BAD_REQUEST_ERROR ⇒ definite rejection", () => {
    expect(classifyFailureText(REJECTION)).toBe("definite_rejection");
    expect(classifyFailureText('{ "error": { "code" :  "BAD_REQUEST_ERROR" } }')).toBe(
      "definite_rejection",
    );
    expect(classifyFailureText(`  ${REJECTION}\n`)).toBe("definite_rejection");
    expect(
      classifyFailureText(
        '{"error":{"code":"BAD_REQUEST_ERROR","description":"x","field":"amount","metadata":{}}}',
      ),
    ).toBe("definite_rejection");
  });

  it.each([
    "context canceled",
    "context deadline exceeded",
    "request timeout",
    "Timed out waiting for Razorpay",
    "SERVER_ERROR",
    "GATEWAY_ERROR",
    "BAD_REQUEST_ERROR and SERVER_ERROR",
    "BAD_REQUEST_ERROR: request cancelled",
    "BAD_REQUEST_ERROR: unexpected EOF",
    "BAD_REQUEST_ERROR: network error",
    "BAD_REQUEST_ERROR: connection reset by peer",
    "BAD_REQUEST_ERROR: HTTP status 503",
    "upstream failed",
    "bad_request_error",
    "NOT_BAD_REQUEST_ERRORS",
    "",
  ])("%j ⇒ ambiguous", (text) => {
    expect(classifyFailureText(text)).toBe("ambiguous");
  });

  it("ambiguous wording wins even inside the pinned JSON shape", () => {
    expect(
      classifyFailureText(
        '{"error":{"code":"BAD_REQUEST_ERROR","description":"gateway timed out"}}',
      ),
    ).toBe("ambiguous");
    expect(
      classifyFailureText('{"error":{"code":"BAD_REQUEST_ERROR","description":"SERVER_ERROR"}}'),
    ).toBe("ambiguous");
  });

  it("a leading token without the JSON envelope ⇒ ambiguous", () => {
    for (const t of [
      "BAD_REQUEST_ERROR",
      "  BAD_REQUEST_ERROR: invalid amount",
      "BAD_REQUEST_ERROR: The refund amount is invalid",
    ]) {
      expect(classifyFailureText(t)).toBe("ambiguous");
    }
  });

  it("the code nested anywhere but top-level error.code ⇒ ambiguous", () => {
    for (const echoed of [
      'refund failed; notes: {"memo":"BAD_REQUEST_ERROR"}',
      "invalid request: BAD_REQUEST_ERROR",
      '{"error":{"code":"X","description":"BAD_REQUEST_ERROR"}}',
      '{"description":"\\"code\\":\\"BAD_REQUEST_ERROR\\""}',
      '{"code":"BAD_REQUEST_ERROR"}',
      '{"notes":{"error":{"code":"BAD_REQUEST_ERROR"}}}',
      '{"error":{"details":{"code":"BAD_REQUEST_ERROR"}}}',
      '{"error":{"code":"X"},"nested":{"error":{"code":"BAD_REQUEST_ERROR"}}}',
      '[{"error":{"code":"BAD_REQUEST_ERROR"}}]',
      '{"error":[{"code":"BAD_REQUEST_ERROR"}]}',
      '{"error":"BAD_REQUEST_ERROR"}',
      "BAD_REQUEST_ERRORX",
    ]) {
      expect(classifyFailureText(echoed)).toBe("ambiguous");
    }
  });

  it("text around the JSON, or two JSON documents ⇒ ambiguous", () => {
    expect(classifyFailureText(`creating refund failed: ${REJECTION}`)).toBe("ambiguous");
    expect(classifyFailureText(`${REJECTION} trailing`)).toBe("ambiguous");
    expect(classifyFailureText(`${REJECTION}\n${REJECTION}`)).toBe("ambiguous");
  });

  it("a non-string or differently-cased error.code ⇒ ambiguous", () => {
    for (const t of [
      '{"error":{"code":null}}',
      '{"error":{"code":400}}',
      '{"error":{"code":["BAD_REQUEST_ERROR"]}}',
      '{"error":{"code":{"BAD_REQUEST_ERROR":true}}}',
      '{"error":{"code":"bad_request_error"}}',
      '{"error":{"code":" BAD_REQUEST_ERROR"}}',
      '{"error":{}}',
      '{"error":null}',
    ]) {
      expect(classifyFailureText(t)).toBe("ambiguous");
    }
  });

  it("oversized text ⇒ ambiguous", () => {
    const big = `{"error":{"code":"BAD_REQUEST_ERROR","description":"${"x".repeat(MAX_FAILURE_TEXT)}"}}`;
    expect(classifyFailureText(big)).toBe("ambiguous");
  });

  it("the allowlist is frozen and only holds BAD_REQUEST_ERROR", () => {
    expect(DEFINITE_REJECTION_CODES).toEqual(["BAD_REQUEST_ERROR"]);
    expect(Object.isFrozen(DEFINITE_REJECTION_CODES)).toBe(true);
  });
});

describe("classifyToolResultFailure", () => {
  it("non-error results ⇒ none", () => {
    expect(classifyToolResultFailure({ content: [] })).toBe("none");
    expect(classifyToolResultFailure({ isError: false, content: [] })).toBe("none");
    expect(classifyToolResultFailure(null)).toBe("none");
  });

  it("exactly one text item in the pinned shape ⇒ definite rejection", () => {
    expect(classifyToolResultFailure(toolError(REJECTION))).toBe("definite_rejection");
  });

  it("two text items ⇒ ambiguous (even if both are the pinned shape)", () => {
    expect(classifyToolResultFailure(toolError(REJECTION, REJECTION))).toBe("ambiguous");
    expect(classifyToolResultFailure(toolError(REJECTION, "context canceled"))).toBe("ambiguous");
  });

  it("no / non-text / leading-token-only content ⇒ ambiguous", () => {
    expect(classifyToolResultFailure(toolError("BAD_REQUEST_ERROR"))).toBe("ambiguous");
    expect(classifyToolResultFailure(toolError())).toBe("ambiguous");
    expect(classifyToolResultFailure({ isError: true })).toBe("ambiguous");
    expect(
      classifyToolResultFailure({
        isError: true,
        content: [{ type: "image", data: REJECTION, mimeType: "image/png" }],
      }),
    ).toBe("ambiguous");
    expect(
      classifyToolResultFailure({ isError: true, content: [{ type: "text", text: 42 }] }),
    ).toBe("ambiguous");
  });
});

describe("containsRejectionCode", () => {
  it("finds the code case-insensitively in values and keys at any depth; too deep ⇒ true", () => {
    expect(containsRejectionCode({ a: "fine", b: [1, { c: "ok" }] })).toBe(false);
    expect(containsRejectionCode({ notes: { memo: "Bad_Request_Error" } })).toBe(true);
    expect(containsRejectionCode({ list: [{ deep: ["x bad_request_error"] }] })).toBe(true);
    expect(containsRejectionCode({ BAD_REQUEST_ERROR: 1 })).toBe(true);
    let deep: unknown = "x";
    for (let i = 0; i < 40; i++) deep = [deep];
    expect(containsRejectionCode(deep)).toBe(true);
  });
});

describe("mergeFailure", () => {
  it("ambiguous wins, then definite, then none", () => {
    expect(mergeFailure("none", undefined)).toBe("none");
    expect(mergeFailure("none", "definite_rejection")).toBe("definite_rejection");
    expect(mergeFailure("definite_rejection", "ambiguous")).toBe("ambiguous");
    expect(mergeFailure("ambiguous", "none")).toBe("ambiguous");
  });
});
