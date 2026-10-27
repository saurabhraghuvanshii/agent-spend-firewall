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

describe("classifyFailureText", () => {
  it("BAD_REQUEST_ERROR alone ⇒ definite rejection", () => {
    expect(classifyFailureText("BAD_REQUEST_ERROR")).toBe("definite_rejection");
    expect(
      classifyFailureText('{"error":{"code":"BAD_REQUEST_ERROR","description":"invalid amount"}}'),
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

  it("the code counts only as the JSON error code or the leading token; echoed elsewhere ⇒ ambiguous", () => {
    expect(classifyFailureText('{ "error": { "code" :  "BAD_REQUEST_ERROR" } }')).toBe(
      "definite_rejection",
    );
    expect(classifyFailureText("  BAD_REQUEST_ERROR: invalid amount")).toBe("definite_rejection");
    for (const echoed of [
      'refund failed; notes: {"memo":"BAD_REQUEST_ERROR"}',
      "invalid request: BAD_REQUEST_ERROR",
      '{"error":{"code":"X","description":"BAD_REQUEST_ERROR"}}',
      '{"description":"\\"code\\":\\"BAD_REQUEST_ERROR\\""}',
      "BAD_REQUEST_ERRORX",
    ]) {
      expect(classifyFailureText(echoed)).toBe("ambiguous");
    }
  });

  it("oversized text ⇒ ambiguous", () => {
    expect(classifyFailureText(`BAD_REQUEST_ERROR ${"x".repeat(MAX_FAILURE_TEXT)}`)).toBe(
      "ambiguous",
    );
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

  it("isError: text classified across items; no / non-text content ⇒ ambiguous", () => {
    expect(classifyToolResultFailure(toolError("BAD_REQUEST_ERROR"))).toBe("definite_rejection");
    expect(classifyToolResultFailure(toolError("BAD_REQUEST_ERROR", "context canceled"))).toBe(
      "ambiguous",
    );
    expect(classifyToolResultFailure(toolError())).toBe("ambiguous");
    expect(classifyToolResultFailure({ isError: true })).toBe("ambiguous");
    expect(
      classifyToolResultFailure({
        isError: true,
        content: [{ type: "image", data: "BAD_REQUEST_ERROR", mimeType: "image/png" }],
      }),
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
