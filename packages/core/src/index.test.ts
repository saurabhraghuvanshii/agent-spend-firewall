import { describe, expect, it } from "vitest";
import { PACKAGE_NAME } from "./index.js";

describe("core", () => {
  it("exports package name", () => {
    expect(PACKAGE_NAME).toBe("@asf/core");
  });
});
