import { describe, expect, it } from "vitest";
import { PACKAGE_NAME } from "./index.js";

describe("dashboard", () => {
  it("exports package name", () => {
    expect(PACKAGE_NAME).toBe("@asf/dashboard");
  });
});
