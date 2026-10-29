import { describe, expect, it } from "vitest";
import { PACKAGE_NAME, createApi } from "./index.js";

describe("api", () => {
  it("exports package name and createApi", () => {
    expect(PACKAGE_NAME).toBe("@asf/api");
    expect(typeof createApi).toBe("function");
  });
});
