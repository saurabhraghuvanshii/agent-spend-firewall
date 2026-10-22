import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    conditions: ["@asf/source"],
  },
  test: {
    include: ["src/**/*.test.ts"],
  },
});
