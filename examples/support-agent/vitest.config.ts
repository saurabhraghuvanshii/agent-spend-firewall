import { defineConfig } from "vitest/config";

// D-006: resolve workspace packages to their `src` via the `@asf/source` export condition (see packages/proxy).
export default defineConfig({
  resolve: {
    conditions: ["@asf/source"],
  },
  ssr: {
    resolve: {
      conditions: ["@asf/source"],
      externalConditions: ["@asf/source"],
    },
  },
  test: {
    include: ["src/**/*.test.ts"],
  },
});
