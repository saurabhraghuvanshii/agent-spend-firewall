import { defineConfig } from "vitest/config";

// D-006: resolve workspace packages to their `src` via the `@asf/source` export condition.
// Vite 6+ only applies `resolve.conditions` to the client environment; Vitest's node tests run in the
// SSR environment, so the condition must be set there too or a stale `dist/` gets imported.
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
