import react from "@vitejs/plugin-react";
import { defaultClientConditions } from "vite";
import { defineConfig } from "vitest/config";

// D-006: resolve workspace packages to their `src` via the `@asf/source` export condition (client + SSR).
export default defineConfig({
  plugins: [react()],
  resolve: {
    conditions: ["@asf/source", ...defaultClientConditions],
  },
  ssr: {
    resolve: {
      conditions: ["@asf/source"],
      externalConditions: ["@asf/source"],
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test/setup.ts"],
  },
});
