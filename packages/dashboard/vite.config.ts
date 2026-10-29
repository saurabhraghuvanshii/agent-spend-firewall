import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defaultClientConditions, defineConfig, type Plugin } from "vite";

/**
 * Production builds get a strict Content-Security-Policy: scripts only from our own origin, network only to loopback
 * (the API binds loopback only, D-036). Dev is left alone because the React refresh preamble is an inline script.
 */
const csp = (): Plugin => ({
  name: "asf-csp",
  apply: "build",
  transformIndexHtml(html) {
    const policy = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self' http://127.0.0.1:* http://localhost:* http://[::1]:*",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
    ].join("; ");
    const charset = '<meta charset="UTF-8" />';
    if (!html.includes(charset)) throw new Error("index.html: missing charset meta for the CSP");
    return html.replace(
      charset,
      `${charset}\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`,
    );
  },
});

/**
 * Anti-clickjacking for the dev / preview servers (the approve and kill-switch buttons must not be framable). A meta
 * CSP cannot carry `frame-ancestors`, so production hosting must send these headers itself (D-037).
 */
export const FRAME_HEADERS = {
  "Content-Security-Policy": "frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
} as const;

// D-006: bundle workspace packages (`@asf/core`) from their `src` via the `@asf/source` export condition.
// envDir stays this package (never the repo-root `.env`, which holds secrets); only `VITE_ASF_*` vars reach the client.
export default defineConfig({
  plugins: [react(), tailwindcss(), csp()],
  envPrefix: "VITE_ASF_",
  resolve: {
    conditions: ["@asf/source", ...defaultClientConditions],
  },
  server: { host: "localhost", port: 5173, strictPort: true, headers: FRAME_HEADERS },
  preview: { host: "localhost", port: 5173, strictPort: true, headers: FRAME_HEADERS },
  build: { sourcemap: false },
});
