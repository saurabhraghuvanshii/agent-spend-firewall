import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { resolveApiBaseUrl } from "./config";
import "./index.css";
import { applyTheme, readThemePref } from "./theme";

applyTheme(readThemePref());

const root = document.getElementById("root");
if (root === null) throw new Error("missing #root element");
const api = resolveApiBaseUrl(import.meta.env.VITE_ASF_API_URL);

createRoot(root).render(
  <StrictMode>
    {api.ok ? (
      <App apiUrl={api.value} />
    ) : (
      <main className="p-6">
        <p role="alert" className="text-red-700">
          Configuration error: {api.error}
        </p>
      </main>
    )}
  </StrictMode>,
);
