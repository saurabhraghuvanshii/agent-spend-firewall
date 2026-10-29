/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Dashboard API base URL, default `http://127.0.0.1:8787` (see config.ts). */
  readonly VITE_ASF_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
