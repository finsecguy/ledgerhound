import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev: `npm run dev` (Vite on 5173) proxies /api to `lh serve --reload`
// (FastAPI on 8000) so the browser only ever talks to one origin and
// relative fetch("/api/...") calls work identically in dev and prod.
// Prod: `npm run build` emits dist/, served by FastAPI itself at "/"
// (see ledgerhound/api/main.py) — no proxy needed there, same origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
