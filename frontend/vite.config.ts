import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * `--mode harness` additionally builds the dev-only globe harness (globe-harness.html) into
 * dist-harness/, for `vite preview --mode harness` and Task 11's Firefox pixel check. The
 * default build contains index.html only, so the harness never ships.
 */
export default defineConfig(({ mode }) => {
  const harness = mode === "harness";
  return {
    plugins: [react()],
    server: {
      proxy: {
        "/api": { target: "http://127.0.0.1:8000", ws: true },
      },
    },
    build: {
      sourcemap: false,
      // Never inline fonts as data: URIs: the production CSP says font-src 'self' (no data:), so the
      // small Plex subsets must ship as real same-origin files. Other assets keep Vite's default.
      assetsInlineLimit: (file: string) => (/\.(woff2?|ttf|otf)$/i.test(file) ? false : undefined),
      outDir: harness ? "dist-harness" : "dist",
      // The one chunk above Vite's 500 kB default is the lazy MapLibre globe chunk (~1.17 MB raw,
      // ~330 kB gzip), deliberately kept out of the initial bundle; the budget test guards that.
      chunkSizeWarningLimit: 1300,
      rollupOptions: {
        input: harness
          ? {
              main: resolve(import.meta.dirname, "index.html"),
              harness: resolve(import.meta.dirname, "globe-harness.html"),
            }
          : resolve(import.meta.dirname, "index.html"),
        output: {
          // MapLibre's worker is an .mjs asset (imported with ?url). Emit it as .js so any static
          // server (nginx's stock mime.types included) sends a JavaScript MIME type, which module
          // workers require.
          assetFileNames: (info) =>
            (info.names ?? []).some((n) => n.endsWith(".mjs"))
              ? "assets/[name]-[hash].js"
              : "assets/[name]-[hash][extname]",
        },
      },
    },
  };
});
