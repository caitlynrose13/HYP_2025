import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { resolve } from "path";

export default defineConfig({
  plugins: [svelte()],
  publicDir: "public", //Files in the public/ folder will be served as static assets.
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "index.html"),
      },
      output: {
        manualChunks: undefined,
        entryFileNames: "popup.js",
      },
    },
  },
});
