import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { resolve } from "path";

export default defineConfig({
  plugins: [svelte()],
  publicDir: "public",
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "index.html"), // popup page
      },
      output: {
        manualChunks: undefined,
        entryFileNames: (chunk) =>
          chunk.name === "popup" ? "popup.js" : "[name].js",
      },
    },
  },
});
