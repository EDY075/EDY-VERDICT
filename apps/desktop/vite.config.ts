import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  base: "./",
  build: {
    target: "es2022",
    sourcemap: false,
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
});
