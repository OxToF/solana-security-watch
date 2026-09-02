import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// web3.js / spl-token reference Node globals (Buffer, process) — the polyfill
// plugin shims them for the browser bundle.
export default defineConfig({
  plugins: [react(), nodePolyfills({ globals: { Buffer: true, global: true, process: true } })],
});
