// Build configuration for @tetrac/credentials-sdk.
// Produces a dual ESM + CJS bundle plus type declarations from a single entry.
// The SDK has zero runtime dependencies, so nothing is externalized/bundled in.
import { defineConfig } from "tsup";

export default defineConfig({
  // Single public entry point; everything else is internal.
  entry: ["src/index.ts"],
  // Emit both module systems so the package works under `import` and `require`.
  format: ["esm", "cjs"],
  // Generate .d.ts type declarations for consumers.
  dts: true,
  // Ship source maps for debuggability in the host app.
  sourcemap: true,
  // Start each build from a clean dist/ so stale artifacts never leak (PRD §14).
  clean: true,
  // Do not split into chunks — one small file per format keeps the surface trivial.
  splitting: false,
  // Match the modern runtime targeted by tsconfig (WebCrypto/TextEncoder available).
  target: "es2022",
  // Pure module: enables aggressive tree-shaking in the host bundler.
  treeshake: true,
});
