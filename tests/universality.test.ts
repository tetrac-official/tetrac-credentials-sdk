// Universality tests (PRD §11.2 — THE requirement):
//   (a) a brand-new fake schema registered at RUNTIME works with no SDK change;
//   (b) the CI grep guard: ZERO real provider-name literals anywhere in src/.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { createCredentialManager, type CredentialManager, type CredentialValues } from "../src/index.js";
import { createMemoryStorage, createVault } from "./helpers.js";

let live: CredentialManager[] = [];
afterEach(() => {
  for (const mgr of live) mgr.dispose();
  live = [];
});

describe("universality — no SDK change to add a provider", () => {
  it("registers a never-before-seen schema at runtime and round-trips it", async () => {
    const vault = createVault();
    const mgr = createCredentialManager({
      getAppKey: vault.getAppKey,
      getIdentity: vault.getIdentity,
      subscribeLock: vault.subscribeLock,
      storage: createMemoryStorage(),
    });
    live.push(mgr);
    // A provider the SDK has never heard of — invented entirely in this test.
    const ref = { namespace: "service", providerId: "some-new-ai-2099" };
    mgr.registerCredentialSchema({
      ref,
      fields: [
        { key: "apiKey", secret: true, required: true },
        { key: "orgId", secret: false },
      ],
      sessionCacheable: false,
    });
    // set/get just works — no SDK edit, no release.
    await mgr.setCredentials(ref, { apiKey: "brand-new", orgId: "org-42" });
    expect((await mgr.getCredentials(ref)) as CredentialValues).toEqual({ apiKey: "brand-new", orgId: "org-42" });
    // And a totally new namespace also works.
    const futureRef = { namespace: "webhooks", providerId: "future-thing" };
    mgr.registerCredentialSchema({ ref: futureRef, fields: [{ key: "url", secret: true, required: true }] });
    await mgr.setCredentials(futureRef, { url: "https://hook" });
    expect((await mgr.getCredentials(futureRef)) as CredentialValues).toEqual({ url: "https://hook" });
  });
});

describe("CI grep guard — no provider-name literals in SDK src/ (R-4)", () => {
  // The deny-list: the two service providers named in the PRD + a representative sample of
  // exchange venue slugs. Mirror next-ttc's full exchange registry here as it grows so the
  // guard stays authoritative; any match is a coupling regression that fails CI.
  const PROVIDER_DENYLIST = [
    "openrouter",
    "telegram",
    "binance",
    "coinbase",
    "kraken",
    "bybit",
    "okx",
    "kucoin",
    "bitget",
    "gateio",
    "mexc",
    "huobi",
    "htx",
    "bitfinex",
    "bitstamp",
    "gemini",
    "bitmex",
    "deribit",
    "phemex",
    "hyperliquid",
    "dydx",
    "vest",
    "drift",
    "jupiter",
    "raydium",
    "orca",
    "paradex",
    "aevo",
    "woofi",
    "bingx",
    "blofin",
    "backpack",
    "lighter",
    "edgex",
    "apex",
    "vertex",
    "bitmart",
    "poloniex",
    "probit",
    "ascendex",
    "crypto-com",
    "umbra",
  ];

  // Escape a term for safe embedding in a RegExp.
  const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Word-boundary matcher so "gate" can't false-positive inside "aggregate", etc.
  const matchers = PROVIDER_DENYLIST.map((term) => ({ term, re: new RegExp(`\\b${escape(term)}\\b`, "i") }));

  // Resolve the SDK src/ directory relative to this test file.
  const here = dirname(fileURLToPath(import.meta.url));
  const srcDir = join(here, "..", "src");

  // Gather all TypeScript source files (src/ is flat).
  const files = readdirSync(srcDir).filter((f) => f.endsWith(".ts"));

  it("actually found source files to scan (guard is not a no-op)", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files)("%s contains zero deny-listed provider literals", (file) => {
    // Read the whole source file.
    const content = readFileSync(join(srcDir, file), "utf8");
    // Collect every deny-listed term that appears (word-boundary, case-insensitive).
    const hits = matchers.filter((m) => m.re.test(content)).map((m) => m.term);
    // Any hit is a coupling regression.
    expect(hits, `Provider literal(s) leaked into src/${file}: ${hits.join(", ")}`).toEqual([]);
  });

  // The BUILT artifact must be just as free of provider literals as src/ — R-4 covers what
  // actually ships. dist/ is scanned when present (a pre-build checkout has none yet).
  const distDir = join(here, "..", "dist");
  let distEntries: string[] = [];
  try {
    distEntries = readdirSync(distDir);
  } catch {
    distEntries = [];
  }
  // Scan every built code/declaration output (any module extension: .js/.cjs/.mjs, .d.ts/.d.cts/.d.mts),
  // never the .map sidecars — so a format change (e.g. ESM-only .mjs) can't slip provider names past us.
  const distFiles = distEntries.filter((f) => /\.(c|m)?js$/.test(f) || /\.d\.(c|m)?ts$/.test(f));

  it("dist scan is not a silent no-op when a build is present", () => {
    // If dist/ holds shippable files but the extension filter matched none, the filter has drifted
    // from the build output — fail loudly rather than quietly scan nothing.
    const shippable = distEntries.filter((f) => !f.endsWith(".map") && !f.startsWith("."));
    if (shippable.length > 0) expect(distFiles.length).toBeGreaterThan(0);
  });

  it.each(distFiles.length ? distFiles : ["<no-dist>"])(
    "%s (dist) contains zero deny-listed provider literals",
    (file) => {
      // Skip silently on a pre-build checkout; after `npm run build` this scans the shipped code.
      if (file === "<no-dist>") return;
      const content = readFileSync(join(distDir, file), "utf8");
      const hits = matchers.filter((m) => m.re.test(content)).map((m) => m.term);
      expect(hits, `Provider literal(s) leaked into dist/${file}: ${hits.join(", ")}`).toEqual([]);
    },
  );

  // Source hygiene: no stray ASCII control bytes (NUL/C0 except tab/newline, or DEL). This locks
  // in the audit cleanup — earlier revisions embedded raw NUL separators in src/. (R-audit.)
  it.each(files)("%s carries no stray control bytes", (file) => {
    const buf = readFileSync(join(srcDir, file));
    const bad: string[] = [];
    for (const b of buf) {
      const allowed = b === 0x09 || b === 0x0a || b === 0x0d; // tab, LF, CR
      if ((b < 0x20 && !allowed) || b === 0x7f) bad.push(`0x${b.toString(16)}`);
    }
    expect(bad, `Control byte(s) in src/${file}: ${bad.join(", ")}`).toEqual([]);
  });
});
