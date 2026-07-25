// Runtime-environment guard coverage: the two "this host can't support the SDK" throws that
// every other test bypasses (they inject storage and run where WebCrypto exists). Surfaced by
// the coverage critic.
import { afterEach, describe, expect, it, vi } from "vitest";
import { decryptString, encryptString } from "../src/crypto.js";
import { resolveStorage } from "../src/storage.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runtime guards", () => {
  it("resolveStorage throws when nothing is injected and there is no localStorage", () => {
    // Node has no globalThis.localStorage; guard the assertion so a DOM env doesn't false-fail.
    if ((globalThis as { localStorage?: unknown }).localStorage) return;
    expect(() => resolveStorage(undefined)).toThrow(/No storage available/);
  });

  it("encrypt/decrypt reject when WebCrypto (crypto.subtle) is unavailable", async () => {
    const real = globalThis.crypto;
    // Replace the global with one that has getRandomValues but NO subtle → getSubtle() throws.
    vi.stubGlobal("crypto", { getRandomValues: real.getRandomValues.bind(real) });
    await expect(encryptString("k", "p", "aad")).rejects.toThrow(/WebCrypto/);
    await expect(decryptString("k", "AAAAAAAAAAAAAAAAAA==", "aad")).rejects.toThrow(/WebCrypto/);
  });
});
