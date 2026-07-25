// Shared-namespace blob, populated-multi probes, write serialization, cache warming,
// and clearNamespace breadth — the branches that only appear when a namespace holds MORE
// THAN ONE provider (the core reason set/remove are async). Surfaced by the coverage critic.
import { afterEach, describe, expect, it } from "vitest";
import {
  createCredentialManager,
  type CredentialManager,
  type CredentialValues,
} from "../src/index.js";
import { indexKey, secretsKey } from "../src/manager.js";
import { createMemoryStorage, createVault } from "./helpers.js";

let live: CredentialManager[] = [];
function makeManager(vault: ReturnType<typeof createVault>, storage = createMemoryStorage()): CredentialManager {
  const mgr = createCredentialManager({
    getAppKey: vault.getAppKey,
    getIdentity: vault.getIdentity,
    subscribeLock: vault.subscribeLock,
    storage,
  });
  live.push(mgr);
  return mgr;
}
afterEach(() => {
  for (const mgr of live) mgr.dispose();
  live = [];
});

// Two single-secret providers that share ONE namespace ("exchange") → one encrypted blob.
const A = { namespace: "exchange", providerId: "a" };
const B = { namespace: "exchange", providerId: "b" };
function registerAB(mgr: CredentialManager): void {
  mgr.registerCredentialSchema({ ref: A, fields: [{ key: "apiKey", secret: true, required: true }], sessionCacheable: true });
  mgr.registerCredentialSchema({ ref: B, fields: [{ key: "apiKey", secret: true, required: true }], sessionCacheable: true });
}

// ---- shared-namespace blob: merge on set, re-encrypt on remove ---------------

describe("shared-namespace blob (multiple providers in one namespace)", () => {
  it("setting a second provider preserves the first (merge into the shared blob, not clobber)", async () => {
    const mgr = makeManager(createVault());
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "AA" });
    await mgr.setCredentials(B, { apiKey: "BB" }); // must read+merge, not overwrite the blob
    expect(await mgr.getCredentials(A)).toEqual({ apiKey: "AA" });
    expect(await mgr.getCredentials(B)).toEqual({ apiKey: "BB" });
    expect(mgr.listProviders("exchange").sort()).toEqual(["a", "b"]);
  });

  it("removeCredentials re-encrypts the REMAINING non-empty blob and preserves co-residents", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "AA" });
    await mgr.setCredentials(B, { apiKey: "BB" });
    await mgr.removeCredentials(A); // blob still holds B → encryptBlob returns a cipher, not null
    expect(mgr.hasCredentials(A)).toBe(false);
    expect(await mgr.getCredentials(A)).toBeNull();
    // The secrets key must STILL exist (B remains) and re-decrypt via a fresh manager instance.
    expect(storage.getItem(secretsKey("credmgr", "exchange", "user-1"))).not.toBeNull();
    const reader = makeManager(vault, storage);
    registerAB(reader);
    expect(await reader.getCredentials(B)).toEqual({ apiKey: "BB" });
  });

  it("removing the LAST provider deletes both storage keys (no stray '{}')", async () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "AA" });
    await mgr.removeCredentials(A);
    expect(storage.getItem(secretsKey("credmgr", "exchange", "user-1"))).toBeNull();
    expect(storage.getItem(indexKey("credmgr", "exchange", "user-1"))).toBeNull();
  });
});

// ---- populated-multi probes (count > 0 true branches) -----------------------

describe("populated-multi probes", () => {
  const MULTI = { namespace: "service", providerId: "keys" };
  function registerMulti(mgr: CredentialManager): void {
    mgr.registerCredentialSchema({ ref: MULTI, fields: [{ key: "apiKey", secret: true, required: true }], multi: true, sessionCacheable: true });
  }

  it("hasCredentials is true for a populated multi (count > 0)", async () => {
    const mgr = makeManager(createVault());
    registerMulti(mgr);
    await mgr.setCredentials(MULTI, [{ apiKey: "k1" }, { apiKey: "k2" }]);
    expect(mgr.hasCredentials(MULTI)).toBe(true);
    expect(mgr.listProviders("service")).toEqual(["keys"]);
  });

  it("getSummary names a populated multi's fields from the schema", async () => {
    const mgr = makeManager(createVault());
    registerMulti(mgr);
    await mgr.setCredentials(MULTI, [{ apiKey: "k1" }]);
    const summary = mgr.getSummary(MULTI);
    expect(summary?.fields).toEqual(["apiKey"]);
    expect(typeof summary?.updatedAt).toBe("number");
  });

  it("multi secret values never appear in the plaintext index or the ciphertext", async () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    registerMulti(mgr);
    await mgr.setCredentials(MULTI, [{ apiKey: "SECRET-1" }, { apiKey: "SECRET-2" }]);
    const idx = storage.getItem(indexKey("credmgr", "service", "user-1")) ?? "";
    const blob = storage.getItem(secretsKey("credmgr", "service", "user-1")) ?? "";
    for (const secret of ["SECRET-1", "SECRET-2"]) {
      expect(idx).not.toContain(secret);
      expect(blob).not.toContain(secret);
    }
  });
});

// ---- write serialization + cache warming ------------------------------------

describe("write serialization (withNamespaceLock) & cache warming", () => {
  it("concurrent un-awaited sets to ONE namespace both persist (no clobber)", async () => {
    const mgr = makeManager(createVault());
    registerAB(mgr);
    // Fire both without awaiting the first — they share the namespace blob and must serialize.
    const p1 = mgr.setCredentials(A, { apiKey: "AA" });
    const p2 = mgr.setCredentials(B, { apiKey: "BB" });
    await Promise.all([p1, p2]);
    expect(await mgr.getCredentials(A)).toEqual({ apiKey: "AA" });
    expect(await mgr.getCredentials(B)).toEqual({ apiKey: "BB" });
  });

  it("a rejecting mutation does not poison the namespace write chain", async () => {
    const mgr = makeManager(createVault());
    registerAB(mgr);
    // `bad` rejects (missing required field); `good` is valid on the same namespace.
    const bad = mgr.setCredentials(A, {} as CredentialValues).catch(() => undefined);
    const good = mgr.setCredentials(A, { apiKey: "OK" });
    await Promise.all([bad, good]);
    expect(await mgr.getCredentials(A)).toEqual({ apiKey: "OK" });
  });

  it("setCredentials warms the cache — a read survives auto-lock with NO prior read", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "warm" }); // no getCredentials in between
    vault.autoLock(); // appKey null, identity present → cache must carry the set value
    expect(await mgr.getCredentials(A)).toEqual({ apiKey: "warm" });
  });

  it("a later set overwrites the cached value", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "v1" });
    await mgr.setCredentials(A, { apiKey: "v2" }); // overwrite while unlocked
    vault.autoLock();
    expect(await mgr.getCredentials(A)).toEqual({ apiKey: "v2" });
  });
});

// ---- clearNamespace breadth --------------------------------------------------

describe("clearNamespace breadth", () => {
  it("drops an already-WARM cache entry (non-concurrent)", async () => {
    const mgr = makeManager(createVault());
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "AA" });
    await mgr.getCredentials(A); // warm the cache while unlocked
    mgr.clearNamespace("exchange");
    expect(await mgr.getCredentials(A)).toBeNull(); // storage + warm cache both gone
  });

  it("wipes ALL identities' storage and cache in the namespace", async () => {
    const vault = createVault({ identity: "user-1" });
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    registerAB(mgr);
    await mgr.setCredentials(A, { apiKey: "u1" });
    await mgr.getCredentials(A); // warm user-1
    vault.switchTo("user-2");
    await mgr.setCredentials(A, { apiKey: "u2" });
    await mgr.getCredentials(A); // warm user-2
    mgr.clearNamespace("exchange");
    expect(await mgr.getCredentials(A)).toBeNull(); // user-2 gone
    vault.switchTo("user-1");
    expect(await mgr.getCredentials(A)).toBeNull(); // user-1 gone too
  });

  it("a clearNamespace on a DIFFERENT namespace does not abort an in-flight set (no false abort)", async () => {
    const mgr = makeManager(createVault());
    registerAB(mgr);
    mgr.registerCredentialSchema({ ref: { namespace: "other", providerId: "x" }, fields: [{ key: "apiKey", secret: true, required: true }] });
    const inFlight = mgr.setCredentials(B, { apiKey: "BB" }); // namespace "exchange"
    mgr.clearNamespace("other"); // a DIFFERENT namespace — must not touch B's epoch
    await inFlight;
    expect(await mgr.getCredentials(B)).toEqual({ apiKey: "BB" });
  });
});

// ---- registration replace (last-writer-wins) --------------------------------

describe("registration — last-writer-wins per ref", () => {
  it("re-registering a ref replaces the schema; routing follows the newest one", async () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    const ref = { namespace: "exchange", providerId: "x" };
    mgr.registerCredentialSchema({ ref, fields: [{ key: "v", secret: true, required: true }] }); // v SECRET
    mgr.registerCredentialSchema({ ref, fields: [{ key: "v", secret: false }] }); // replace: v NON-secret
    await mgr.setCredentials(ref, { v: "VALUE" });
    // The replacement schema (non-secret) must apply → v lands in the PLAINTEXT index.
    expect(storage.getItem(indexKey("credmgr", "exchange", "user-1")) ?? "").toContain("VALUE");
    expect(await mgr.getCredentials(ref)).toEqual({ v: "VALUE" });
  });
});
