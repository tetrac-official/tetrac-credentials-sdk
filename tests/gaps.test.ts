// Coverage-gap tests surfaced by the v0.1.0 re-review completeness critic: high-value behaviors the
// existing 132 tests did not pin. These are not tied to a single fix — they lock down invariants that,
// if they silently broke, would ship a security or data-loss regression with a green suite.
import { afterEach, describe, expect, it } from "vitest";
import {
  CredentialSchemaError,
  VaultLockedError,
  createCredentialManager,
  type CredentialManager,
  type CredentialSchema,
  type CredentialValues,
} from "../src/index.js";
import { indexKey, secretsKey } from "../src/storage.js";
import { createMemoryStorage, createVault } from "./helpers.js";

let live: CredentialManager[] = [];
function makeManager(
  vault: ReturnType<typeof createVault>,
  storage = createMemoryStorage(),
): CredentialManager {
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

const SINGLE: CredentialSchema = {
  ref: { namespace: "exchange", providerId: "venue" },
  fields: [
    { key: "apiKey", secret: true, required: true },
    { key: "apiSecret", secret: true, required: true },
    { key: "label", secret: false },
  ],
  sessionCacheable: true,
};

// Enumerate every (key,value) pair in a memory-storage double.
function allEntries(
  storage: ReturnType<typeof createMemoryStorage>,
): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (let i = 0; i < storage.length; i += 1) {
    const k = storage.key(i)!;
    out.push([k, storage.getItem(k) ?? ""]);
  }
  return out;
}

describe("full-store leak invariant — no secret VALUE lands in ANY storage key", () => {
  it("scans every key, not just the two known ones; non-secret label lives only in the index", async () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    mgr.registerCredentialSchema(SINGLE);
    const secretVal = "as_super_secret_value_9f3c";
    await mgr.setCredentials(SINGLE.ref, {
      apiKey: "ak_key",
      apiSecret: secretVal,
      label: "My spot",
    });

    const entries = allEntries(storage);
    // The secret value appears in NO stored value anywhere.
    for (const [, value] of entries) {
      expect(value.includes(secretVal)).toBe(false);
      expect(value.includes("ak_key")).toBe(false);
    }
    // The non-secret label appears ONLY in the index key (plaintext index by design), never the blob.
    const idxK = indexKey("credmgr", "exchange", "user-1");
    const secK = secretsKey("credmgr", "exchange", "user-1");
    expect(storage.getItem(idxK)!.includes("My spot")).toBe(true);
    expect(storage.getItem(secK)!.includes("My spot")).toBe(false);
  });
});

describe("locked vs unconfigured vs UNREGISTERED are three distinct outcomes", () => {
  it("unregistered → CredentialSchemaError; unconfigured → null; locked → VaultLockedError", async () => {
    const storage = createMemoryStorage();
    const vault = createVault();
    const mgr = makeManager(vault, storage);
    // Unregistered ref: schema error (async rejection).
    await expect(mgr.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(
      CredentialSchemaError,
    );
    // Registered but unconfigured: null.
    mgr.registerCredentialSchema(SINGLE);
    expect(await mgr.getCredentials(SINGLE.ref)).toBeNull();
    // Configured, then locked: VaultLockedError (distinct from the null above).
    await mgr.setCredentials(SINGLE.ref, { apiKey: "k", apiSecret: "s" });
    vault.logout(); // clears cache + key + identity
    await expect(mgr.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(
      VaultLockedError,
    );
  });

  it("a FRESH manager reads persisted has/list/summary WITHOUT the schema, but get/set need it", async () => {
    const storage = createMemoryStorage();
    const vault = createVault();
    const writer = makeManager(vault, storage);
    writer.registerCredentialSchema(SINGLE);
    await writer.setCredentials(SINGLE.ref, {
      apiKey: "k",
      apiSecret: "s",
      label: "L",
    });
    // Fresh manager, schema NOT registered — the index probes are schema-independent.
    const fresh = makeManager(vault, storage);
    expect(fresh.hasCredentials(SINGLE.ref)).toBe(true);
    expect(fresh.listProviders("exchange")).toEqual(["venue"]);
    expect(fresh.getSummary(SINGLE.ref)?.fields).toContain("label");
    // But the crypto paths require the schema.
    await expect(fresh.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(
      CredentialSchemaError,
    );
  });
});

describe("session cache lifecycle gaps", () => {
  it("an unconfigured cacheable read caches NOTHING → a later locked read still surfaces 'locked'", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    // Unconfigured read returns null and must not warm the cache with anything.
    expect(await mgr.getCredentials(SINGLE.ref)).toBeNull();
    vault.autoLock();
    // If the null had been cached, this would wrongly return null instead of throwing.
    await expect(mgr.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(
      VaultLockedError,
    );
  });

  it("a MULTI cacheable value survives an idle auto-lock and is deep-cloned out of the cache", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    const MULTI: CredentialSchema = {
      ref: { namespace: "service", providerId: "ai" },
      fields: [{ key: "apiKey", secret: true, required: true }],
      multi: true,
      sessionCacheable: true,
    };
    mgr.registerCredentialSchema(MULTI);
    await mgr.setCredentials(MULTI.ref, [{ apiKey: "a" }, { apiKey: "b" }]);
    const first = (await mgr.getCredentials(MULTI.ref)) as CredentialValues[];
    expect(first).toEqual([{ apiKey: "a" }, { apiKey: "b" }]);
    // Mutate the returned list — the cache must not be poisoned by reference.
    first[0]!.apiKey = "TAMPERED";
    (first as unknown[]).push({ apiKey: "c" });
    vault.autoLock(); // key gone; cacheable multi must survive
    expect(await mgr.getCredentials(MULTI.ref)).toEqual([
      { apiKey: "a" },
      { apiKey: "b" },
    ]);
  });

  it("an account switch PURGES the departing identity's cached secret (not merely isolates it)", async () => {
    const vault = createVault({ identity: "user-1" });
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "k", apiSecret: "s" });
    await mgr.getCredentials(SINGLE.ref); // warm user-1's cache
    vault.switchTo("user-2"); // lock signal → drop non-user-2 submaps
    vault.switchTo("user-1"); // back to user-1, key present again
    // Prove user-1's decrypted secret is GONE from memory: with the key nulled, a read can only be
    // served from cache — and there must be nothing left to serve.
    vault.autoLock();
    await expect(mgr.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(
      VaultLockedError,
    );
  });

  it("clearNamespace('a') leaves a WARM cache entry for namespace 'b' intact", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    const A: CredentialSchema = {
      ref: { namespace: "a", providerId: "p" },
      fields: [{ key: "apiKey", secret: true, required: true }],
      sessionCacheable: true,
    };
    const B: CredentialSchema = {
      ref: { namespace: "b", providerId: "p" },
      fields: [{ key: "apiKey", secret: true, required: true }],
      sessionCacheable: true,
    };
    mgr.registerCredentialSchema(A);
    mgr.registerCredentialSchema(B);
    await mgr.setCredentials(A.ref, { apiKey: "in-a" });
    await mgr.setCredentials(B.ref, { apiKey: "in-b" });
    await mgr.getCredentials(A.ref);
    await mgr.getCredentials(B.ref); // both warm
    mgr.clearNamespace("a"); // wipes a's storage + a's cache only
    vault.autoLock();
    // b survives from cache; a is gone (storage removed + cache dropped → cold + locked).
    expect(await mgr.getCredentials(B.ref)).toEqual({ apiKey: "in-b" });
    await expect(mgr.getCredentials(A.ref)).rejects.toBeInstanceOf(
      VaultLockedError,
    );
  });
});

describe("slot-binding & identity-encoding gaps", () => {
  it("a blob transplanted across NAMESPACES within one identity fails AAD (fails closed)", async () => {
    const storage = createMemoryStorage();
    const vault = createVault();
    const mgr = makeManager(vault, storage);
    const NS1 = { namespace: "ns1", providerId: "p" };
    const NS2 = { namespace: "ns2", providerId: "p" };
    mgr.registerCredentialSchema({
      ref: NS1,
      fields: [{ key: "apiKey", secret: true, required: true }],
    });
    mgr.registerCredentialSchema({
      ref: NS2,
      fields: [{ key: "apiKey", secret: true, required: true }],
    });
    await mgr.setCredentials(NS1, { apiKey: "s" });
    // Copy ns1's ciphertext into ns2's slot + plant a matching index entry so get() reaches the blob.
    const cipher = storage.getItem(secretsKey("credmgr", "ns1", "user-1"))!;
    storage.setItem(secretsKey("credmgr", "ns2", "user-1"), cipher);
    storage.setItem(
      indexKey("credmgr", "ns2", "user-1"),
      JSON.stringify({
        p: { publicFields: {}, secretKeys: ["apiKey"], updatedAt: 1 },
      }),
    );
    // AAD binds the ciphertext to ns1's slot; decrypting it as ns2 must fail rather than forge.
    await expect(mgr.getCredentials(NS2)).rejects.toThrow();
  });

  it("an identity containing ':' is storage-key isolated and round-trips (no prefix aliasing)", async () => {
    const storage = createMemoryStorage();
    const vault = createVault({ identity: "a:b" });
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "k", apiSecret: "s" });
    // The ':' in the identity is percent-encoded in the storage key, so it can't collide with "a".
    expect(
      storage.getItem(indexKey("credmgr", "exchange", "a:b")),
    ).not.toBeNull();
    // A prefix-related identity "a" sees nothing…
    vault.switchTo("a");
    expect(await mgr.getCredentials(SINGLE.ref)).toBeNull();
    // …and switching back recovers the original account's credential.
    vault.switchTo("a:b");
    expect(await mgr.getCredentials(SINGLE.ref)).toEqual({
      apiKey: "k",
      apiSecret: "s",
    });
  });
});

describe("write-path robustness gaps", () => {
  it("setCredentials AFTER a clearNamespace still persists (the clear epoch is not permanently poisoning)", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "k1", apiSecret: "s1" });
    mgr.clearNamespace("exchange");
    expect(mgr.hasCredentials(SINGLE.ref)).toBe(false);
    // A fresh write after the clear must land normally.
    await mgr.setCredentials(SINGLE.ref, { apiKey: "k2", apiSecret: "s2" });
    expect(mgr.hasCredentials(SINGLE.ref)).toBe(true);
    expect(await mgr.getCredentials(SINGLE.ref)).toEqual({
      apiKey: "k2",
      apiSecret: "s2",
    });
  });

  it("single get() with the secrets blob deleted but a surviving index entry fails SAFE (no forged/partial secret)", async () => {
    const storage = createMemoryStorage();
    const vault = createVault();
    const mgr = makeManager(vault, storage);
    // Non-cacheable so get() must consult storage (a cacheable schema would serve the warm cache and
    // never exercise the fail-safe blob-read path this test targets).
    const NC: CredentialSchema = {
      ref: { namespace: "svc", providerId: "p" },
      fields: [
        { key: "apiKey", secret: true, required: true },
        { key: "label", secret: false },
      ],
      sessionCacheable: false,
    };
    mgr.registerCredentialSchema(NC);
    await mgr.setCredentials(NC.ref, { apiKey: "k", label: "L" });
    // Simulate a partial at-rest corruption: the encrypted blob vanishes, the index entry remains.
    storage.removeItem(secretsKey("credmgr", "svc", "user-1"));
    // has() still reports present (index-driven), but get() must never surface a secret it can't
    // authenticate — the secret field is simply absent (secrets are sourced only from the blob).
    expect(mgr.hasCredentials(NC.ref)).toBe(true);
    const got = (await mgr.getCredentials(NC.ref)) as CredentialValues;
    expect(got.apiKey).toBeUndefined();
    expect(got.label).toBe("L"); // the non-secret index value still renders
  });
});
