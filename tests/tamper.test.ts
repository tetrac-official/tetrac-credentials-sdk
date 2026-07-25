// Adversarial hardening suite — the at-rest TAMPERER (threat-model adversary #1) and ordinary
// storage corruption. These lock in three invariants found by the v0.1.1 audit pass:
//   F-11 — the lock-free probes (has/list/summary/get) fail SAFE against a malformed index ENTRY
//          (not just a malformed whole index): they report "absent", never throw, never mis-list.
//   F-12 — a schema-declared SECRET field can only ever be sourced from the AUTHENTICATED blob,
//          never from the unauthenticated, app-writable plaintext index.
//   F-13 — reserved object keys (__proto__/constructor/prototype) are rejected at registration so
//          the plain-object blob/index stores can't silently drop a credential.
// All schemas are FAKE/runtime — no provider names (R-4).
import { afterEach, describe, expect, it } from "vitest";
import {
  CredentialSchemaError,
  createCredentialManager,
  type CredentialManager,
  type CredentialSchema,
  type CredentialValues,
} from "../src/index.js";
import { indexKey } from "../src/manager.js";
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

const SINGLE: CredentialSchema = {
  ref: { namespace: "exchange", providerId: "venue-x" },
  fields: [{ key: "apiKey", secret: true, required: true }],
  sessionCacheable: true,
};

// ---- F-11: probe fail-safe against a malformed index ENTRY ------------------

describe("hardening — probe fail-safe on a malformed index ENTRY (F-11)", () => {
  // Each is a WELL-FORMED top-level index object whose single entry is malformed. readIndex's
  // pre-F-11 guard only checked the top level, so these reached getSummary and threw a TypeError.
  const MALFORMED: Array<{ label: string; json: string }> = [
    { label: "entry is a number", json: '{"venue-x":42}' },
    { label: "entry is null", json: '{"venue-x":null}' },
    { label: "entry is an array", json: '{"venue-x":[1,2,3]}' },
    { label: "entry is a string", json: '{"venue-x":"nope"}' },
    { label: "entry missing publicFields", json: '{"venue-x":{"secretKeys":[],"updatedAt":1}}' },
    { label: "entry missing secretKeys", json: '{"venue-x":{"publicFields":{},"updatedAt":1}}' },
    { label: "entry publicFields is an array", json: '{"venue-x":{"publicFields":[],"secretKeys":[],"updatedAt":1}}' },
    { label: "entry updatedAt not a number", json: '{"venue-x":{"publicFields":{},"secretKeys":[],"updatedAt":"x"}}' },
    { label: "entry count not a number", json: '{"venue-x":{"publicFields":{},"secretKeys":[],"updatedAt":1,"count":"x"}}' },
  ];

  for (const { label, json } of MALFORMED) {
    it(`every probe treats a corrupt entry as absent — never throws — when ${label}`, async () => {
      const vault = createVault();
      const storage = createMemoryStorage();
      const mgr = makeManager(vault, storage);
      mgr.registerCredentialSchema(SINGLE);
      storage.setItem(indexKey("credmgr", "exchange", "user-1"), json);
      // None of the lock-free probes may throw, and all must agree "absent".
      expect(() => mgr.getSummary(SINGLE.ref)).not.toThrow();
      expect(mgr.getSummary(SINGLE.ref)).toBeNull();
      expect(mgr.hasCredentials(SINGLE.ref)).toBe(false);
      expect(mgr.listProviders("exchange")).toEqual([]);
      // getCredentials (which reads the index too) must report null, not {} or partial data.
      expect(await mgr.getCredentials(SINGLE.ref)).toBeNull();
    });
  }

  it("a corrupt entry is dropped but a VALID sibling entry in the same index still works", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const writer = makeManager(vault, storage);
    const good = { namespace: "exchange", providerId: "good" };
    writer.registerCredentialSchema({ ref: good, fields: [{ key: "apiKey", secret: true, required: true }] });
    await writer.setCredentials(good, { apiKey: "GOOD" });
    // Splice a malformed sibling entry into the same namespace index next to the valid one.
    const key = indexKey("credmgr", "exchange", "user-1");
    const idx = JSON.parse(storage.getItem(key) as string) as Record<string, unknown>;
    idx["broken"] = 42;
    storage.setItem(key, JSON.stringify(idx));
    // Fresh reader (cold cache) forces the storage/decrypt path.
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema({ ref: good, fields: [{ key: "apiKey", secret: true, required: true }] });
    expect(reader.listProviders("exchange")).toEqual(["good"]); // broken dropped, good kept
    expect(reader.hasCredentials(good)).toBe(true);
    expect(await reader.getCredentials(good)).toEqual({ apiKey: "GOOD" });
    expect(reader.hasCredentials({ namespace: "exchange", providerId: "broken" })).toBe(false);
  });

  it("a valid entry (regression) is never dropped by the entry validator", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "ok" });
    expect(mgr.hasCredentials(SINGLE.ref)).toBe(true);
    expect(mgr.getSummary(SINGLE.ref)?.fields).toEqual(["apiKey"]);
    expect(await mgr.getCredentials(SINGLE.ref)).toEqual({ apiKey: "ok" });
  });
});

// ---- F-12: a secret value can never come from the plaintext index -----------

describe("hardening — secret fields only ever come from the authenticated blob (F-12)", () => {
  // apiKey + an OPTIONAL passphrase are secret; walletAddress is public.
  const OPT: CredentialSchema = {
    ref: { namespace: "exchange", providerId: "venue" },
    fields: [
      { key: "apiKey", secret: true, required: true },
      { key: "passphrase", secret: true }, // optional — deliberately left unset below
      { key: "walletAddress", secret: false },
    ],
  };

  function tamperIndex(
    storage: ReturnType<typeof createMemoryStorage>,
    mutate: (entry: { publicFields: Record<string, string> }) => void,
  ): void {
    const key = indexKey("credmgr", "exchange", "user-1");
    const idx = JSON.parse(storage.getItem(key) as string) as Record<string, { publicFields: Record<string, string> }>;
    mutate(idx["venue"] as { publicFields: Record<string, string> });
    storage.setItem(key, JSON.stringify(idx));
  }

  it("an index-planted OPTIONAL secret (absent from the blob) is NOT returned", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const writer = makeManager(vault, storage);
    writer.registerCredentialSchema(OPT);
    await writer.setCredentials(OPT.ref, { apiKey: "real", walletAddress: "0xpub" }); // no passphrase
    // Attacker plants a value for the secret `passphrase` field in the plaintext index.
    tamperIndex(storage, (e) => {
      e.publicFields.passphrase = "ATTACKER-PLANTED";
    });
    // Cold reader forces the storage merge path.
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema(OPT);
    const got = (await reader.getCredentials(OPT.ref)) as CredentialValues;
    expect(got).toEqual({ apiKey: "real", walletAddress: "0xpub" }); // no planted passphrase
    expect(got.passphrase).toBeUndefined();
  });

  it("an index-planted value for a POPULATED secret is overridden by the authentic blob value", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const writer = makeManager(vault, storage);
    writer.registerCredentialSchema(OPT);
    await writer.setCredentials(OPT.ref, { apiKey: "AUTHENTIC", walletAddress: "0xpub" });
    tamperIndex(storage, (e) => {
      e.publicFields.apiKey = "ATTACKER"; // secret-named key planted in the index
    });
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema(OPT);
    expect(((await reader.getCredentials(OPT.ref)) as CredentialValues).apiKey).toBe("AUTHENTIC");
  });

  it("non-secret index fields still flow through (the filter is not over-broad)", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(OPT);
    await mgr.setCredentials(OPT.ref, { apiKey: "real", walletAddress: "0xWALLET" });
    expect(await mgr.getCredentials(OPT.ref)).toEqual({ apiKey: "real", walletAddress: "0xWALLET" });
  });
});

// ---- F-13: reserved object keys are rejected at registration ----------------

describe("hardening — reserved object keys rejected at registration (F-13)", () => {
  for (const bad of ["__proto__", "constructor", "prototype"]) {
    it(`rejects "${bad}" as a namespace`, () => {
      const mgr = makeManager(createVault());
      expect(() =>
        mgr.registerCredentialSchema({ ref: { namespace: bad, providerId: "p" }, fields: [{ key: "k", secret: true }] }),
      ).toThrow(CredentialSchemaError);
    });
    it(`rejects "${bad}" as a providerId`, () => {
      const mgr = makeManager(createVault());
      expect(() =>
        mgr.registerCredentialSchema({ ref: { namespace: "n", providerId: bad }, fields: [{ key: "k", secret: true }] }),
      ).toThrow(CredentialSchemaError);
    });
    it(`rejects "${bad}" as a field key`, () => {
      const mgr = makeManager(createVault());
      expect(() =>
        mgr.registerCredentialSchema({ ref: { namespace: "n", providerId: "p" }, fields: [{ key: bad, secret: true }] }),
      ).toThrow(CredentialSchemaError);
    });
  }

  it("registering a reserved key never pollutes Object.prototype", () => {
    const mgr = makeManager(createVault());
    try {
      mgr.registerCredentialSchema({ ref: { namespace: "__proto__", providerId: "p" }, fields: [{ key: "k", secret: true }] });
    } catch {
      /* expected */
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, "k")).toBe(false);
  });

  it("the check is exact-match — identifiers that merely resemble reserved keys are allowed", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    const ref = { namespace: "proto", providerId: "constructorX" };
    expect(() =>
      mgr.registerCredentialSchema({ ref, fields: [{ key: "prototypeKey", secret: true, required: true }] }),
    ).not.toThrow();
    await mgr.setCredentials(ref, { prototypeKey: "value" });
    expect(await mgr.getCredentials(ref)).toEqual({ prototypeKey: "value" });
  });
});
