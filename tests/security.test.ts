// RED-TEAM hardening suite for @tetrac/credentials-sdk (audit v0.1.0).
// Every test here is adversarial: it either reproduces a finding the audit fixed
// (F-1..F-5) or locks in an at-rest / isolation invariant so a regression fails CI.
// All schemas are FAKE/runtime — no provider names, consistent with R-4.
import { afterEach, describe, expect, it } from "vitest";
import {
  CredentialSchemaError,
  createCredentialManager,
  type CredentialManager,
  type CredentialSchema,
  type CredentialValues,
} from "../src/index.js";
import { decryptString, encryptString } from "../src/crypto.js";
import { indexKey, secretsKey } from "../src/manager.js";
import { createMemoryStorage, createVault } from "./helpers.js";

// ---- shared harness ---------------------------------------------------------

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

// base64 <-> bytes helpers for byte-level tampering (Node/browser globals only).
function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin);
}

const SECRET: CredentialSchema = {
  ref: { namespace: "exchange", providerId: "venue-x" },
  fields: [{ key: "apiKey", secret: true, required: true }],
  sessionCacheable: true,
};

// ---- F-4: storage-key ':' delimiter -----------------------------------------

describe("hardening — storage-key delimiter (F-4)", () => {
  it("clearNamespace('a') must NOT nuke the hierarchical sibling namespace 'a:b'", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    const outer = { namespace: "a", providerId: "p" };
    const inner = { namespace: "a:b", providerId: "p" };
    mgr.registerCredentialSchema({ ref: outer, fields: [{ key: "apiKey", secret: true, required: true }] });
    mgr.registerCredentialSchema({ ref: inner, fields: [{ key: "apiKey", secret: true, required: true }] });
    await mgr.setCredentials(outer, { apiKey: "OUTER" });
    await mgr.setCredentials(inner, { apiKey: "INNER" });
    mgr.clearNamespace("a");
    expect(mgr.hasCredentials(outer)).toBe(false); // targeted namespace is gone
    expect(mgr.hasCredentials(inner)).toBe(true); // sibling survives
    expect(await mgr.getCredentials(inner)).toEqual({ apiKey: "INNER" });
  });

  it("two namespaces separated only by a ':' boundary stay isolated on disk", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    const a = { namespace: "svc:a", providerId: "p" };
    const b = { namespace: "svc", providerId: "a:p" };
    mgr.registerCredentialSchema({ ref: a, fields: [{ key: "apiKey", secret: true, required: true }] });
    mgr.registerCredentialSchema({ ref: b, fields: [{ key: "apiKey", secret: true, required: true }] });
    await mgr.setCredentials(a, { apiKey: "A" });
    await mgr.setCredentials(b, { apiKey: "B" });
    expect(await mgr.getCredentials(a)).toEqual({ apiKey: "A" });
    expect(await mgr.getCredentials(b)).toEqual({ apiKey: "B" });
    // Distinct encoded storage slots (no collision).
    expect(secretsKey("credmgr", "svc:a", "user-1")).not.toBe(secretsKey("credmgr", "svc", "user-1"));
  });
});

// ---- F-1/F-2/F-3: identifier hygiene + injective keys ------------------------

describe("hardening — identifier hygiene & key injectivity (F-1/F-2/F-3)", () => {
  it("rejects a namespace or providerId containing control characters", () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    expect(() =>
      mgr.registerCredentialSchema({ ref: { namespace: "ns\u0000x", providerId: "p" }, fields: [{ key: "k", secret: true }] }),
    ).toThrow(CredentialSchemaError);
    expect(() =>
      mgr.registerCredentialSchema({ ref: { namespace: "ns", providerId: "p\u0001" }, fields: [{ key: "k", secret: true }] }),
    ).toThrow(CredentialSchemaError);
  });

  it("two distinct refs never collide in the schema registry (secret routing preserved)", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    // A naive character-join of these two refs would land on the same registry key.
    const refA = { namespace: "a b", providerId: "c" };
    const refB = { namespace: "a", providerId: "b c" };
    mgr.registerCredentialSchema({ ref: refA, fields: [{ key: "v", secret: true, required: true }], sessionCacheable: false });
    mgr.registerCredentialSchema({ ref: refB, fields: [{ key: "v", secret: false }], sessionCacheable: false });
    await mgr.setCredentials(refA, { v: "SECRET-A" }); // v is SECRET here → must be encrypted
    await mgr.setCredentials(refB, { v: "PUBLIC-B" }); // v is NON-secret here → plaintext index
    expect(await mgr.getCredentials(refA)).toEqual({ v: "SECRET-A" });
    expect(await mgr.getCredentials(refB)).toEqual({ v: "PUBLIC-B" });
    // The secret value must NOT have leaked into refA's plaintext index.
    expect(storage.getItem(indexKey("credmgr", "a b", "user-1")) ?? "").not.toContain("SECRET-A");
    // The non-secret value SHOULD be in refB's plaintext index (proves distinct schema applied).
    expect(storage.getItem(indexKey("credmgr", "a", "user-1")) ?? "").toContain("PUBLIC-B");
  });
});

// ---- F-5: session-cache reference hygiene -----------------------------------

describe("hardening — session-cache reference hygiene (F-5)", () => {
  it("mutating a returned single-set credential does not poison the cache", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "REAL" });
    const first = (await mgr.getCredentials(SECRET.ref)) as CredentialValues;
    first.apiKey = "TAMPERED";
    expect(((await mgr.getCredentials(SECRET.ref)) as CredentialValues).apiKey).toBe("REAL");
  });

  it("mutating a returned multi list does not poison the cache", async () => {
    const vault = createVault();
    const ref = { namespace: "service", providerId: "keys" };
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema({ ref, fields: [{ key: "apiKey", secret: true, required: true }], multi: true, sessionCacheable: true });
    await mgr.setCredentials(ref, [{ apiKey: "k1" }, { apiKey: "k2" }]);
    const list = (await mgr.getCredentials(ref)) as CredentialValues[];
    list.push({ apiKey: "INJECTED" });
    (list[0] as CredentialValues).apiKey = "TAMPERED";
    expect(await mgr.getCredentials(ref)).toEqual([{ apiKey: "k1" }, { apiKey: "k2" }]);
  });

  it("mutating the input object after setCredentials does not reach the cache", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SECRET);
    const input = { apiKey: "REAL" };
    await mgr.setCredentials(SECRET.ref, input);
    input.apiKey = "TAMPERED"; // caller keeps + mutates its own object
    expect(((await mgr.getCredentials(SECRET.ref)) as CredentialValues).apiKey).toBe("REAL");
  });
});

// ---- account isolation with prefix-y identities -----------------------------

describe("hardening — identity isolation (exact-key, no prefix aliasing)", () => {
  it("switching to a prefix-related identity cannot read the previous account's cache", async () => {
    const vault = createVault({ identity: "user" });
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "USER-SECRET" });
    await mgr.getCredentials(SECRET.ref); // warm cache under "user"
    // "user-extra" is a prefix superset of "user".
    vault.switchTo("user-extra");
    expect(await mgr.getCredentials(SECRET.ref)).toBeNull(); // no leak of "user"'s value
    // Back to "user": their own persisted credential still decrypts.
    vault.switchTo("user");
    expect(await mgr.getCredentials(SECRET.ref)).toEqual({ apiKey: "USER-SECRET" });
  });
});

// ---- at-rest crypto (AES-256-GCM envelope) ----------------------------------

describe("hardening — at-rest crypto (AES-256-GCM)", () => {
  it("uses a fresh random IV per encryption (no deterministic ciphertext)", async () => {
    const a = await encryptString("k", "same-plaintext", "aad");
    const b = await encryptString("k", "same-plaintext", "aad");
    expect(a).not.toEqual(b);
    expect(await decryptString("k", a, "aad")).toBe("same-plaintext");
  });

  it("decryption fails when the AAD does not match (slot binding)", async () => {
    const env = await encryptString("k", "p", "aad-1");
    await expect(decryptString("k", env, "aad-2")).rejects.toThrow();
  });

  it("decryption fails under the wrong app key", async () => {
    const env = await encryptString("key-1", "p", "aad");
    await expect(decryptString("key-2", env, "aad")).rejects.toThrow();
  });

  it("a single flipped ciphertext byte is detected (GCM auth tag)", async () => {
    const env = await encryptString("k", "sensitive", "aad");
    const bytes = b64ToBytes(env);
    // Flip a byte inside the ciphertext region (past the 1-byte version + 12-byte IV).
    const i = bytes.length - 1;
    bytes[i] = (bytes[i]! ^ 0xff) & 0xff;
    await expect(decryptString("k", bytesToB64(bytes), "aad")).rejects.toThrow();
  });

  it("an unsupported envelope version byte is rejected", async () => {
    const env = await encryptString("k", "p", "aad");
    const bytes = b64ToBytes(env);
    bytes[0] = 0x02; // version 2 does not exist
    await expect(decryptString("k", bytesToB64(bytes), "aad")).rejects.toThrow(/version/i);
  });

  it("a truncated envelope is rejected", async () => {
    const env = await encryptString("k", "p", "aad");
    const bytes = b64ToBytes(env).subarray(0, 5); // shorter than version + IV
    await expect(decryptString("k", bytesToB64(bytes), "aad")).rejects.toThrow(/malformed/i);
  });
});

// ---- end-to-end confidentiality & fail-safe ---------------------------------

describe("hardening — end-to-end confidentiality & fail-safe", () => {
  it("a secret blob transplanted into another identity's slot fails to decrypt (AAD)", async () => {
    const vault = createVault({ identity: "user-1" });
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "u1-secret" });
    // Attacker copies user-1's encrypted blob + index into user-2's slots.
    const blob = storage.getItem(secretsKey("credmgr", "exchange", "user-1"))!;
    const index = storage.getItem(indexKey("credmgr", "exchange", "user-1"))!;
    storage.setItem(secretsKey("credmgr", "exchange", "user-2"), blob);
    storage.setItem(indexKey("credmgr", "exchange", "user-2"), index);
    // Log in as user-2: the transplanted blob is AAD-bound to user-1's slot → must fail.
    vault.switchTo("user-2");
    await expect(mgr.getCredentials(SECRET.ref)).rejects.toThrow();
  });

  it("tampering with the stored secret blob makes get() fail closed (never forged plaintext)", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const writer = makeManager(vault, storage);
    writer.registerCredentialSchema(SECRET);
    await writer.setCredentials(SECRET.ref, { apiKey: "authentic" });
    // Flip a byte in the stored ciphertext.
    const key = secretsKey("credmgr", "exchange", "user-1");
    const bytes = b64ToBytes(storage.getItem(key)!);
    bytes[bytes.length - 1] = (bytes[bytes.length - 1]! ^ 0xff) & 0xff;
    storage.setItem(key, bytesToB64(bytes));
    // Fresh reader to bypass the session cache.
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema(SECRET);
    await expect(reader.getCredentials(SECRET.ref)).rejects.toThrow();
  });

  it("a corrupt (non-base64) secret blob fails closed instead of returning partial data", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "ok" });
    storage.setItem(secretsKey("credmgr", "exchange", "user-1"), "@@@not-base64@@@");
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema(SECRET);
    await expect(reader.getCredentials(SECRET.ref)).rejects.toThrow();
  });

  it("no secret value appears in the plaintext index or the on-disk ciphertext", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema({
      ref: { namespace: "exchange", providerId: "v" },
      fields: [
        { key: "apiKey", secret: true, required: true },
        { key: "walletAddress", secret: false },
      ],
    });
    await mgr.setCredentials({ namespace: "exchange", providerId: "v" }, { apiKey: "TOP-SECRET", walletAddress: "0xPUB" });
    const idx = storage.getItem(indexKey("credmgr", "exchange", "user-1")) ?? "";
    const blob = storage.getItem(secretsKey("credmgr", "exchange", "user-1")) ?? "";
    expect(idx).toContain("0xPUB"); // non-secret is indexed
    expect(idx).not.toContain("TOP-SECRET"); // secret never in the index
    expect(blob).not.toContain("TOP-SECRET"); // and never in clear in the ciphertext
  });

  it("a crafted plaintext index cannot pollute Object.prototype", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema({ ref: { namespace: "exchange", providerId: "v" }, fields: [{ key: "walletAddress", secret: false }] });
    // A RAW JSON string with a genuine "__proto__" key — an object literal `{ __proto__: … }`
    // sets the prototype and is DROPPED by JSON.stringify, which would make this test vacuous.
    // JSON.parse instead creates "__proto__" as an OWN property; the SDK must not let it pollute.
    storage.setItem(
      indexKey("credmgr", "exchange", "user-1"),
      '{"__proto__":{"polluted":true},"v":{"publicFields":{"walletAddress":"0x"},"secretKeys":[],"updatedAt":1}}',
    );
    // Exercise every index-reading path.
    mgr.listProviders("exchange");
    mgr.getSummary({ namespace: "exchange", providerId: "v" });
    await mgr.getCredentials({ namespace: "exchange", providerId: "v" });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, "polluted")).toBe(false);
  });
});

// ---- F-9: KDF domain separation ---------------------------------------------

describe("hardening — KDF domain separation (F-9)", () => {
  it("the AES key is domain-separated (a plain SHA-256(appKey) key no longer decrypts)", async () => {
    const appKey = "high-entropy-vault-key";
    const env = await encryptString(appKey, "secret-payload", "aad-slot");
    // Reconstruct the PRE-hardening key = SHA-256(appKey) with no domain prefix.
    const enc = new TextEncoder();
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(appKey));
    const oldKey = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["decrypt"]);
    const bytes = b64ToBytes(env); // [1 version][12 iv][ct+tag]
    // Copy through `new Uint8Array` so TS sees a plain-ArrayBuffer-backed BufferSource.
    const iv = new Uint8Array(bytes.subarray(1, 13));
    const ct = new Uint8Array(bytes.subarray(13));
    const aad = new Uint8Array(enc.encode("aad-slot"));
    // The old derivation must FAIL — proof the SDK now binds the key to its own domain.
    await expect(
      crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, oldKey, ct),
    ).rejects.toThrow();
    // The SDK's own (domain-separated) derivation still round-trips.
    expect(await decryptString(appKey, env, "aad-slot")).toBe("secret-payload");
  });

  it("distinct app keys still derive distinct AES keys (prefix is injective)", async () => {
    const env = await encryptString("key-A", "p", "aad");
    await expect(decryptString("key-B", env, "aad")).rejects.toThrow();
  });
});

// ---- F-6: empty-multi consistency -------------------------------------------

describe("hardening — empty-multi consistency (F-6)", () => {
  const MULTI: CredentialSchema = {
    ref: { namespace: "service", providerId: "keylist" },
    fields: [{ key: "apiKey", secret: true, required: true }],
    multi: true,
    sessionCacheable: true,
  };

  it("setting a multi list to [] makes has()/get()/list() all agree it is absent", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(MULTI);
    await mgr.setCredentials(MULTI.ref, []);
    expect(mgr.hasCredentials(MULTI.ref)).toBe(false);
    expect(await mgr.getCredentials(MULTI.ref)).toBeNull();
    expect(mgr.listProviders("service")).not.toContain("keylist");
  });

  it("clearing a previously-populated multi list to [] removes it (and drops the cache)", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(MULTI);
    await mgr.setCredentials(MULTI.ref, [{ apiKey: "k1" }, { apiKey: "k2" }]);
    await mgr.getCredentials(MULTI.ref); // warm cache
    await mgr.setCredentials(MULTI.ref, []); // clear
    expect(mgr.hasCredentials(MULTI.ref)).toBe(false);
    expect(await mgr.getCredentials(MULTI.ref)).toBeNull(); // cache not serving a stale []
  });
});

// ---- concurrency: clearNamespace vs in-flight write (adversarial finding) ----

describe("hardening — clearNamespace concurrency (no resurrection of cleared secrets)", () => {
  it("a clearNamespace during an in-flight setCredentials does NOT resurrect the namespace", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "old" });
    // Kick off a new save but DON'T await it, then synchronously "clear all" — simulating a
    // clear-all click landing while the save is parked on its crypto await.
    const inFlight = mgr.setCredentials(SECRET.ref, { apiKey: "in-flight-secret" });
    mgr.clearNamespace("exchange");
    await inFlight; // let the save run to completion
    // The clear must win: the namespace stays empty; the resuming save did not re-persist it.
    expect(mgr.hasCredentials(SECRET.ref)).toBe(false);
    expect(await mgr.getCredentials(SECRET.ref)).toBeNull();
    expect(storage.getItem(secretsKey("credmgr", "exchange", "user-1"))).toBeNull();
    expect(mgr.listProviders("exchange")).toEqual([]);
  });

  it("a clearNamespace during an in-flight removeCredentials also leaves the namespace cleared", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "old" });
    const inFlight = mgr.removeCredentials(SECRET.ref);
    mgr.clearNamespace("exchange");
    await inFlight;
    expect(mgr.hasCredentials(SECRET.ref)).toBe(false);
    expect(storage.getItem(secretsKey("credmgr", "exchange", "user-1"))).toBeNull();
  });

  it("a normal setCredentials still commits when no clear intervenes (guard is not over-eager)", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "kept" });
    expect(await mgr.getCredentials(SECRET.ref)).toEqual({ apiKey: "kept" });
  });
});

// ---- probe agreement against a tampered/legacy count:0 index entry -----------

describe("hardening — probe agreement on a stray count:0 entry", () => {
  it("has/get/list/summary all treat a planted count:0 multi entry as absent", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    const ref = { namespace: "service", providerId: "ghost" };
    mgr.registerCredentialSchema({ ref, fields: [{ key: "apiKey", secret: true, required: true }], multi: true });
    // Simulate a legacy/tampered index entry with an empty list (count:0), which current code
    // never writes but list()/summary() must not treat as "present".
    storage.setItem(
      indexKey("credmgr", "service", "user-1"),
      JSON.stringify({ ghost: { publicFields: {}, secretKeys: [], updatedAt: 1, count: 0 } }),
    );
    expect(mgr.hasCredentials(ref)).toBe(false);
    expect(mgr.listProviders("service")).not.toContain("ghost");
    expect(mgr.getSummary(ref)).toBeNull();
    expect(await mgr.getCredentials(ref)).toBeNull();
  });
});

// ---- concurrency: clearNamespace vs in-flight READ (F-10 completeness) -------

describe("hardening — clearNamespace vs in-flight getCredentials (no cache resurrection)", () => {
  it("a clearNamespace during a cold-cache read neither returns nor caches the cleared secret", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    // Writer commits, then a COLD reader (empty cache) forces the storage-decrypt path.
    const writer = makeManager(vault, storage);
    writer.registerCredentialSchema(SECRET);
    await writer.setCredentials(SECRET.ref, { apiKey: "old" });
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema(SECRET);
    // Start the read (parks on the decrypt await), then synchronously clear the namespace.
    const inFlight = reader.getCredentials(SECRET.ref);
    reader.clearNamespace("exchange");
    // The in-flight read honors the clear (null, not the stale "old").
    expect(await inFlight).toBeNull();
    // And the cache was NOT re-warmed: the next read is still null, and at-rest is gone.
    expect(await reader.getCredentials(SECRET.ref)).toBeNull();
    expect(reader.hasCredentials(SECRET.ref)).toBe(false);
    expect(storage.getItem(secretsKey("credmgr", "exchange", "user-1"))).toBeNull();
  });
});

// ---- storage fail-safe & crypto edge inputs (coverage critic) ----------------

describe("hardening — storage fail-safe & crypto edge inputs", () => {
  it("a malformed plaintext index fails safe (probes report nothing, never throw)", () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    const key = indexKey("credmgr", "exchange", "user-1");
    // (a) unparseable JSON, (b) valid JSON that isn't an object — both → treated as empty.
    for (const bad of ["not-json{{{", "42", '"a string"', "null"]) {
      storage.setItem(key, bad);
      expect(mgr.hasCredentials(SECRET.ref)).toBe(false);
      expect(mgr.listProviders("exchange")).toEqual([]);
      expect(mgr.getSummary(SECRET.ref)).toBeNull();
    }
  });

  it("removeCredentials deletes the secrets AND index keys (no stray '{}')", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SECRET);
    await mgr.setCredentials(SECRET.ref, { apiKey: "a" });
    await mgr.removeCredentials(SECRET.ref);
    expect(storage.getItem(secretsKey("credmgr", "exchange", "user-1"))).toBeNull();
    expect(storage.getItem(indexKey("credmgr", "exchange", "user-1"))).toBeNull();
  });

  it("encrypt/decrypt round-trips empty, large, and multi-byte-unicode payloads", async () => {
    const payloads = ["", "x".repeat(200_000), "emoji 🎉 accénts ✓ 日本語 \u{1F510}"];
    for (const p of payloads) {
      const env = await encryptString("k", p, "aad");
      expect(await decryptString("k", env, "aad")).toBe(p);
    }
  });
});
