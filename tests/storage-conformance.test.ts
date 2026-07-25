// StorageLike conformance. The SDK leans on exact Web Storage semantics (getItem null-on-absent,
// setItem overwrite, removeItem, key(index) enumeration, live length) — yet nothing pinned those
// assumptions. This suite exercises them against the in-memory double the tests use, which is
// intentionally the SAME shape a host injects (e.g. the demo's createMemoryStorage / real
// localStorage). It also drives the SDK end-to-end over the double and stresses the one place the SDK
// enumerates the store itself: clearNamespace across multiple identities while key() re-indexes.
import { describe, expect, it } from "vitest";
import {
  createCredentialManager,
  type CredentialSchema,
  type StorageLike,
} from "../src/index.js";
import { createMemoryStorage, createVault } from "./helpers.js";

describe("StorageLike conformance (Web Storage semantics the SDK relies on)", () => {
  it("getItem returns null for an absent key and the stored value for a present one", () => {
    const s: StorageLike = createMemoryStorage();
    expect(s.getItem("missing")).toBeNull();
    s.setItem("k", "v");
    expect(s.getItem("k")).toBe("v");
  });

  it("setItem overwrites in place without changing length", () => {
    const s = createMemoryStorage();
    s.setItem("k", "v1");
    expect(s.length).toBe(1);
    s.setItem("k", "v2");
    expect(s.getItem("k")).toBe("v2");
    expect(s.length).toBe(1);
  });

  it("removeItem deletes the key, drops length, and is a no-op on an absent key", () => {
    const s = createMemoryStorage();
    s.setItem("k", "v");
    s.removeItem("k");
    expect(s.getItem("k")).toBeNull();
    expect(s.length).toBe(0);
    expect(() => s.removeItem("k")).not.toThrow();
    expect(s.length).toBe(0);
  });

  it("length reflects the live count and key(index) enumerates every key, null out of range", () => {
    const s = createMemoryStorage();
    s.setItem("a", "1");
    s.setItem("b", "2");
    s.setItem("c", "3");
    expect(s.length).toBe(3);
    const seen = new Set<string>();
    for (let i = 0; i < s.length; i += 1) seen.add(s.key(i)!);
    expect(seen).toEqual(new Set(["a", "b", "c"]));
    expect(s.key(3)).toBeNull();
    expect(s.key(99)).toBeNull();
  });

  it("the SDK round-trips end-to-end over the injected StorageLike", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = createCredentialManager({
      getAppKey: vault.getAppKey,
      getIdentity: vault.getIdentity,
      subscribeLock: vault.subscribeLock,
      storage,
    });
    const ref = { namespace: "exchange", providerId: "venue" };
    mgr.registerCredentialSchema({
      ref,
      fields: [
        { key: "apiKey", secret: true, required: true },
        { key: "label", secret: false },
      ],
    });
    await mgr.setCredentials(ref, { apiKey: "k", label: "L" });
    expect(await mgr.getCredentials(ref)).toEqual({ apiKey: "k", label: "L" });
    mgr.dispose();
  });
});

describe("clearNamespace enumerates + removes across identities even as key() re-indexes", () => {
  it("removes every 'a' key for all identities, leaving other namespaces intact", async () => {
    const vault = createVault({ identity: "user-1" });
    const storage = createMemoryStorage();
    const mgr = createCredentialManager({
      getAppKey: vault.getAppKey,
      getIdentity: vault.getIdentity,
      subscribeLock: vault.subscribeLock,
      storage,
    });
    const A: CredentialSchema = {
      ref: { namespace: "a", providerId: "p" },
      fields: [{ key: "apiKey", secret: true, required: true }],
    };
    const B: CredentialSchema = {
      ref: { namespace: "b", providerId: "p" },
      fields: [{ key: "apiKey", secret: true, required: true }],
    };
    mgr.registerCredentialSchema(A);
    mgr.registerCredentialSchema(B);
    // Two identities each hold a credential in namespace 'a'; user-1 also holds one in 'b'.
    await mgr.setCredentials(A.ref, { apiKey: "u1-a" });
    await mgr.setCredentials(B.ref, { apiKey: "u1-b" });
    vault.switchTo("user-2");
    await mgr.setCredentials(A.ref, { apiKey: "u2-a" });
    // Sanity: namespace 'a' has keys for both identities (2 secrets + 2 index = 4), 'b' has 2.
    const aKeysBefore = countKeys(storage, "credmgr:a:");
    expect(aKeysBefore).toBe(4);
    // Nuke 'a' across ALL identities. namespaceKeys collects first, so key()-reindexing on delete is safe.
    mgr.clearNamespace("a");
    expect(countKeys(storage, "credmgr:a:")).toBe(0);
    // Namespace 'b' is untouched.
    expect(countKeys(storage, "credmgr:b:")).toBe(2);
    vault.switchTo("user-1");
    expect(await mgr.getCredentials(B.ref)).toEqual({ apiKey: "u1-b" });
    expect(mgr.hasCredentials(A.ref)).toBe(false);
    mgr.dispose();
  });
});

function countKeys(
  storage: ReturnType<typeof createMemoryStorage>,
  prefix: string,
): number {
  let n = 0;
  for (let i = 0; i < storage.length; i += 1) {
    if (storage.key(i)!.startsWith(prefix)) n += 1;
  }
  return n;
}
