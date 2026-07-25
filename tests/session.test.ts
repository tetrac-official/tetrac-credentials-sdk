// Session-handler tests (PRD §11.3): one unlock → many reads survive the 15s auto-lock;
// logout wipes the cache; a non-cacheable schema re-prompts; a custody-marked key is
// never cached; account-switch isolates identities; dispose() detaches the listener.
import { afterEach, describe, expect, it } from "vitest";
import {
  VaultLockedError,
  createCredentialManager,
  type CredentialManager,
  type CredentialSchema,
  type CredentialValues,
} from "../src/index.js";
import { createMemoryStorage, createVault } from "./helpers.js";

// Cacheable (B2) schema — decrypted value should survive an auto-lock.
const CACHEABLE: CredentialSchema = {
  ref: { namespace: "exchange", providerId: "venue-x" },
  fields: [{ key: "apiKey", secret: true, required: true }],
  sessionCacheable: true,
};

// Non-cacheable schema — must decrypt-per-read (re-prompt after lock).
const PER_READ: CredentialSchema = {
  ref: { namespace: "service", providerId: "per-read-provider" },
  fields: [{ key: "apiKey", secret: true, required: true }],
  sessionCacheable: false,
};

// Custody-marked schema — hard-excluded from caching even though sessionCacheable is true.
const CUSTODY: CredentialSchema = {
  ref: { namespace: "signing", providerId: "agent-key" },
  fields: [{ key: "secretKey", secret: true, required: true }],
  sessionCacheable: true,
  custody: true,
};

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

describe("session handler (B2 policy)", () => {
  it("one unlock → reads survive the 15s idle auto-lock", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(CACHEABLE);
    await mgr.setCredentials(CACHEABLE.ref, { apiKey: "ak" });
    // First read decrypts + caches.
    expect(await mgr.getCredentials(CACHEABLE.ref)).toEqual({ apiKey: "ak" });
    // Auto-lock: app key clears, identity stays, lock signal fires.
    vault.autoLock();
    expect(vault.getAppKey()).toBeNull();
    // Cached read still succeeds despite the null app key — user unlocks at most once.
    expect(await mgr.getCredentials(CACHEABLE.ref)).toEqual({ apiKey: "ak" });
  });

  it("logout wipes the cache → next read throws VaultLockedError", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(CACHEABLE);
    await mgr.setCredentials(CACHEABLE.ref, { apiKey: "ak" });
    await mgr.getCredentials(CACHEABLE.ref); // warm cache
    // Logout: app key AND identity clear; lock signal fires → cache wiped.
    vault.logout();
    // With no cache and no key, the read surfaces the locked state.
    await expect(mgr.getCredentials(CACHEABLE.ref)).rejects.toBeInstanceOf(VaultLockedError);
  });

  it("non-cacheable schema re-prompts (decrypt-per-read) after an auto-lock", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(PER_READ);
    await mgr.setCredentials(PER_READ.ref, { apiKey: "ak" });
    // Reads fine while unlocked.
    expect(await mgr.getCredentials(PER_READ.ref)).toEqual({ apiKey: "ak" });
    // Auto-lock (same identity). Nothing was cached, so the next read needs the key.
    vault.autoLock();
    await expect(mgr.getCredentials(PER_READ.ref)).rejects.toBeInstanceOf(VaultLockedError);
    // Unlock again → reads once more.
    vault.unlock();
    expect(await mgr.getCredentials(PER_READ.ref)).toEqual({ apiKey: "ak" });
  });

  it("custody-marked key is NEVER cached (R-3), even with sessionCacheable true", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(CUSTODY);
    await mgr.setCredentials(CUSTODY.ref, { secretKey: "sk" });
    // Reads while unlocked.
    expect(await mgr.getCredentials(CUSTODY.ref)).toEqual({ secretKey: "sk" });
    // Auto-lock: because custody keys are never cached, the next read must re-prompt.
    vault.autoLock();
    await expect(mgr.getCredentials(CUSTODY.ref)).rejects.toBeInstanceOf(VaultLockedError);
  });

  it("account switch isolates identities — user-2 cannot read user-1's cache or storage", async () => {
    const vault = createVault({ identity: "user-1" });
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(CACHEABLE);
    // user-1 stores + caches.
    await mgr.setCredentials(CACHEABLE.ref, { apiKey: "u1-key" });
    await mgr.getCredentials(CACHEABLE.ref);
    // Switch to user-2 (fires lock signal → drops user-1's cache).
    vault.switchTo("user-2");
    // user-2 has nothing stored → null (NOT user-1's cached value).
    expect(await mgr.getCredentials(CACHEABLE.ref)).toBeNull();
    // Switch back to user-1 → their persisted credential decrypts again.
    vault.switchTo("user-1");
    expect((await mgr.getCredentials(CACHEABLE.ref)) as CredentialValues).toEqual({ apiKey: "u1-key" });
  });

  it("dispose() detaches the lock listener", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    // One listener is attached at construction.
    expect(vault.listenerCount()).toBe(1);
    mgr.dispose();
    // dispose() unsubscribes it.
    expect(vault.listenerCount()).toBe(0);
    // Remove from the teardown list (already disposed).
    live = live.filter((m) => m !== mgr);
  });
});
