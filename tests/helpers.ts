// Shared test doubles for the credentials SDK. No provider names here either — the
// tests register FAKE schemas at runtime to prove the SDK never hardcodes a roster.
import type { StorageLike } from "../src/index.js";

/** An in-memory StorageLike backed by a Map, mirroring the Web Storage API the SDK needs. */
export function createMemoryStorage(): StorageLike & { size: () => number } {
  // The backing store; insertion order gives a stable key() enumeration.
  const map = new Map<string, string>();
  return {
    // Read a value or null when absent.
    getItem: (key) => (map.has(key) ? (map.get(key) as string) : null),
    // Write a value.
    setItem: (key, value) => {
      map.set(key, value);
    },
    // Delete a value.
    removeItem: (key) => {
      map.delete(key);
    },
    // Return the key at an index (for namespace enumeration), or null out of range.
    key: (index) => Array.from(map.keys())[index] ?? null,
    // Number of stored keys.
    get length() {
      return map.size;
    },
    // Test-only helper to assert how many keys are stored.
    size: () => map.size,
  };
}

/** A controllable mock of the injected login-SDK vault: app key, identity, and lock signal. */
export function createVault(initial?: { appKey?: string; identity?: string }) {
  // Current app key (null = locked/logged-out).
  let appKey: string | null = initial?.appKey ?? "test-app-key-v1";
  // Current identity (null = logged out).
  let identity: string | null = initial?.identity ?? "user-1";
  // Registered lock listeners.
  const listeners = new Set<() => void>();
  // Fire every lock listener (emulates the vault broadcasting a lock/logout event).
  const fire = () => {
    for (const cb of listeners) cb();
  };
  return {
    // ----- the three injected accessors the SDK consumes -----
    getAppKey: () => appKey,
    getIdentity: () => identity,
    subscribeLock: (cb: () => void) => {
      // Register the listener and hand back an unsubscribe.
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    // ----- test controls -----
    // Idle auto-lock: app key clears but identity stays; fires the lock signal.
    autoLock() {
      appKey = null;
      fire();
    },
    // Unlock again with a (possibly rotated) app key; no signal on unlock.
    unlock(key = "test-app-key-v1") {
      appKey = key;
    },
    // Full logout: app key AND identity clear; fires the lock signal.
    logout() {
      appKey = null;
      identity = null;
      fire();
    },
    // Account switch: new identity + fresh key; fires the lock signal.
    switchTo(nextIdentity: string, key = "test-app-key-v1") {
      identity = nextIdentity;
      appKey = key;
      fire();
    },
    // Number of live lock listeners (to assert dispose() detached).
    listenerCount: () => listeners.size,
  };
}
