// The key session handler for @tetrac/credentials-sdk (PRD §6).
// ONE place implements the owner-authorized PRD-7 "B2" policy for how long a
// DECRYPTED credential lives in memory:
//   - unlock once, cache per identity;
//   - survive the vault's 15s idle auto-lock;
//   - wipe on logout / account-switch (identity → null or changed);
//   - custody-marked credentials are NEVER cached (R-3).
import type { CredentialOutput, CredentialRef } from "./types.js";

/**
 * Deep-copy a cached value so the cache never hands out (or holds) a reference the caller
 * can mutate. Without this, `x = await getCredentials(ref); x.apiKey = "…"` would silently
 * rewrite the in-memory cache, and every later reader would see the tampered value.
 * `structuredClone` is a platform global (Node ≥17, all modern browsers) — no dependency —
 * and credential values are plain JSON-shaped data, so it clones them faithfully. (R-audit F-5.)
 */
function clone(value: CredentialOutput): CredentialOutput {
  return value === null ? null : (structuredClone(value) as CredentialOutput);
}

/**
 * In-memory cache of decrypted credential values, tagged by (identity → namespace → providerId).
 *
 * The tag is a THREE-LEVEL nested Map rather than a single delimited string key. That makes
 * every isolation property structural instead of string-parsing: two different refs, two
 * different identities, or two different namespaces can never alias each other regardless of
 * what characters an app puts in a namespace/providerId/identity — there is no separator byte
 * to collide on. Nothing here is persisted; it lives only for the session and is wiped on logout.
 */
export class SessionCache {
  /** identity → (namespace → (providerId → decrypted values)). */
  private readonly byIdentity = new Map<string, Map<string, Map<string, CredentialOutput>>>();

  /** Unsubscribe handle for the injected lock listener, so `dispose` can detach it. */
  private readonly unsubscribe: () => void;

  /**
   * @param getIdentity Reads the current account identity (null when logged out).
   * @param subscribeLock Subscribes to vault lock/logout events.
   */
  constructor(
    private readonly getIdentity: () => string | null,
    subscribeLock: (callback: () => void) => () => void,
  ) {
    // Wire the lock/logout signal to our wipe policy; keep the unsubscribe for teardown.
    this.unsubscribe = subscribeLock(() => this.onLockSignal());
  }

  /**
   * Return a COPY of the cached decrypted value for `ref` under the CURRENT identity, or
   * undefined on a miss. Never returns another identity's data (each identity is a separate
   * sub-Map) and never returns a live reference into the cache (the value is cloned out).
   */
  read(ref: CredentialRef): CredentialOutput | undefined {
    // Resolve who we are right now.
    const identity = this.getIdentity();
    // A logged-out context has no cache.
    if (identity === null) return undefined;
    // Walk identity → namespace → providerId; a missing level short-circuits to undefined.
    const hit = this.byIdentity.get(identity)?.get(ref.namespace)?.get(ref.providerId);
    // Clone on the way out so a caller mutating the result can't poison the cache.
    return hit === undefined ? undefined : clone(hit);
  }

  /**
   * Store a COPY of a decrypted value for `ref` under the CURRENT identity. No-op when logged
   * out (nothing to scope the entry to). Callers only invoke this for cacheable, non-custody
   * schemas — the custody hard-exclusion is enforced by the manager before calling here.
   */
  write(ref: CredentialRef, value: CredentialOutput): void {
    // Resolve the current identity.
    const identity = this.getIdentity();
    // Refuse to cache anything while logged out.
    if (identity === null) return;
    // Get-or-create the identity level.
    let byNamespace = this.byIdentity.get(identity);
    if (!byNamespace) {
      byNamespace = new Map();
      this.byIdentity.set(identity, byNamespace);
    }
    // Get-or-create the namespace level.
    let byProvider = byNamespace.get(ref.namespace);
    if (!byProvider) {
      byProvider = new Map();
      byNamespace.set(ref.namespace, byProvider);
    }
    // Record a CLONE so a later mutation of the caller's object can't reach into the cache.
    byProvider.set(ref.providerId, clone(value));
  }

  /**
   * Drop the cached entry for a single ref under the current identity (e.g. after a write
   * or a remove) so the next read reflects fresh storage.
   */
  invalidate(ref: CredentialRef): void {
    // Resolve the current identity.
    const identity = this.getIdentity();
    // Nothing identity-scoped to drop when logged out.
    if (identity === null) return;
    // Remove just this ref's slot (missing levels are a no-op).
    this.byIdentity.get(identity)?.get(ref.namespace)?.delete(ref.providerId);
  }

  /**
   * Drop every cached entry in a namespace across ALL identities. Used by clearNamespace.
   */
  invalidateNamespace(namespace: string): void {
    // Delete the namespace sub-Map from each identity that has one.
    for (const byNamespace of this.byIdentity.values()) byNamespace.delete(namespace);
  }

  /**
   * Wipe the entire cache (logout, teardown).
   */
  clear(): void {
    this.byIdentity.clear();
  }

  /**
   * The B2 lock/logout policy, invoked whenever the injected lock signal fires.
   *
   * The distinction that makes B2 correct: an idle AUTO-LOCK keeps the same identity
   * (the user is still logged in, just locked) → we KEEP the cache so they unlock once.
   * A LOGOUT/account-switch changes identity (→ null, or → a different account) → we
   * drop every account other than the current one. Because identities are Map keys (not a
   * string prefix), "user" and "user-2" are compared for exact equality — no prefix can
   * mask a stale account's decrypted secrets.
   *
   * NOTE (integration contract): correctness of the logout wipe depends on the injected
   * `getIdentity()` already reflecting the post-event state (null on logout, the new id on
   * switch) at the moment the lock signal fires. The host vault must update identity BEFORE
   * broadcasting the lock. If it fired first, a switched-away account's values would linger
   * in memory until the next signal — they are never cross-account READABLE (reads are
   * identity-scoped), but they would not be promptly dropped.
   */
  private onLockSignal(): void {
    // Who are we now that the signal fired?
    const identity = this.getIdentity();
    // Logged out entirely → wipe the whole cache.
    if (identity === null) {
      this.byIdentity.clear();
      return;
    }
    // Still logged in: keep only the current identity's decrypted values; drop every other
    // account's (defensive account-switch handling). Exact-key comparison, no prefix games.
    for (const key of this.byIdentity.keys()) {
      if (key !== identity) this.byIdentity.delete(key);
    }
  }

  /**
   * Detach the lock listener and wipe the cache. Call on manager teardown / in tests.
   */
  dispose(): void {
    // Stop receiving lock/logout signals.
    this.unsubscribe();
    // Drop all decrypted values from memory.
    this.byIdentity.clear();
  }
}
