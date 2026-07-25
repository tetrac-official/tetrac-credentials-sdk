// Public and internal type definitions for @tetrac/credentials-sdk.
// This module is types-only plus the SDK's error classes. It contains ZERO
// provider/exchange names — that is the whole point of the SDK (PRD §5.1, R-4).

/**
 * A credential is addressed by an opaque (namespace, providerId) pair.
 * Neither field is ever interpreted by the SDK: ("exchange","<venue>"),
 * ("service","<provider>"), ("<future-namespace>","<anything>") and every other
 * combination are equally meaningless strings here. The roster of providers is
 * data owned by the host app, never code in this package.
 */
export interface CredentialRef {
  /** Logical bucket, e.g. "exchange" or "service" — an arbitrary app-chosen string. */
  namespace: string;
  /** Provider identity within the namespace — an arbitrary app-chosen string. */
  providerId: string;
}

/**
 * One field in a credential set. The app registers these at runtime; the SDK
 * only cares whether each value is `secret` (encrypted) or not (plaintext index).
 */
export interface CredentialFieldSpec {
  /** Field name, e.g. "apiKey" | "apiSecret" | "passphrase" | "token" | "chatId". Opaque to the SDK. */
  key: string;
  /** true → value goes into the encrypted body; false → value goes into the plaintext index (badges/lists). */
  secret: boolean;
  /** When true, `setCredentials` rejects a set that omits this field. Defaults to false. */
  required?: boolean;
}

/**
 * The runtime-registered shape of a credential. Schemas are DATA: the app hands
 * them in via `registerCredentialSchema(s)`; adding a new credential type never
 * requires an SDK edit (PRD §5.2).
 */
export interface CredentialSchema {
  /** Which (namespace, providerId) this schema describes. */
  ref: CredentialRef;
  /** The field specs for this credential set. */
  fields: CredentialFieldSpec[];
  /**
   * Opt in to the in-memory session cache (PRD §6). Defaults to false so the SDK
   * is "never looser than the vault by default" — the app widens exposure explicitly.
   */
  sessionCacheable?: boolean;
  /** When true this provider holds a LIST of value-sets (e.g. a rotating key list). */
  multi?: boolean;
  /**
   * Fund-custody hard-exclusion (R-3). When true the session handler REFUSES to
   * cache this credential regardless of `sessionCacheable` — custody always wins.
   */
  custody?: boolean;
}

/** A single set of credential values (field name → value). Every value is opaque bytes to the SDK. */
export type CredentialValues = Record<string, string>;

/** Accepted input to `setCredentials`: one set, or a list of sets for `multi` schemas. */
export type CredentialInput = CredentialValues | CredentialValues[];

/** Result of `getCredentials`: one set, a list of sets (multi), or null when unconfigured. */
export type CredentialOutput = CredentialValues | CredentialValues[] | null;

/** Non-secret metadata about a stored credential, readable WITHOUT unlocking the vault. */
export interface CredentialSummary {
  /** Names of the fields present in the stored set (secret names + non-secret keys). */
  fields: string[];
  /** Milliseconds-epoch of the last write. */
  updatedAt: number;
}

/**
 * The minimal persistence surface the SDK needs. Defaults to `globalThis.localStorage`
 * in the browser; tests (and any non-DOM host) inject their own implementation.
 * This mirrors the Web Storage API so a real `localStorage` satisfies it as-is.
 */
export interface StorageLike {
  /** Read a stored string value, or null if absent. */
  getItem(key: string): string | null;
  /** Write a string value under `key`. */
  setItem(key: string, value: string): void;
  /** Delete the value at `key`. */
  removeItem(key: string): void;
  /** Return the storage key at `index`, or null if out of range (used to enumerate for clearNamespace). */
  key(index: number): string | null;
  /** Number of stored keys. */
  readonly length: number;
}

/**
 * Everything the host app injects at construction. The SDK owns NONE of these —
 * it holds no vault, no app key, and no dependency on @tetrac/login-sdk (PRD §4).
 */
export interface CredentialManagerConfig {
  /** Returns the login-SDK vault app key, or null when the vault is locked/logged out. */
  getAppKey: () => string | null;
  /** Returns the current account identity (e.g. a public key); null when logged out. Scopes storage + cache. */
  getIdentity: () => string | null;
  /** Subscribes to lock/logout events; returns an unsubscribe fn. Fires so the cache can wipe on logout. */
  subscribeLock: (callback: () => void) => () => void;
  /** Persistence backend. Defaults to `globalThis.localStorage`. */
  storage?: StorageLike;
  /** Storage-key namespace prefix. Defaults to "credmgr". */
  keyPrefix?: string;
}

/** The public manager surface returned by `createCredentialManager`. */
export interface CredentialManager {
  /** Register one schema (idempotent; last-writer-wins per ref). */
  registerCredentialSchema(schema: CredentialSchema): void;
  /** Register many schemas at once (e.g. from an app-side manifest). */
  registerCredentialSchemas(schemas: CredentialSchema[]): void;
  /** Encrypt secrets + write non-secrets to the index. Async (WebCrypto); requires an unlocked vault. */
  setCredentials(ref: CredentialRef, values: CredentialInput): Promise<void>;
  /** Decrypt (session-cached per §6). Async (WebCrypto); throws VaultLockedError when locked. */
  getCredentials(ref: CredentialRef): Promise<CredentialOutput>;
  /** Index probe — NO unlock required. Sync. */
  hasCredentials(ref: CredentialRef): boolean;
  /** List configured providerIds in a namespace from the plaintext index — NO unlock required. Sync. */
  listProviders(namespace: string): string[];
  /** Non-secret summary from the index — NO unlock required. Sync. */
  getSummary(ref: CredentialRef): CredentialSummary | null;
  /** Delete one provider's secrets + index entry. Async (must re-encrypt the remaining blob); requires unlock. */
  removeCredentials(ref: CredentialRef): Promise<void>;
  /** Nuke an entire namespace across all identities (explicit user action only). Sync (no crypto). */
  clearNamespace(namespace: string): void;
  /** Unsubscribe the lock listener and wipe the in-memory cache (cleanup / teardown). */
  dispose(): void;
}

/**
 * Thrown by `getCredentials`/`setCredentials`/`removeCredentials` when the vault is
 * locked (injected `getAppKey()` returned null). Deliberately DISTINCT from a null
 * "unconfigured" result so read sites never confuse "locked" with "not set" (R-1).
 */
export class VaultLockedError extends Error {
  constructor(message = "Vault is locked: unlock the vault before reading or writing credentials.") {
    super(message);
    // Fixed name so callers can `err.name === "VaultLockedError"` across bundle boundaries.
    this.name = "VaultLockedError";
    // Restore the prototype chain (TS/ES class-extending-Error caveat) so `instanceof` works.
    Object.setPrototypeOf(this, VaultLockedError.prototype);
  }
}

/** Thrown when an operation references a ref with no registered schema. */
export class CredentialSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialSchemaError";
    Object.setPrototypeOf(this, CredentialSchemaError.prototype);
  }
}

/** Thrown when input values violate the registered schema (missing required field, unknown key, wrong arity). */
export class CredentialValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialValidationError";
    Object.setPrototypeOf(this, CredentialValidationError.prototype);
  }
}
