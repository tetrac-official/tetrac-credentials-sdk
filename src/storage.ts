// Persistence layout for @tetrac/credentials-sdk.
// Generalises the exchange store's existing "one AES blob + one plaintext index"
// (PRD §3, §5.3) to any namespace. Both are scoped by the current identity so
// different accounts never collide. The index is plaintext ON PURPOSE: it powers
// has/list/summary WITHOUT unlocking the vault.
import type { StorageLike } from "./types.js";

/**
 * The plaintext index entry for one provider. Holds everything renderable while the
 * vault is locked: the non-secret field values, the NAMES of the secret fields
 * present (never their values), and a timestamp. `count` is set for `multi` schemas.
 */
export interface IndexEntry {
  /** Non-secret field values, stored in clear for badges/lists (e.g. walletAddress). */
  publicFields: Record<string, string>;
  /** Names of the secret fields whose values live in the encrypted blob (single schemas). */
  secretKeys: string[];
  /** Milliseconds-epoch of the last write. */
  updatedAt: number;
  /** For `multi` schemas: how many value-sets are stored (drives hasCredentials). */
  count?: number;
}

/** The whole plaintext index for a namespace: providerId → entry. */
export type NamespaceIndex = Record<string, IndexEntry>;

/**
 * The decrypted secret blob for a namespace: providerId → secret values (single) or
 * an array of full value-sets (multi). This is what gets AES-GCM encrypted at rest.
 */
export type SecretBlob = Record<
  string,
  Record<string, string> | Record<string, string>[]
>;

/**
 * Resolve the storage backend: an explicitly injected one, else `globalThis.localStorage`.
 * Throws if neither exists (e.g. a non-DOM host that forgot to inject storage).
 */
export function resolveStorage(injected: StorageLike | undefined): StorageLike {
  // Prefer whatever the app injected (tests inject an in-memory stub).
  if (injected) return injected;
  // Fall back to the browser's localStorage if present.
  const ls = (globalThis as { localStorage?: StorageLike }).localStorage;
  if (ls) return ls;
  // Nothing to persist to — fail loudly at construction time.
  throw new Error(
    "No storage available: inject `storage` or run where localStorage exists.",
  );
}

/**
 * Encode one storage-key segment so a `:` (or any other character) inside an app-chosen
 * namespace or identity can never be confused with the `:` that delimits the key's own
 * fields. `encodeURIComponent` percent-escapes `:` (→ `%3A`) and every non-`[A-Za-z0-9-_.!~*'()]`
 * byte, making each segment unambiguous, so e.g. namespace "a:b" can't collide with "a".
 * Ordinary identifiers (alphanumerics, `-`, `_`) pass through unchanged — the on-disk
 * layout is byte-identical to before for all realistic inputs. (Hardening: R-audit F-4.)
 */
function seg(value: string): string {
  return encodeURIComponent(value);
}

/**
 * Storage key for a namespace's ENCRYPTED secret blob, scoped to an identity.
 * Shape: `${prefix}:${enc(namespace)}:secrets:${enc(identity)}`.
 */
export function secretsKey(
  prefix: string,
  namespace: string,
  identity: string,
): string {
  return `${prefix}:${seg(namespace)}:secrets:${seg(identity)}`;
}

/**
 * Storage key for a namespace's PLAINTEXT index, scoped to an identity.
 * Shape: `${prefix}:${enc(namespace)}:index:${enc(identity)}`.
 */
export function indexKey(
  prefix: string,
  namespace: string,
  identity: string,
): string {
  return `${prefix}:${seg(namespace)}:index:${seg(identity)}`;
}

/**
 * The AAD string that binds a secret blob to its slot (passed to AES-GCM). Any blob
 * moved to a different namespace/identity slot will fail authentication on decrypt.
 */
export function secretsAad(
  prefix: string,
  namespace: string,
  identity: string,
): string {
  return secretsKey(prefix, namespace, identity);
}

/**
 * A stored index entry is trusted only if it has the exact shape `writeIndex` produces:
 * a `publicFields` object, a `secretKeys` array, a numeric `updatedAt`, and (for `multi`)
 * an optional numeric `count`. The plaintext index is unauthenticated and app-writable
 * (adversary: an at-rest storage tamperer) AND it backs the LOCK-FREE probes
 * (`has`/`list`/`summary`). So a malformed-but-object entry — `42`, `null`, `[]`, or one
 * missing `publicFields`/`secretKeys` — must be dropped rather than trusted: otherwise
 * `getSummary` throws a `TypeError` (`Object.keys(undefined)` / spreading a non-iterable
 * `secretKeys`) and `has`/`list` report a garbage provider as present. Dropping keeps every
 * probe fail-safe and mutually consistent — a corrupt entry reads as "absent", exactly like
 * a corrupt whole index. (R-audit F-11.)
 */
function isValidEntry(value: unknown): value is IndexEntry {
  // Must be a plain (non-null, non-array) object.
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const entry = value as Record<string, unknown>;
  // publicFields must itself be a plain object (we spread it into the merged output).
  const publicFields = entry.publicFields;
  if (
    typeof publicFields !== "object" ||
    publicFields === null ||
    Array.isArray(publicFields)
  )
    return false;
  // secretKeys must be an array (getSummary spreads it).
  if (!Array.isArray(entry.secretKeys)) return false;
  // updatedAt must be a number; count, when present, must be a NON-NEGATIVE INTEGER.
  // The write path only ever emits count>=1 (empty multi → the provider is deleted, not
  // stored with count 0). Admitting a negative / NaN / Infinity / fractional count here would
  // let an at-rest tamperer split the lock-free probes: has/list gate on `count>0` (absent for
  // -1/NaN) while getSummary historically gated on `count===0` (present for -1/NaN). Requiring a
  // clean non-negative integer at the storage gate keeps the three probes provably in agreement.
  if (typeof entry.updatedAt !== "number") return false;
  const count = entry.count;
  if (
    count !== undefined &&
    (typeof count !== "number" || !Number.isInteger(count) || count < 0)
  )
    return false;
  return true;
}

/**
 * A fresh, PROTOTYPE-LESS index object. Every readIndex return path uses this (not a `{}` literal)
 * so a lookup by a providerId that happens to equal an Object.prototype member name ("toString",
 * "valueOf", "constructor", "hasOwnProperty", …) resolves to `undefined` — never an inherited
 * function. Without this the lock-free probes fail OPEN on an ABSENT/CORRUPT index:
 * `hasCredentials({providerId:"toString"})` would read `Object.prototype.toString` and report a
 * phantom credential as present, and `getSummary`/`getCredentials` would throw a `TypeError`
 * (`Object.keys(<function>.publicFields)`) instead of reporting "unconfigured". (R-audit F-11 read-path.)
 */
function emptyIndex(): NamespaceIndex {
  return Object.create(null) as NamespaceIndex;
}

/**
 * Read + parse a namespace's plaintext index. Returns an empty index if absent or
 * corrupt (corrupt-index is treated as "nothing configured", never a throw). Individual
 * entries that fail {@link isValidEntry} are dropped so the lock-free probes stay fail-safe
 * against a tampered/corrupt entry (F-11).
 */
export function readIndex(
  storage: StorageLike,
  prefix: string,
  namespace: string,
  identity: string,
): NamespaceIndex {
  // Look up the raw JSON string.
  const raw = storage.getItem(indexKey(prefix, namespace, identity));
  // No entry → empty index (null-proto, so a "toString"-style providerId can't alias a prototype member).
  if (!raw) return emptyIndex();
  try {
    // Parse the stored JSON into an index object.
    const parsed = JSON.parse(raw) as unknown;
    // Only a plain (non-array) object is a usable index; anything else → nothing configured.
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return emptyIndex();
    // Copy through a NULL-PROTOTYPE object so a literal "__proto__"/"constructor" key produced by
    // JSON.parse can never reach Object.prototype during the copy (the `clean[key] = …` write below
    // would otherwise hit the __proto__ setter), and keep only well-formed entries so a tampered or
    // corrupt entry can't crash or mislead the lock-free probes. (F-11.)
    const clean = emptyIndex();
    for (const key of Object.keys(parsed as Record<string, unknown>)) {
      const entry = (parsed as Record<string, unknown>)[key];
      if (isValidEntry(entry)) clean[key] = entry;
    }
    return clean;
  } catch {
    // Malformed JSON → treat as unconfigured rather than crashing a render path.
    return emptyIndex();
  }
}

/**
 * Serialise + write a namespace's plaintext index. Removes the key entirely when the
 * index is empty so we never leave a stray `{}` behind.
 */
export function writeIndex(
  storage: StorageLike,
  prefix: string,
  namespace: string,
  identity: string,
  index: NamespaceIndex,
): void {
  // Compute the index storage key once.
  const key = indexKey(prefix, namespace, identity);
  // An empty index means "nothing configured" — delete the key instead of writing "{}".
  if (Object.keys(index).length === 0) {
    storage.removeItem(key);
    return;
  }
  // Otherwise persist the index as JSON.
  storage.setItem(key, JSON.stringify(index));
}

/**
 * Read the RAW (still-encrypted) secret blob string for a namespace, or null if absent.
 * Decryption happens in the manager (it owns the app key); storage stays crypto-free.
 */
export function readSecretsRaw(
  storage: StorageLike,
  prefix: string,
  namespace: string,
  identity: string,
): string | null {
  return storage.getItem(secretsKey(prefix, namespace, identity));
}

/**
 * Write the RAW (already-encrypted) secret blob string for a namespace.
 */
export function writeSecretsRaw(
  storage: StorageLike,
  prefix: string,
  namespace: string,
  identity: string,
  ciphertext: string,
): void {
  storage.setItem(secretsKey(prefix, namespace, identity), ciphertext);
}

/**
 * Delete a namespace's secret blob for one identity (used when it becomes empty).
 */
export function removeSecrets(
  storage: StorageLike,
  prefix: string,
  namespace: string,
  identity: string,
): void {
  storage.removeItem(secretsKey(prefix, namespace, identity));
}

/**
 * Enumerate every storage key belonging to a namespace across ALL identities. Used by
 * `clearNamespace`, the explicit "nuke this bucket" action. Matches both the secrets
 * and index keys via the `${prefix}:${namespace}:` prefix.
 */
export function namespaceKeys(
  storage: StorageLike,
  prefix: string,
  namespace: string,
): string[] {
  // The shared prefix for every key in this namespace, any identity. The namespace is
  // encoded exactly as the key builders encode it, so a `:` in a hierarchical namespace
  // (e.g. "a:b") can't make clearNamespace("a") over-match its siblings (R-audit F-4).
  const match = `${prefix}:${seg(namespace)}:`;
  // Collect matching keys first (mutating storage while iterating indices is unsafe).
  const keys: string[] = [];
  // Walk the storage index space.
  for (let i = 0; i < storage.length; i += 1) {
    // Read the key name at position i.
    const key = storage.key(i);
    // Keep it if it lives under this namespace.
    if (key && key.startsWith(match)) keys.push(key);
  }
  // Return the collected keys for the caller to remove.
  return keys;
}
