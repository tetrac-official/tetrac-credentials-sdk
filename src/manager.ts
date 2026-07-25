// The credentials manager for @tetrac/credentials-sdk (PRD §5).
// Owns the schema registry, the blob+index storage layout, and the crypto-touching
// read/write path. Delegates the decrypted-value lifetime to the SessionCache (§6).
//
// Async vs sync (necessary deviation from the PRD's illustrative sync signatures):
// WebCrypto is async-only, so the two crypto-touching methods — getCredentials and
// setCredentials, plus removeCredentials which re-encrypts the remaining blob — return
// Promises. The index-only probes (hasCredentials/listProviders/getSummary) and
// clearNamespace stay SYNCHRONOUS: they never touch crypto, so they need no unlock.
import { decryptString, encryptString } from "./crypto.js";
import { SessionCache } from "./session.js";
import {
  indexKey,
  namespaceKeys,
  readIndex,
  readSecretsRaw,
  removeSecrets,
  resolveStorage,
  secretsAad,
  secretsKey,
  writeIndex,
  writeSecretsRaw,
  type IndexEntry,
  type NamespaceIndex,
  type SecretBlob,
} from "./storage.js";
import {
  CredentialSchemaError,
  CredentialValidationError,
  VaultLockedError,
  type CredentialInput,
  type CredentialManager,
  type CredentialManagerConfig,
  type CredentialOutput,
  type CredentialRef,
  type CredentialSchema,
  type CredentialSummary,
  type CredentialValues,
  type StorageLike,
} from "./types.js";

// Default storage-key prefix; overridable via config.keyPrefix.
const DEFAULT_PREFIX = "credmgr";

/**
 * Build the schema-registry map key for a ref. JSON-encoding a two-string tuple is
 * INJECTIVE — the escaping guarantees ("a b","c") and ("a","b c") map to distinct keys —
 * so no choice of namespace/providerId can collide two different schemas onto one entry
 * (which would silently mis-route a secret field into the plaintext index). (R-audit F-3.)
 */
function schemaMapKey(ref: CredentialRef): string {
  return JSON.stringify([ref.namespace, ref.providerId]);
}

/**
 * Object keys that, used as a namespace / providerId / field name, would collide with a plain
 * object's prototype machinery. `blob[providerId]`, `index[providerId]`, and `secretFields[key]`
 * are all writes to plain objects; assigning to `"__proto__"` (an object value) mutates the
 * object's prototype instead of storing an own property, so the credential is silently DROPPED on
 * write. These strings never occur in legitimate identifiers; rejecting them at registration keeps
 * the plain-object stores well-defined. (R-audit F-13.)
 */
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Reject a namespace/providerId carrying an ASCII control character (NUL / C0 range or the
 * DEL 0x7F), or one equal to a reserved object key. Control bytes never occur in a legitimate
 * identifier; forbidding them keeps every downstream key derivation (schema map, session cache,
 * storage keys) provably unambiguous rather than merely relying on a delimiter byte happening to
 * be absent (R-audit F-1/F-2). Reserved keys are rejected so the plain-object blob/index stores
 * can't silently swallow a credential written under a prototype-colliding key (F-13).
 */
function assertSafeSegment(kind: string, value: string): void {
  // eslint-disable-next-line no-control-regex -- control chars are exactly what we screen out.
  if (/[\x00-\x1f\x7f]/.test(value)) {
    throw new CredentialSchemaError(
      `Schema ${kind} must not contain control characters.`,
    );
  }
  if (RESERVED_KEYS.has(value)) {
    throw new CredentialSchemaError(
      `Schema ${kind} must not be a reserved object key ("${value}").`,
    );
  }
}

/**
 * A schema is cacheable only if it opted in AND is not fund-custody. Custody always
 * wins over sessionCacheable so a custody key can never be held in memory (R-3).
 */
function isCacheable(schema: CredentialSchema): boolean {
  return schema.sessionCacheable === true && schema.custody !== true;
}

/**
 * Validate one value-set against its schema: reject unknown fields and missing required
 * fields. Values themselves are never interpreted — only presence/shape is checked.
 */
function validateSet(schema: CredentialSchema, set: CredentialValues): void {
  // The set of field names this schema allows.
  const allowed = new Set(schema.fields.map((f) => f.key));
  // Reject any provided key the schema doesn't declare (catches typos / stray data).
  for (const key of Object.keys(set)) {
    if (!allowed.has(key)) {
      throw new CredentialValidationError(
        `Unknown field "${key}" for ${schema.ref.namespace}/${schema.ref.providerId}.`,
      );
    }
  }
  // Every required field must be present and non-empty.
  for (const field of schema.fields) {
    if (field.required) {
      // Read the provided value for this required field.
      const value = set[field.key];
      // Absent, null, or empty-string all count as "missing".
      if (value === undefined || value === null || value === "") {
        throw new CredentialValidationError(
          `Missing required field "${field.key}" for ${schema.ref.namespace}/${schema.ref.providerId}.`,
        );
      }
    }
  }
}

/**
 * Split a validated single set into its plaintext (index) and secret (blob) halves,
 * per the schema's `secret` flags. Omitted optional fields are simply dropped.
 */
function splitSet(
  schema: CredentialSchema,
  set: CredentialValues,
): {
  publicFields: Record<string, string>;
  secretFields: Record<string, string>;
} {
  // Non-secret values destined for the plaintext index.
  const publicFields: Record<string, string> = {};
  // Secret values destined for the encrypted blob.
  const secretFields: Record<string, string> = {};
  // Route each declared field by its secret flag.
  for (const field of schema.fields) {
    // The provided value for this field (may be absent for optional fields).
    const value = set[field.key];
    // Skip fields the caller didn't provide.
    if (value === undefined) continue;
    // Secret → blob; non-secret → index.
    if (field.secret) secretFields[field.key] = value;
    else publicFields[field.key] = value;
  }
  // Hand back both halves.
  return { publicFields, secretFields };
}

/**
 * Construct the credential manager. The app injects the vault accessors (§4); the SDK
 * holds no key of its own. Returns the public {@link CredentialManager} surface.
 */
export function createCredentialManager(
  config: CredentialManagerConfig,
): CredentialManager {
  // Reads the vault app key (null when locked). Injected — never owned here.
  const getAppKey = config.getAppKey;
  // Reads the current account identity (null when logged out). Scopes storage + cache.
  const getIdentity = config.getIdentity;
  // Storage backend: injected, or the browser's localStorage.
  const storage: StorageLike = resolveStorage(config.storage);
  // Storage-key prefix (defaulted).
  const prefix = config.keyPrefix ?? DEFAULT_PREFIX;
  // The one decrypted-value cache implementing the B2 session policy (§6).
  const cache = new SessionCache(getIdentity, config.subscribeLock);
  // Runtime schema registry: refKey → schema.
  const schemas = new Map<string, CredentialSchema>();
  // Per-namespace write serialization tail, so concurrent set/remove don't clobber the blob.
  const writeTails = new Map<string, Promise<void>>();
  // Per-namespace monotonic "clear epoch". `clearNamespace` (synchronous, not lock-serialized)
  // bumps it; an in-flight set/remove captures it up front and refuses to commit if it changed,
  // so a "clear all" landing during a save's crypto await can't resurrect just-cleared secrets.
  const clearEpochs = new Map<string, number>();
  // Read the current clear epoch for a namespace (0 if never cleared).
  const clearEpoch = (ns: string): number => clearEpochs.get(ns) ?? 0;
  // Per-namespace monotonic "write generation": bumped after every COMMITTED set/remove. A
  // getCredentials snapshots it before its decrypt await and refuses to warm the cache if it
  // changed — so a read that decrypted a now-superseded ciphertext can't clobber the fresher value
  // a concurrent write just cached (read-after-write staleness). Unlike clearEpoch this NEVER aborts
  // a write; it only gates the racing READER's own cache write, so concurrent writes are unaffected.
  const writeGens = new Map<string, number>();
  const writeGen = (ns: string): number => writeGens.get(ns) ?? 0;
  const bumpWriteGen = (ns: string): void =>
    void writeGens.set(ns, writeGen(ns) + 1);

  /**
   * Serialize a mutating operation per namespace (read-modify-write on one shared blob).
   */
  function withNamespaceLock<T>(
    namespace: string,
    task: () => Promise<T>,
  ): Promise<T> {
    // The previous operation on this namespace (or an already-resolved promise).
    const prev = writeTails.get(namespace) ?? Promise.resolve();
    // Chain our task after it, running regardless of whether prev resolved or rejected.
    const run = prev.then(task, task);
    // Record a settled-only tail so the next caller waits for us without inheriting errors.
    writeTails.set(
      namespace,
      run.then(
        () => undefined,
        () => undefined,
      ),
    );
    // Give the caller the real (typed, error-propagating) result.
    return run;
  }

  /**
   * Look up a registered schema, or throw — every set/get needs a schema.
   */
  function requireSchema(ref: CredentialRef): CredentialSchema {
    // Fetch by registry key.
    const schema = schemas.get(schemaMapKey(ref));
    // No schema → the app forgot to register this credential type.
    if (!schema) {
      throw new CredentialSchemaError(
        `No schema registered for ${ref.namespace}/${ref.providerId}. Call registerCredentialSchema first.`,
      );
    }
    // Found.
    return schema;
  }

  /**
   * Assert the vault is unlocked and return the app key, else throw VaultLockedError.
   */
  function requireAppKey(): string {
    // Read the injected app key.
    const appKey = getAppKey();
    // Null means locked/logged-out — surface the distinct locked state (R-1).
    if (appKey === null) throw new VaultLockedError();
    // Unlocked.
    return appKey;
  }

  /**
   * Assert we have an identity to scope storage/cache to, else treat as locked.
   */
  function requireIdentity(): string {
    // Read the injected identity.
    const identity = getIdentity();
    // No identity → nothing to scope to; behave as locked rather than writing global blobs.
    if (identity === null)
      throw new VaultLockedError(
        "No identity: log in before accessing credentials.",
      );
    // Present.
    return identity;
  }

  /**
   * Read + decrypt a namespace's secret blob for an identity. Empty object if absent.
   */
  async function readBlob(
    appKey: string,
    namespace: string,
    identity: string,
  ): Promise<SecretBlob> {
    // Fetch the raw ciphertext.
    const raw = readSecretsRaw(storage, prefix, namespace, identity);
    // Nothing stored yet → empty blob.
    if (!raw) return {};
    // Decrypt under the app key, AAD-bound to this exact slot.
    const json = await decryptString(
      appKey,
      raw,
      secretsAad(prefix, namespace, identity),
    );
    // Parse the recovered JSON.
    const parsed = JSON.parse(json) as unknown;
    // Guard the shape before trusting it as a blob.
    return parsed && typeof parsed === "object" ? (parsed as SecretBlob) : {};
  }

  /**
   * Encrypt a namespace's secret blob into its storable ciphertext, or `null` when the blob is
   * empty (nothing to persist). This is the ONLY crypto await on the write path; splitting it
   * from the synchronous {@link commitBlob} lets a caller run its final commit await-free — so a
   * synchronous `clearNamespace` can't interleave between the encrypt and the store (F-audit).
   */
  async function encryptBlob(
    appKey: string,
    namespace: string,
    identity: string,
    blob: SecretBlob,
  ): Promise<string | null> {
    // An empty blob means "no secrets left" — signal deletion rather than encrypting "{}".
    if (Object.keys(blob).length === 0) return null;
    // Serialize + encrypt the blob, AAD-bound to this slot.
    return encryptString(
      appKey,
      JSON.stringify(blob),
      secretsAad(prefix, namespace, identity),
    );
  }

  /**
   * Synchronously persist an already-encrypted blob (or delete the key when `cipher` is null).
   * Await-free by design: callers invoke it only after the last await, inside a clear-epoch guard.
   */
  function commitBlob(
    namespace: string,
    identity: string,
    cipher: string | null,
  ): void {
    if (cipher === null) removeSecrets(storage, prefix, namespace, identity);
    else writeSecretsRaw(storage, prefix, namespace, identity, cipher);
  }

  // ---- Public surface -------------------------------------------------------

  /**
   * Register one schema (idempotent; last-writer-wins per ref).
   */
  function registerCredentialSchema(schema: CredentialSchema): void {
    // Basic structural validation — a malformed schema is a programming error.
    if (!schema.ref || !schema.ref.namespace || !schema.ref.providerId) {
      throw new CredentialSchemaError(
        "Schema.ref must have a non-empty namespace and providerId.",
      );
    }
    // Screen out control characters so every downstream key derivation stays unambiguous.
    assertSafeSegment("namespace", schema.ref.namespace);
    assertSafeSegment("providerId", schema.ref.providerId);
    // A schema with no fields can hold nothing.
    if (!Array.isArray(schema.fields) || schema.fields.length === 0) {
      throw new CredentialSchemaError(
        `Schema ${schema.ref.namespace}/${schema.ref.providerId} must declare at least one field.`,
      );
    }
    // Reject duplicate field keys (ambiguous secret/non-secret routing otherwise) and any field
    // key equal to a reserved object key (would silently drop the value when written to the blob /
    // index plain objects — see RESERVED_KEYS / F-13).
    const seen = new Set<string>();
    for (const field of schema.fields) {
      if (RESERVED_KEYS.has(field.key)) {
        throw new CredentialSchemaError(
          `Schema field key must not be a reserved object key ("${field.key}") in schema ${schema.ref.namespace}/${schema.ref.providerId}.`,
        );
      }
      if (seen.has(field.key)) {
        throw new CredentialSchemaError(
          `Duplicate field "${field.key}" in schema ${schema.ref.namespace}/${schema.ref.providerId}.`,
        );
      }
      seen.add(field.key);
    }
    // Store (or replace) the schema under its ref key.
    schemas.set(schemaMapKey(schema.ref), schema);
  }

  /**
   * Register many schemas at once (e.g. from an app-side manifest).
   */
  function registerCredentialSchemas(list: CredentialSchema[]): void {
    // Delegate to the single-schema path for each entry.
    for (const schema of list) registerCredentialSchema(schema);
  }

  /**
   * Encrypt secrets + write non-secrets to the index. Requires an unlocked vault.
   */
  function setCredentials(
    ref: CredentialRef,
    values: CredentialInput,
  ): Promise<void> {
    // Snapshot the clear epoch NOW, synchronously at call time — before this write is even queued.
    // If a clearNamespace bumps it before we commit, we abort so the clear wins (no resurrection).
    const startEpoch = clearEpoch(ref.namespace);
    // Bind this write to the account + app key active NOW (synchronously), not to whatever the vault
    // holds when the microtask-deferred task body finally runs. withNamespaceLock defers the task, so
    // an account switch (or key rotation) between this call and the task would otherwise redirect the
    // write to a DIFFERENT account's storage slot, or encrypt it under the wrong key. The null-checks
    // stay INSIDE the task so a locked/logged-out vault surfaces as a promise REJECTION, never a
    // synchronous throw (uniform async error handling).
    const callIdentity = getIdentity();
    const callAppKey = getAppKey();
    // Serialize the whole read-modify-write against this namespace's blob. EVERY error path —
    // including the unregistered-schema check — lives INSIDE the returned promise, so all failures
    // surface as promise REJECTIONS, never a synchronous throw (uniform async error handling).
    return withNamespaceLock(ref.namespace, async () => {
      // Resolve the schema (rejects if unregistered).
      const schema = requireSchema(ref);
      // Enforce the unlocked-vault + identity contract on the CALL-TIME snapshot (async rejection).
      if (callAppKey === null) throw new VaultLockedError();
      if (callIdentity === null)
        throw new VaultLockedError(
          "No identity: log in before accessing credentials.",
        );
      const appKey = callAppKey;
      const identity = callIdentity;
      // Load the existing decrypted blob (to preserve OTHER providers in this namespace).
      const blob = await readBlob(appKey, namespace(ref), identity);
      // Load the existing plaintext index.
      const index = readIndex(storage, prefix, namespace(ref), identity);
      // The value we'll cache after a successful write (canonical merged view).
      let cacheValue: CredentialOutput;

      if (schema.multi) {
        // A multi schema stores a LIST of full value-sets.
        if (!Array.isArray(values)) {
          throw new CredentialValidationError(
            `${ref.namespace}/${ref.providerId} is a multi schema; setCredentials expects an array of sets.`,
          );
        }
        // Validate every set in the list.
        for (const set of values) validateSet(schema, set);
        if (values.length === 0) {
          // An empty list means "no keys" — clear the provider entirely so every probe agrees
          // (hasCredentials=false, getCredentials=null, listProviders omits it). (R-audit F-6.)
          delete blob[ref.providerId];
          delete index[ref.providerId];
          // Nothing present → don't cache; the tail below drops any stale entry.
          cacheValue = null;
        } else {
          // Store all sets (full field bodies) in the encrypted blob.
          blob[ref.providerId] = values;
          // Index tracks only count + timestamp for multi (no per-set plaintext rendering).
          index[ref.providerId] = {
            publicFields: {},
            secretKeys: [],
            updatedAt: Date.now(),
            count: values.length,
          };
          // Cache the array as-is.
          cacheValue = values;
        }
      } else {
        // A single schema stores exactly one value-set.
        if (Array.isArray(values)) {
          throw new CredentialValidationError(
            `${ref.namespace}/${ref.providerId} is a single schema; setCredentials expects one set, not an array.`,
          );
        }
        // Validate the set.
        validateSet(schema, values);
        // Split into plaintext (index) and secret (blob) halves.
        const { publicFields, secretFields } = splitSet(schema, values);
        // Secret half → blob under this provider.
        blob[ref.providerId] = secretFields;
        // Non-secret half + secret field NAMES → index (names only, never secret values).
        index[ref.providerId] = {
          publicFields,
          secretKeys: Object.keys(secretFields),
          updatedAt: Date.now(),
        };
        // Cache the merged view (what getCredentials would return).
        cacheValue = { ...publicFields, ...secretFields };
      }

      // Encrypt first (the last await), THEN commit synchronously below.
      const cipher = await encryptBlob(appKey, namespace(ref), identity, blob);
      // A clearNamespace(ns) that ran during any of our awaits must win — don't resurrect it.
      // From here down there is NO await, so this guard + the stores are atomic vs the sync clear.
      if (clearEpoch(ref.namespace) !== startEpoch) {
        cache.invalidate(ref);
        return;
      }
      // Persist the re-encrypted blob and the updated index.
      commitBlob(namespace(ref), identity, cipher);
      writeIndex(storage, prefix, namespace(ref), identity, index);
      // Signal the committed write so any getCredentials currently parked on a decrypt await for
      // this namespace won't re-warm the cache with the value it read BEFORE this commit.
      bumpWriteGen(ref.namespace);

      // Update the session cache: warm it for a present, cacheable credential; otherwise drop any
      // stale entry (non-cacheable schema, or an empty multi cleared above → cacheValue null).
      // Guard on identity: if an account switch landed during our crypto awaits, getIdentity() now
      // names a DIFFERENT account and cache.write would file THIS account's plaintext under it — a
      // cross-identity leak. The storage commit above is still correct (it used the captured
      // `identity`); we simply refuse to cache under the wrong account.
      if (
        isCacheable(schema) &&
        cacheValue !== null &&
        getIdentity() === identity
      )
        cache.write(ref, cacheValue);
      else cache.invalidate(ref);
    });
  }

  /**
   * Decrypt (session-cached per §6). Throws VaultLockedError when locked.
   */
  async function getCredentials(ref: CredentialRef): Promise<CredentialOutput> {
    // Resolve the schema (throws if unregistered).
    const schema = requireSchema(ref);
    // Cacheable schemas: a cache hit means we never touch crypto/storage (unlock once).
    if (isCacheable(schema)) {
      const cached = cache.read(ref);
      // Return the cached decrypted value on a hit.
      if (cached !== undefined) return cached;
    }
    // Cache miss (or non-cacheable): require an unlocked vault + identity.
    const appKey = requireAppKey();
    const identity = requireIdentity();
    // Snapshot the clear epoch AND the write generation BEFORE the decrypt await: a clearNamespace
    // landing mid-read must not re-warm the cache for a wiped namespace (F-10), and a concurrent
    // set/remove that COMMITS mid-read must not have its fresh cache entry clobbered by the value we
    // read before it committed (read-after-write staleness).
    const startEpoch = clearEpoch(ref.namespace);
    const startGen = writeGen(ref.namespace);
    // Read the plaintext index for this namespace.
    const index = readIndex(storage, prefix, namespace(ref), identity);
    // The index entry for this provider (undefined → unconfigured).
    const entry = index[ref.providerId];
    // Distinct from "locked": genuinely not configured → null.
    if (!entry) return null;
    // Decrypt the namespace blob and pull out this provider's secret part.
    const blob = await readBlob(appKey, namespace(ref), identity);
    // A clearNamespace ran during the decrypt await → the namespace is gone; honor the clear:
    // don't warm the cache, and report unconfigured rather than a resurrected secret.
    if (clearEpoch(ref.namespace) !== startEpoch) return null;
    // An account switch landed during the decrypt await → this decrypted value belongs to the
    // PREVIOUS identity. Returning or caching it now would hand one account's secret to another
    // (the switch's lock signal already wiped the previous identity's cache submap). Report
    // unconfigured for the new account rather than leaking.
    if (getIdentity() !== identity) return null;
    const secretPart = blob[ref.providerId];

    // Assemble the output shape per single vs multi.
    let output: CredentialOutput;
    if (schema.multi) {
      // Multi: the data IS the array of sets in the blob. An absent OR empty list reads back as
      // null so has()/get() agree (F-6) — a defensive mirror of the clear-on-empty set path.
      output =
        Array.isArray(secretPart) && secretPart.length > 0 ? secretPart : null;
    } else {
      // Single: merge plaintext (index) with decrypted secrets (blob). Defense-in-depth (F-12):
      // a schema-declared SECRET field must only ever be sourced from the AUTHENTICATED blob, never
      // from the unauthenticated, app-writable plaintext index. The legit write path never routes a
      // secret field into the index, so this filter is a no-op for untampered data — it strips only
      // a secret-named key that an at-rest tamperer planted in the index to forge that field's value
      // (e.g. an optional secret the blob doesn't hold). Non-secret index fields are unaffected.
      const secretDeclared = new Set(
        schema.fields.filter((f) => f.secret).map((f) => f.key),
      );
      const publicOnly: Record<string, string> = {};
      for (const [key, value] of Object.entries(entry.publicFields)) {
        if (!secretDeclared.has(key)) publicOnly[key] = value;
      }
      // Decrypted secret half (authenticated); spread LAST so it always wins over any index value.
      const secrets =
        secretPart && !Array.isArray(secretPart) ? secretPart : {};
      output = { ...publicOnly, ...secrets };
    }

    // Warm the cache for cacheable schemas so subsequent reads survive the auto-lock — but ONLY if
    // no set/remove committed for this namespace during our decrypt await. If one did, our decrypted
    // `output` may reflect the pre-write ciphertext; caching it would overwrite the fresher value the
    // writer already cached. Skip the warm (the next read re-decrypts) rather than persist staleness.
    if (
      output !== null &&
      isCacheable(schema) &&
      writeGen(ref.namespace) === startGen
    )
      cache.write(ref, output);
    // Hand back the decrypted view.
    return output;
  }

  /**
   * Index probe — NO unlock required. True when a set is configured for this ref.
   */
  function hasCredentials(ref: CredentialRef): boolean {
    // Without an identity there's no per-user index to probe.
    const identity = getIdentity();
    if (identity === null) return false;
    // Read the plaintext index and look up this provider.
    const entry = readIndex(storage, prefix, ref.namespace, identity)[
      ref.providerId
    ];
    // Present, and (for multi) holding at least one set.
    return !!entry && (entry.count === undefined || entry.count > 0);
  }

  /**
   * List configured providerIds in a namespace from the plaintext index — NO unlock.
   */
  function listProviders(ns: string): string[] {
    // Without an identity there's nothing scoped to list.
    const identity = getIdentity();
    if (identity === null) return [];
    // The index keys ARE the configured providerIds — but skip any empty (count:0) multi entry so
    // list() shares hasCredentials()'s "present" definition (a defensive guard against a legacy or
    // tampered count:0 entry the current code never writes). (R-audit F-6 hardening.)
    const index = readIndex(storage, prefix, ns, identity);
    return Object.keys(index).filter((pid) => {
      const count = index[pid]?.count;
      return count === undefined || count > 0;
    });
  }

  /**
   * Non-secret summary from the index — NO unlock required.
   */
  function getSummary(ref: CredentialRef): CredentialSummary | null {
    // Without an identity there's no summary to give.
    const identity = getIdentity();
    if (identity === null) return null;
    // Look up the index entry.
    const entry = readIndex(storage, prefix, ref.namespace, identity)[
      ref.providerId
    ];
    // Not configured, or a non-positive-count multi entry → null, matching has()/list()'s `count>0`
    // presence test. getSummary previously gated only on `count===0`, so it disagreed with has/list
    // for a tampered negative/NaN count; isValidEntry now drops those at the storage gate, and this
    // predicate keeps summary in lock-step for any legacy count that slips through. (F-6 hardening.)
    if (!entry || (entry.count !== undefined && !(entry.count > 0)))
      return null;
    // The registered schema (if any) lets us name multi fields; single derives from the entry.
    const schema = schemas.get(schemaMapKey(ref));
    // Field names present: multi uses the schema's declared keys; single uses index data.
    const fields = schema?.multi
      ? schema.fields.map((f) => f.key)
      : [...Object.keys(entry.publicFields), ...entry.secretKeys];
    // Return names + last-write timestamp (no secret values ever).
    return { fields, updatedAt: entry.updatedAt };
  }

  /**
   * Delete one provider's secrets + index entry. Re-encrypts the remaining blob, so it
   * requires an unlocked vault.
   */
  function removeCredentials(ref: CredentialRef): Promise<void> {
    // Snapshot the clear epoch synchronously (see setCredentials) so a mid-flight clear wins.
    const startEpoch = clearEpoch(ref.namespace);
    // Bind the removal to the CALL-TIME account + key (see setCredentials): the deferred task must
    // rewrite THIS account's blob under THIS account's key, even if a switch lands before it runs.
    const callIdentity = getIdentity();
    const callAppKey = getAppKey();
    // Serialize against other writes to this namespace's blob.
    return withNamespaceLock(ref.namespace, async () => {
      // Enforce the unlocked-vault + identity contract on the CALL-TIME snapshot (async rejection).
      if (callAppKey === null) throw new VaultLockedError();
      if (callIdentity === null)
        throw new VaultLockedError(
          "No identity: log in before accessing credentials.",
        );
      const appKey = callAppKey;
      const identity = callIdentity;
      // Load the current index.
      const index = readIndex(storage, prefix, namespace(ref), identity);
      // Load + decrypt the current blob.
      const blob = await readBlob(appKey, namespace(ref), identity);
      // Drop this provider from both structures.
      delete index[ref.providerId];
      delete blob[ref.providerId];
      // Encrypt first (last await), then commit await-free under the clear-epoch guard.
      const cipher = await encryptBlob(appKey, namespace(ref), identity, blob);
      if (clearEpoch(ref.namespace) !== startEpoch) {
        cache.invalidate(ref);
        return;
      }
      // Persist the (possibly now-empty) blob and index.
      commitBlob(namespace(ref), identity, cipher);
      writeIndex(storage, prefix, namespace(ref), identity, index);
      // Signal the committed write so a getCredentials parked on a decrypt await for this namespace
      // won't re-warm the cache with the value it read before this removal.
      bumpWriteGen(ref.namespace);
      // Evict any cached decrypted copy.
      cache.invalidate(ref);
    });
  }

  /**
   * Nuke an entire namespace across ALL identities (explicit user action only). No crypto.
   */
  function clearNamespace(ns: string): void {
    // Bump the clear epoch FIRST so any set/remove currently parked on a crypto await will see
    // the change when it resumes and refuse to re-persist this namespace (no resurrection).
    clearEpochs.set(ns, clearEpoch(ns) + 1);
    // Enumerate + remove every storage key under this namespace (all identities).
    for (const key of namespaceKeys(storage, prefix, ns))
      storage.removeItem(key);
    // Drop the namespace's cached decrypted values too.
    cache.invalidateNamespace(ns);
  }

  /**
   * Unsubscribe the lock listener and wipe the in-memory cache.
   */
  function dispose(): void {
    // Tear down the session cache (detaches the lock listener, clears memory).
    cache.dispose();
  }

  // Assemble and return the public manager object.
  return {
    registerCredentialSchema,
    registerCredentialSchemas,
    setCredentials,
    getCredentials,
    hasCredentials,
    listProviders,
    getSummary,
    removeCredentials,
    clearNamespace,
    dispose,
  };
}

/**
 * Tiny helper to read a ref's namespace (keeps the call sites terse + readable).
 */
function namespace(ref: CredentialRef): string {
  return ref.namespace;
}

// Re-export the storage-internal types some callers may want to reference in tests.
export type { IndexEntry, NamespaceIndex, SecretBlob };
// Re-export the storage key builders so tests can assert the on-disk layout.
export { indexKey, secretsKey };
