---
name: credentials-sdk
description: How to use @tetrac/credentials-sdk — the universal, provider-agnostic API-credential store + decrypted-key session handler. Use when storing/reading/listing/removing any API credential (exchange API keys, OpenRouter key, Telegram bot token, RPC keys, or any future secret), wiring the manager at app boot, registering a new credential type, or debugging VaultLockedError / "credential is null" / session-cache behavior. Keywords: createCredentialManager, CredentialRef, CredentialSchema, registerCredentialSchema, getCredentials, setCredentials, hasCredentials, listProviders, VaultLockedError, sessionCacheable, custody, namespace, providerId, blob+index, WebCrypto AES-GCM.
---

# @tetrac/credentials-sdk — Usage Guide

A tiny, **zero-dependency** package that stores, encrypts, indexes, and session-caches
**API credentials** behind **one universal interface**. It is the single home for exchange
API keys, the OpenRouter key, the Telegram bot token, RPC keys, and any secret invented later.

Two hard rules define it:

1. **No provider/exchange names live in the SDK.** Credentials are addressed by arbitrary
   `(namespace, providerId)` strings. The roster of providers is **app-side data** — adding or
   removing a venue is a data change, never an SDK release. (A CI grep guard fails the build if
   any real provider name appears in `src/`.)
2. **Zero runtime deps, zero peer deps.** The host app **injects** the vault app key + lock
   signals. Encryption is platform WebCrypto **AES-256-GCM** (a global).

> **Scope:** this SDK holds only revocable, low-risk **API credentials**. It NEVER holds
> wallet/signing (fund-custody) keys — those stay in `@tetrac/login-sdk`. There is exactly one
> vault (the login-SDK vault); this SDK owns none.

---

## 1. Wire it once, at app boot

The SDK creates no vault. The project (which owns `@tetrac/login-sdk`) injects the vault's
existing accessors. Unlocking the login-SDK vault is what lets this SDK decrypt.

```ts
import { getAppKey, getPublicKey, subscribeLock } from "@tetrac/login-sdk/client";
import { createCredentialManager } from "@tetrac/credentials-sdk";

export const credentials = createCredentialManager({
  getAppKey,                 // () => string | null  — vault app key; null when locked/logged-out
  getIdentity: getPublicKey, // () => string | null  — scopes storage + session cache; null = logged out
  subscribeLock,             // (cb) => unsubscribe   — fires on lock/logout so the cache can wipe
  // storage,                // optional StorageLike; defaults to globalThis.localStorage
  // keyPrefix,              // optional storage-key prefix; defaults to "credmgr"
});
```

Construct it **exactly once** (a module singleton). Register the app's schemas right after
(see §3). In `next-ttc` this lives in `src/config/credentials.ts`.

---

## 2. Addressing — `(namespace, providerId)`

```ts
type CredentialRef = { namespace: string; providerId: string };
```

Both are opaque app-chosen strings. Conventional buckets:

| namespace  | providerId examples                    | notes                         |
| ---------- | -------------------------------------- | ----------------------------- |
| `exchange` | `binance`, `some-new-dex`, …           | ~40 venues, come and go       |
| `service`  | `openrouter`, `telegram`, `rpc`, …     | AI keys, bot token, RPC keys  |
| `<future>` | `<anything>`                           | new namespaces need no change |

These names are **data you pass in** — they must not appear in the SDK's own source.

---

## 3. Schemas are data — register at runtime (no SDK edit)

A schema declares a credential's field shape and policy. The app registers them; the SDK never
hardcodes field lists.

```ts
interface CredentialFieldSpec {
  key: string;        // "apiKey" | "apiSecret" | "passphrase" | "token" | "chatId" | …
  secret: boolean;    // true → encrypted blob;  false → plaintext index (badges/lists)
  required?: boolean; // set() rejects a set that omits it
}
interface CredentialSchema {
  ref: CredentialRef;
  fields: CredentialFieldSpec[];
  sessionCacheable?: boolean;  // opt into the in-memory session cache (§6). DEFAULT false.
  multi?: boolean;             // provider holds a LIST of value-sets (e.g. a key list)
  custody?: boolean;           // fund-custody: HARD-refused from caching, always (R-3)
}
```

Register one or many (idempotent; last-writer-wins per ref):

```ts
credentials.registerCredentialSchemas([
  // Single set with a secret/non-secret split. sessionCacheable → held in memory for the session.
  {
    ref: { namespace: "exchange", providerId: "binance" },
    fields: [
      { key: "apiKey",        secret: true,  required: true },
      { key: "apiSecret",     secret: true,  required: true },
      { key: "passphrase",    secret: true },
      { key: "walletAddress", secret: false }, // non-secret → renders while locked
    ],
    sessionCacheable: true,
  },
  // multi: a rotating list of key-sets (all-secret).
  {
    ref: { namespace: "service", providerId: "openrouter" },
    fields: [{ key: "apiKey", secret: true, required: true }],
    multi: true,
    sessionCacheable: true,
  },
  // Bot token (secret) + non-secret chat id.
  {
    ref: { namespace: "service", providerId: "telegram" },
    fields: [
      { key: "token",  secret: true,  required: true },
      { key: "chatId", secret: false },
    ],
    sessionCacheable: true,
  },
]);
```

> **Design note (project decision):** the SDK's internal `sessionCacheable` default is **false**
> ("never looser than the vault by default"). The owner wants all app credentials held in memory
> on demand, so the **app sets `sessionCacheable: true`** on each schema it registers.

---

## 4. The API surface — mind async vs sync

WebCrypto is async-only, so the crypto-touching methods return Promises. The index-only probes
are synchronous and need **no unlock**.

| Method                        | Sync/Async | Needs unlock? | What it does                                       |
| ----------------------------- | ---------- | ------------- | ------------------------------------------------- |
| `setCredentials(ref, values)` | **async**  | **yes**       | validate → encrypt secrets → write index          |
| `getCredentials(ref)`         | **async**  | yes (on miss) | decrypt (session-cached); throws when locked      |
| `removeCredentials(ref)`      | **async**  | **yes**       | drop one provider; re-encrypts the remaining blob |
| `hasCredentials(ref)`         | sync       | no            | index probe → boolean                             |
| `listProviders(namespace)`    | sync       | no            | configured providerIds from the index             |
| `getSummary(ref)`             | sync       | no            | `{ fields, updatedAt }` (no secret values) or null |
| `clearNamespace(namespace)`   | sync       | no            | nuke a whole bucket across all identities         |
| `dispose()`                   | sync       | —             | detach lock listener + wipe cache (teardown)      |

```ts
const ref = { namespace: "exchange", providerId: "binance" };

// WRITE — always await.
await credentials.setCredentials(ref, { apiKey: "ak", apiSecret: "as", walletAddress: "0x…" });

// READ — always await. Single schema → object; multi schema → non-empty array of sets, else null; unconfigured → null.
const creds = await credentials.getCredentials(ref); // { apiKey, apiSecret, walletAddress } | null

// multi read returns an array of sets:
const keys = await credentials.getCredentials({ namespace: "service", providerId: "openrouter" });
// → [{ apiKey: "k1" }, { apiKey: "k2" }] | null

// PROBES — no await, no unlock (render badges/lists while the vault is locked):
credentials.hasCredentials(ref);          // boolean
credentials.listProviders("exchange");    // string[]
credentials.getSummary(ref);              // { fields: string[]; updatedAt: number } | null

// DELETE one, or the whole bucket:
await credentials.removeCredentials(ref); // async (re-encrypts the rest)
credentials.clearNamespace("exchange");   // sync, explicit user action only
```

---

## 5. `VaultLockedError` is NOT `null` — the #1 gotcha

- `getCredentials` returns **`null`** → the credential is **unconfigured** (never set).
- `getCredentials` **throws `VaultLockedError`** → the vault is **locked, or no identity is present**
  (`getAppKey()` **or** `getIdentity()` is null) and the value isn't cached. This is a *different*
  state — the caller should trigger the app's unlock ceremony, not treat it as "not configured".

```ts
import { VaultLockedError } from "@tetrac/credentials-sdk";

try {
  const creds = await credentials.getCredentials(ref);
  if (creds === null) return notConfigured();   // genuinely absent
  useIt(creds);
} catch (e) {
  if (e instanceof VaultLockedError) return promptUnlock(); // locked ≠ unconfigured
  throw e;
}
```

Legacy read sites that used to swallow errors and return `null` for "not configured" **must**
keep locked distinct from unconfigured after migrating.

---

## 6. Session policy (the one B2 rule)

For schemas with `sessionCacheable: true` (and **not** `custody`):

- **Unlock once, cache per identity.** First `getCredentials` decrypts into an in-memory cache
  tagged by `getIdentity()`; later reads hit the cache — the user unlocks at most once.
- **Survive the idle auto-lock.** A lock that keeps the *same* identity does **not** clear the
  cache (the B2 relaxation for low-risk keys).
- **Wipe on logout / account-switch.** When the lock signal fires and `getIdentity()` is `null`
  (logout) the whole cache is wiped; a different identity (account switch) drops the old
  account's entries. Reads are always identity-scoped, so one account can never read another's.
- **Custody keys are never cached.** `custody: true` hard-excludes a schema from the cache even
  if `sessionCacheable` is true.

Non-cacheable schemas are **decrypt-per-read**: after an auto-lock, the next read throws
`VaultLockedError` until re-unlocked.

---

## 7. Integration contracts & sharp edges

- **`getIdentity()` must reflect the post-event state BEFORE `subscribeLock` fires.** The host
  vault must update identity (→ `null` on logout, → new id on switch) *before* broadcasting the
  lock signal. If it fires first, a switched-away account's decrypted values linger in memory
  until the next signal (never cross-account *readable*, but not promptly dropped). `@tetrac/login-sdk`
  already satisfies this (it clears/sets the public key before `notify()`). **Wire `getIdentity` to
  the login-SDK `getPublicKey`** — the identity that goes `null` on logout — **never to `isLocked()`
  / `getAppKey()`**, or an idle auto-lock would masquerade as a logout and wipe the cache the B2
  policy is meant to preserve.
- **Returned values are deep clones.** `getCredentials` hands back a copy. Mutating it does **not**
  change the cache or storage — to persist an edit, call `setCredentials` again with the new set.
- **`clearNamespace` wins over in-flight writes and reads.** A "clear all" that lands while a
  `set`/`remove`/`get` for the same namespace is parked on its crypto `await` aborts that operation:
  it persists/returns nothing and does not re-warm the cache, so just-cleared secrets are never
  resurrected in storage or the session cache. `clearNamespace` itself stays synchronous.
- **`namespace`/`providerId` must not contain ASCII control characters.** `registerCredentialSchema`
  throws `CredentialSchemaError` if they do (keeps key derivation unambiguous). Ordinary ids
  (alphanumerics, `-`, `_`, even `:`) are fine.
- **`multi` schemas: a count in the index; an empty list means unconfigured.** `hasCredentials` /
  `listProviders` answer while locked; `getSummary` names a multi provider's fields only if its schema
  is registered in this manager instance. **Setting a `multi` schema to `[]` clears that provider** —
  `has()=false`, `get()=null`, `listProviders` omits it, `getSummary()=null` (an empty key-list is
  treated as unconfigured, never a stored `[]`).
- **The sync probes are identity-scoped.** `hasCredentials` / `listProviders` / `getSummary` read the
  plaintext index while the vault is **locked** (app key null, identity still present) — but return
  `false` / `[]` / `null` once **logged out** (`getIdentity()` is null), since there's no per-user
  index to read. "Works while locked" ≠ "works while logged out".
- **Uniform async error handling.** Every error from the async methods (`set`/`get`/`remove`) —
  unregistered ref, locked vault, missing identity, validation — surfaces as a **promise rejection**,
  never a synchronous throw, so both `try { await … } catch` and `.catch()` work. Only the
  **synchronous** methods throw synchronously: `registerCredentialSchema` (malformed/duplicate-field
  schema, control chars in a ref) and construction-time storage errors.
- **Storage default is `localStorage`.** Inject a `StorageLike` for tests or non-DOM hosts (§9).
- **Crypto format is AES-256-GCM with a versioned, domain-separated KDF.** The key is
  `SHA-256("tetrac-credentials-sdk:aes-256-gcm:v1:" + appKey)`. Bumping that prefix intentionally
  invalidates every earlier blob — both legacy `crypto-es` blobs and any written by the previous
  *unversioned* KDF. No migration path — a one-time re-entry of dev keys is expected at cutover.

---

## 8. Errors

| Error                       | Thrown when                                                        |
| --------------------------- | ----------------------------------------------------------------- |
| `VaultLockedError`          | `get` while `getAppKey()`/`getIdentity()` is null **and** no cache hit; `set`/`remove` while either is null (writes never consult the cache) |
| `CredentialSchemaError`     | `get`/`set` on an **unregistered** ref (`remove` and the sync probes don't require a schema); malformed/duplicate-field schema; control chars in a ref |
| `CredentialValidationError` | missing required field; unknown field; wrong arity (array vs object) for the schema |

All three are exported from the package root.

---

## 9. Testing pattern (standalone, no DOM)

Inject an in-memory `StorageLike` and a mock vault:

```ts
import { createCredentialManager, type StorageLike } from "@tetrac/credentials-sdk";

function memoryStorage(): StorageLike {
  const m = new Map<string, string>();
  return {
    getItem: (k) => (m.has(k) ? m.get(k)! : null),
    setItem: (k, v) => void m.set(k, v),
    removeItem: (k) => void m.delete(k),
    key: (i) => [...m.keys()][i] ?? null,
    get length() { return m.size; },
  };
}

let appKey: string | null = "test-key";
let identity: string | null = "user-1";
const listeners = new Set<() => void>();

const mgr = createCredentialManager({
  getAppKey: () => appKey,
  getIdentity: () => identity,
  subscribeLock: (cb) => { listeners.add(cb); return () => listeners.delete(cb); },
  storage: memoryStorage(),
});

// Simulate an auto-lock:  appKey = null; listeners.forEach((cb) => cb());   // identity unchanged → cache survives
// Simulate a logout:      appKey = null; identity = null; listeners.forEach((cb) => cb()); // cache wiped
// Always mgr.dispose() in teardown to detach the listener.
```

---

## 10. Do / Don't

**Do**
- `await` every `set`/`get`/`remove`.
- Treat `VaultLockedError` and `null` as different outcomes.
- Register all schemas once at boot from the app-side manifest.
- Use the sync probes (`has`/`list`/`getSummary`) to render while locked.
- Add a new credential type by **registering a schema** — nothing in the SDK changes.

**Don't**
- Don't put a real provider name (`"binance"`, `"openrouter"`, …) anywhere in the SDK's `src/` —
  the grep guard fails the build. Names belong in **app** schema data only.
- Don't store wallet/signing (fund-custody) keys here — that's `@tetrac/login-sdk`.
- Don't cache `getAppKey()`/`getIdentity()` results — read them through the injected accessors.
- Don't rely on mutating a returned object to persist — call `setCredentials`.
- Don't mark a custody key `sessionCacheable` and expect it to cache — custody always wins.
