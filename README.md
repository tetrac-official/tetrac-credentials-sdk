# @tetrac/credentials-sdk

A tiny, provider-agnostic **API-credential store** and **decrypted-key session handler**.
It stores, encrypts, indexes, and session-caches API credentials — exchange API keys, an
OpenRouter-style key, a Telegram-style bot token, RPC keys, and any secret invented later —
behind **one universal interface**.

Two hard constraints:

1. **No provider/exchange names live in the SDK.** Credentials are addressed by arbitrary
   `(namespace, providerId)` strings, so venues come and go with **no SDK release**.
2. **Zero runtime dependencies, zero peer dependencies.** The host app injects the vault app
   key + lock signals; encryption uses the platform WebCrypto **AES-256-GCM** (a global).

> This SDK holds only revocable, low-risk **API credentials**. It never holds wallet/signing
> (fund-custody) keys — those stay in `@tetrac/login-sdk`.

## Install

```bash
npm install @tetrac/credentials-sdk
```

## Wire it once, at app boot

The SDK owns no vault. The project (which already owns `@tetrac/login-sdk`) injects the
vault's existing accessors — unlocking the login-SDK vault is what unlocks this SDK.

```ts
import { getAppKey, getPublicKey, subscribeLock } from "@tetrac/login-sdk/client";
import { createCredentialManager } from "@tetrac/credentials-sdk";

export const credentials = createCredentialManager({
  getAppKey,                 // () => string | null   — vault app key (null when locked)
  getIdentity: getPublicKey, // () => string | null   — scopes storage + session cache
  subscribeLock,             // (cb) => unsubscribe    — fires on lock/logout so the cache can wipe
  // storage,                // optional StorageLike; defaults to globalThis.localStorage
});
```

## Register schemas (schemas are data, not SDK code)

```ts
credentials.registerCredentialSchemas([
  {
    ref: { namespace: "exchange", providerId: "some-venue" },
    fields: [
      { key: "apiKey", secret: true, required: true },
      { key: "apiSecret", secret: true, required: true },
      { key: "passphrase", secret: true },
      { key: "walletAddress", secret: false }, // non-secret → plaintext index (badges/lists)
    ],
    sessionCacheable: true, // hold decrypted in memory for the session (B2)
  },
  {
    ref: { namespace: "service", providerId: "some-ai" },
    fields: [{ key: "apiKey", secret: true, required: true }],
    multi: true,            // a LIST of key sets
    sessionCacheable: true,
  },
]);
```

## Use it

```ts
// Encrypt secrets, write non-secrets to the plaintext index. Async (WebCrypto).
await credentials.setCredentials({ namespace: "exchange", providerId: "some-venue" }, {
  apiKey: "…", apiSecret: "…", walletAddress: "0x…",
});

// Decrypt (session-cached). Throws VaultLockedError if the vault is locked.
const creds = await credentials.getCredentials({ namespace: "exchange", providerId: "some-venue" });

// Index probes — NO unlock required (render badges/lists while locked):
credentials.hasCredentials({ namespace: "exchange", providerId: "some-venue" }); // boolean
credentials.listProviders("exchange");                                            // string[]
credentials.getSummary({ namespace: "exchange", providerId: "some-venue" });      // { fields, updatedAt } | null

// Delete one provider (re-encrypts the rest — async). Or nuke a whole namespace (sync).
await credentials.removeCredentials({ namespace: "exchange", providerId: "some-venue" });
credentials.clearNamespace("exchange");
```

## `VaultLockedError` is distinct from `null`

- `getCredentials` returns `null` when a credential is **unconfigured**.
- `getCredentials` **throws `VaultLockedError`** when the vault is **locked** (app key null).

Read sites must treat "locked" ≠ "unconfigured".

## The session policy (one place)

Cacheable schemas (`sessionCacheable: true`, non-custody) follow the PRD-7 **B2** rule:

- **Unlock once** — first `getCredentials` decrypts into an in-memory cache tagged by identity;
  later reads hit the cache.
- **Survive the idle auto-lock** — a lock that keeps the same identity does not clear the cache.
- **Wipe on logout / account-switch** — identity → null (or changed) clears it.
- **Custody keys are never cached** — `custody: true` hard-excludes a schema from the cache.

## Sync vs async

`getCredentials` / `setCredentials` / `removeCredentials` are **async** (WebCrypto is async-only).
`hasCredentials` / `listProviders` / `getSummary` / `clearNamespace` are **sync** — they only
touch the plaintext index / delete keys, so they need no unlock.

## Scripts

```bash
npm run build      # ESM + CJS + .d.ts (tsup)
npm run typecheck  # tsc --noEmit
npm test           # vitest run
npm run guard      # the "no provider literals" CI grep guard
```
