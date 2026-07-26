# Security Audit — `@tetrac/credentials-sdk` v0.1.0

**Engagement:** RedHat Team adversarial review (red-team + hardening)
**Target:** `@tetrac/credentials-sdk` @ `0.1.0`
**Date:** 2026-07-24
**Reviewer:** RedHat Team (automated + manual)
**Scope:** `src/` (crypto, storage, session, manager, types), the public API surface, and the on-disk / in-memory data model. Injected host dependencies (`@tetrac/login-sdk` vault: `getAppKey` / `getIdentity` / `subscribeLock`) are **out of scope** except where the SDK's guarantees depend on their contract (see F-7).

---

## 1. Executive summary

The SDK is a small, provider-agnostic credential store that encrypts secrets at rest with **WebCrypto AES-256-GCM**, keeps a plaintext index for lock-free `has/list/summary`, and session-caches decrypted values per identity. The core cryptographic design is sound: authenticated encryption, a random 96-bit IV per message, AAD that binds each ciphertext to its `(namespace, identity)` slot, a non-extractable `CryptoKey`, and zero runtime dependencies.

The review found **no exploitable break of the encryption itself.** It did find **two correctness/integrity defects reachable with ordinary inputs** (F-4 data loss, F-5 cache poisoning) and a **class of key-derivation ambiguities** (F-1/F-2/F-3) that were safe only because the internal delimiter happened to be a `NUL` byte — a fragile invariant that rested on an *incorrect* code comment. All five have been **fixed and covered by regression tests**. Three lower-severity items are documented with accepted rationale or deferred to v0.2.

> **Update — hardening pass 2 (2026-07-24):** the two items originally deferred to v0.2 (F-6, F-9)
> were also applied at the owner's request, along with the CI-guard extensions. An impact-discovery
> sweep across the consumer repos confirms **no edits are required outside this repo** (see §7.5).
> A follow-up **multi-agent adversarial verification** of those changes then surfaced one further
> real defect — **F-10** (a `clearNamespace` concurrency race) — now fixed on both the write path
> and (after a second re-verification caught the read path too) `getCredentials` (see §3).
>
> **Update — hardening pass 3 (2026-07-25):** an independent re-audit focused on the **at-rest
> tamperer** (adversary #1) and ordinary storage corruption surfaced three further items, now all
> fixed and regression-tested: **F-11** (a real fail-safe bug — a malformed index *entry* made
> `getSummary` throw a `TypeError` and `has`/`list` mis-report a garbage provider as present, because
> `readIndex` validated only the top-level object), **F-12** (defense-in-depth — a schema-declared
> *secret* field could be sourced from the unauthenticated plaintext index; it is now sourced only
> from the AEAD blob), and **F-13** (robustness — reserved object keys `__proto__`/`constructor`/
> `prototype` were accepted as a namespace/providerId/field key and would silently drop the
> credential on write; now rejected at registration). Test suite **107 → 132**; each fix carries a
> negative-control-verified regression test.
>
> **Update — hardening pass 4 → shipped in v0.1.1 (2026-07-25):** a further multi-agent adversarial
> re-review (per-module review → independent skeptic verification) surfaced five more issues, all now
> fixed in **v0.1.1**: (1) **readIndex fail-OPEN on an absent/corrupt index** — the null-prototype
> guard from F-11 was only applied on the populated path, so a prototype-named `providerId`
> (`"toString"`/`"valueOf"`/…) fell through to an inherited member, making `has()` report a phantom
> credential and `getSummary`/`getCredentials` throw a `TypeError` (reachable with ordinary input, no
> tampering); (2) **cross-identity cache leak** — a `set`/`get` whose account switched mid-crypto-await
> filed (or returned) the previous account's plaintext under the new identity; writes are now bound to
> the call-time account+key and cache writes are identity-guarded; (3) **read-after-write staleness** —
> a `get` racing a committed `set` could re-warm the cache with the pre-write value (per-namespace
> write-generation guard added); (4) **BOM data-loss** — `decryptString` stripped a leading U+FEFF
> (`ignoreBOM`); (5) **count-validation divergence** — `isValidEntry` admitted a negative/NaN `count`
> and `getSummary` disagreed with `has`/`list`. Test suite **132 → 162** (13 regression +
> negative-control-verified where reproducible, 11 coverage-gap, 6 StorageLike-conformance); typecheck
> clean; build + no-provider-literal guard green. **v0.1.1 fixes these issues and is ready to go.**

**Verdict:** With all hardening applied and the pass-4 fixes shipped, **v0.1.1 is approved** for its intended use (revocable, low-risk API credentials — never fund-custody keys). Test suite: **162/162 passing** (was 24), typecheck clean, no-provider-literal guard green (scans `dist/` too, with a silent-no-op guard), zero control bytes in `src/`.

| Severity | Count | Fixed | Documented (no code change) |
|----------|-------|-------|-----------------------------|
| High     | 0     | —     | —                           |
| Medium   | 3     | 3 (F-4, F-5, F-10) | —              |
| Low      | 6     | 6 (F-1, F-2, F-3, F-6, F-11, F-12) | —  |
| Info     | 4     | 2 (F-9, F-13) | 2 (F-7 verified-satisfied, F-8 accepted) |

> This table tallies the original F-1..F-13 findings. The **pass-4 re-review** later surfaced five
> more (incl. two High-severity: the readIndex fail-open and the cross-identity cache leak) — all
> fixed and shipped in **v0.1.1**; see the pass-4 note above.

---

## 2. Threat model

Assets: the **secret credential values** (API keys/secrets/tokens) held encrypted in `localStorage` and, transiently, decrypted in the in-memory session cache.

Adversaries considered:

1. **At-rest attacker** — can read/copy/tamper with `localStorage` (shared machine, backup exfiltration, or an XSS write). Must not recover plaintext secrets or forge accepted ciphertext.
2. **Cross-account / cross-slot attacker** — a second local account (identity B) trying to read identity A's secrets, or a blob relocated between storage slots.
3. **Careless / hostile caller** — application code that mutates returned objects, registers ambiguous schemas, or supplies unusual `namespace`/`providerId` strings (the SDK's headline promise is that these are *arbitrary app-chosen strings*).
4. **Locked-vault reader** — code hitting the index probes while the vault is locked; must never obtain a decrypted secret and must distinguish "locked" from "unconfigured".

Explicitly **not** defended (documented, by design): a live attacker with script execution in the page during an unlocked session (they can call the API directly); the impossibility of zeroing plaintext strings in a JS heap (F-8).

---

## 3. Findings

### F-4 — `clearNamespace` over-deletes sibling namespaces (`:` delimiter collision) · **Medium · FIXED**

**Location:** `src/storage.ts` (`secretsKey`, `indexKey`, `namespaceKeys`).

On-disk keys were built as `` `${prefix}:${namespace}:secrets:${identity}` `` with a bare `:` delimiter, while `namespace` is an arbitrary app string. `clearNamespace(ns)` deletes every key with prefix `` `${prefix}:${ns}:` ``. A **hierarchical namespace** (e.g. `exchange:spot` alongside `exchange`) — a completely realistic choice — collides: clearing `exchange` also silently destroys `exchange:spot`.

**Proof (pre-fix):**
```
clearNamespace('a')  →  outer('a').has = false   inner('a:b').has = false   ← sibling wrongly nuked
```

**Impact:** Silent, irrecoverable **data loss** of a sibling namespace's credentials; latent potential for slot aliasing when a `namespace`/`identity` contains `:`.

**Fix:** Every key segment is now percent-encoded (`encodeURIComponent`) before assembly, so `:` (→ `%3A`) can never be confused with the structural delimiter. Ordinary identifiers (alphanumerics, `-`, `_`) encode to themselves, so the on-disk layout is **byte-identical for all realistic inputs** — no migration needed. `namespaceKeys` matches on the encoded prefix. AAD (derived from `secretsKey`) stays consistent across encrypt/decrypt.

**Regression tests:** `hardening — storage-key delimiter (F-4)` (2 tests).

---

### F-5 — Session cache hands out live references (caller mutation poisons the cache) · **Medium · FIXED**

**Location:** `src/session.ts` (`SessionCache.read`/`write`), `src/manager.ts` (`getCredentials`).

`getCredentials` returned the *same object* it stored in the cache. A caller doing `const c = await getCredentials(ref); c.apiKey = "…"` rewrote the cached value in place; every subsequent reader in the session then received the mutated credential.

**Proof (pre-fix):**
```
first  = get(ref)            → { apiKey: "REAL" }
first.apiKey = "TAMPERED"
second = get(ref)            → { apiKey: "TAMPERED" }   ← cache poisoned
```

**Impact:** Integrity break — a decrypted credential could be corrupted (or an attacker-influenced value planted) for the rest of the session, and used against a live venue/API. Also affected the multi-list shape (a pushed element persisted).

**Fix:** The cache now **deep-clones on the way in and on the way out** (`structuredClone`, a zero-dependency platform global). The stored copy and every returned copy are fully independent; mutating either can no longer reach the other. Applies to single sets, multi lists, and the input object handed to `setCredentials`.

**Regression tests:** `hardening — session-cache reference hygiene (F-5)` (3 tests).

---

### F-10 — `clearNamespace` race resurrects just-cleared secrets · **Medium · FIXED**

**Location:** `src/manager.ts` (`clearNamespace`, `setCredentials`, `removeCredentials`).

*Surfaced by the multi-agent adversarial verification of pass 2, not the initial review.* `clearNamespace` is **synchronous** and — unlike `setCredentials`/`removeCredentials` — was **not** serialized through `withNamespaceLock`. A mutator reads + decrypts the blob, then yields the event loop on its crypto `await` (`readBlob` decrypt, `writeBlob` encrypt). If a user's "clear all" action fires during that window, `clearNamespace` deletes the namespace's keys and cache; the mutator then **resumes and re-persists** the blob + index (and re-warms the cache) — **resurrecting secrets the user just deleted**. In a browser this is reachable because `SubtleCrypto` genuinely resolves on a later tick, letting a concurrent click handler run in between.

**Impact:** A lost-delete / durability defect that is security-relevant: credentials the user believed were wiped silently return to storage **and** the in-memory session cache. Low-to-moderate likelihood (requires the bulk-clear to overlap an in-flight save), real consequence.

**Fix (keeps `clearNamespace` synchronous — honoring the owner's sync-API decision):** a per-namespace monotonic **clear epoch**. `clearNamespace` bumps `clearEpochs[ns]` *before* deleting. Every crypto-touching path snapshots the epoch **synchronously at call time** and re-checks it after its decrypt/encrypt `await`, before touching storage or the cache:

- **`setCredentials` / `removeCredentials`** do their single crypto `await` (`encryptBlob`), then run an **await-free commit** guarded by `if (clearEpoch(ns) !== startEpoch) { cache.invalidate(ref); return; }`. Because the guard and the `commitBlob`+`writeIndex`+cache updates are now contiguous synchronous code, a clear can never interleave between the check and the store. (Splitting `writeBlob` into async `encryptBlob` + sync `commitBlob` is what makes the commit await-free; as a side benefit the blob and index stores are now adjacent, narrowing the two-key write window.)
- **`getCredentials`** (added after the adversarial re-verification flagged it) snapshots the epoch before its `readBlob` decrypt `await` and, on resume, returns `null` **without warming the cache** if the epoch changed — so a clear that races an in-flight *read* can no longer resurrect the secret into the session cache or hand it back.

The clear always wins; the racing write/read aborts instead of resurrecting.

**Regression tests:** `hardening — clearNamespace concurrency` (3 tests: set-race, remove-race, no-false-abort), `hardening — clearNamespace vs in-flight getCredentials` (1 test: cold-cache read-race), and `hardening — probe agreement on a stray count:0 entry` (1 test — `listProviders`/`getSummary` now share `hasCredentials`'s "present" definition, so a legacy/tampered `count:0` index entry can't make the probes disagree).

---

### F-11 — Malformed index *entry* crashes `getSummary` / mis-reports probes · **Low · FIXED**

**Location:** `src/storage.ts` (`readIndex`); observed in `src/manager.ts` (`getSummary`, `hasCredentials`, `listProviders`).

*Surfaced by the pass-3 re-audit.* `readIndex` validated only that the **top-level** parsed value was an object; it trusted each per-provider **entry** verbatim. The plaintext index is unauthenticated and app-writable (adversary #1 can tamper it; ordinary corruption can mangle it), and it backs the **lock-free** probes. A well-formed index object whose *entry* is malformed — `{"p":42}`, `{"p":null}`, `{"p":[…]}`, `{"p":{}}` (missing `publicFields`), or an entry missing `secretKeys` — reached the probes and broke them:

**Proof (pre-fix):**
```
index = {"venue-x":{"publicFields":{},"updatedAt":1}}   // missing secretKeys
getSummary(ref)  →  TypeError: entry.secretKeys is not iterable   ← throws in a lock-free render path
index = {"venue-x":42}
getSummary(ref)  →  TypeError: Cannot convert undefined to object (Object.keys(entry.publicFields))
hasCredentials(ref) → true    listProviders(ns) → ["venue-x"]     ← garbage reported as present
```

**Impact:** A fail-safe violation. `getSummary` throws (a `TypeError` can crash a badge/list render or be a minor DoS while the vault is *locked*), and `has`/`list`/`get` disagree — some report a corrupt entry as a present credential. Contradicts the audit's stated "probes report nothing, never throw" invariant. Reachable by the at-rest tamperer and by plain storage corruption; no secret disclosure.

**Fix:** `readIndex` now validates **each entry's shape** (`publicFields` object, `secretKeys` array, numeric `updatedAt`, optional numeric `count`) and **drops** any that fail, copying survivors through a **null-prototype** accumulator (so a literal `"__proto__"` key from `JSON.parse` can't reach `Object.prototype` during the copy, and — with F-13 — a reserved-key entry is written as a safe own property). A corrupt entry now reads as "absent" — every probe agrees, none throws — exactly like a corrupt whole index. Arrays at the top level are also treated as unconfigured.

**Regression tests:** `hardening — probe fail-safe on a malformed index ENTRY (F-11)` (11 tests: 9 malformed shapes × all-probes-agree-absent-and-never-throw, plus valid-sibling-survives and valid-entry-not-dropped).

---

### F-12 — A secret field could be sourced from the unauthenticated index · **Low · FIXED (defense-in-depth)**

**Location:** `src/manager.ts` (`getCredentials`, single-schema merge).

*Surfaced by the pass-3 re-audit.* The single-schema read merged `{ ...entry.publicFields, ...secrets }`. `secrets` (from the AEAD blob) is spread last, so it **overrides** any same-named index key — a populated secret is safe. But a schema-declared **secret** field that is **absent** from the blob (e.g. an unset optional secret) has no `secrets` entry to override an index-planted value, so an at-rest tamperer who writes that secret's name into the plaintext `publicFields` could **forge that field's value** in the object the app consumes.

**Proof (pre-fix):**
```
schema: apiKey(secret,req), passphrase(secret,optional), walletAddress(public)
set { apiKey:"real", walletAddress:"0xpub" }          // passphrase never set → not in blob
tamper index.publicFields.passphrase = "ATTACKER"
get(ref) → { apiKey:"real", walletAddress:"0xpub", passphrase:"ATTACKER" }   ← forged secret field
```

**Impact:** Integrity — the app could act on a "secret" value that never came through authenticated encryption. Never a *disclosure* of the victim's real secret; scoped to fields the blob doesn't hold. Rated Low (requires at-rest write access; the plaintext index was always tamperable for *non-secret* data by design).

**Fix:** `getCredentials` now strips every schema-declared **secret** key from the index half before the merge, so a secret field can **only** ever be sourced from the authenticated blob. The legit write path never routes a secret into the index, so this is a **no-op for untampered data**; non-secret index fields are unaffected.

**Regression tests:** `hardening — secret fields only ever come from the authenticated blob (F-12)` (3 tests: planted-optional-secret-not-returned, planted-value-for-populated-secret-loses-to-blob, non-secret-fields-still-flow).

---

### F-13 — Reserved object keys accepted as identifiers (silent data loss) · **Info · FIXED**

**Location:** `src/manager.ts` (`assertSafeSegment`, `registerCredentialSchema`).

*Surfaced by the pass-3 re-audit.* `blob[providerId]`, `index[providerId]`, and `secretFields[fieldKey]` are writes to **plain objects**. A `providerId` of `"__proto__"` makes `blob["__proto__"] = {…}` mutate the blob's *prototype* instead of adding an own property; `encryptBlob` then sees `Object.keys(blob).length === 0` and stores **nothing** — the credential is silently dropped (no persistence, no error). `constructor`/`prototype` are the same class of hazard. This is self-inflicted (an app choosing a pathological identifier), not a live pollution of `Object.prototype`, hence Info.

**Fix:** `registerCredentialSchema` now rejects `__proto__`/`constructor`/`prototype` as a `namespace`, `providerId`, or field `key` (exact match) via `CredentialSchemaError` — a natural companion to the existing control-character rejection. Combined with F-11's null-prototype `readIndex` copy, the plain-object stores are well-defined for every accepted identifier.

**Regression tests:** `hardening — reserved object keys rejected at registration (F-13)` (11 tests: 3 reserved keys × {namespace, providerId, field key}, no-Object.prototype-pollution, and exact-match-not-substring so `proto`/`constructorX`/`prototypeKey` still round-trip).

---

### F-1 — Cache-key delimiter collision (theoretical) · **Low · FIXED (defense-in-depth)**
### F-2 — Account-switch prefix-keep leaves stale decrypted secrets · **Low · FIXED (defense-in-depth)**
### F-3 — Schema-registry key collision mis-routes a secret to plaintext · **Low · FIXED (defense-in-depth)**

**Location:** `src/session.ts` (flat `${identity}${SEP}${ns}${SEP}${pid}` cache key + `onLockSignal` prefix match), `src/manager.ts` (`${ns}${SCHEMA_KEY_SEP}${pid}` registry key).

The in-memory cache key, the account-switch eviction (`key.startsWith(identity + SEP)`), and the schema-registry key were all built by joining app strings with a single separator. The code comments claimed the separator was `NUL` and therefore "can't appear in identities/namespaces/ids." Two problems:

- The claim is only as strong as "no identifier ever contains a `NUL`" — an invariant the SDK never enforced, while simultaneously advertising `namespace`/`providerId` as *arbitrary* strings.
- Had any identifier contained the separator byte, the consequences were real: (F-1) two different refs share one cache slot → cross-credential disclosure; (F-2) `onLockSignal`'s `startsWith` keeps another account's decrypted secrets in memory when one identity is a prefix of another; (F-3) two schemas collide onto one registry entry, so a field declared **secret** in schema A could be routed to the **plaintext index** under schema B's spec.

These were **not exploitable with realistic identifiers** (they required a control byte inside an app-chosen string), so they are rated Low — but the safety argument was incorrect and worth making airtight.

**Fix (three layers):**
1. **`SessionCache` redesigned to a three-level nested `Map` (`identity → namespace → providerId`).** Isolation is now structural — there is no delimiter to collide on, and `onLockSignal` compares identities by **exact `Map` key** (so `user` vs `user-2` can never alias). Fixes F-1 and F-2 unconditionally.
2. **Schema-registry key is now `JSON.stringify([namespace, providerId])`** — an injective encoding, so no two distinct refs can ever map to one entry. Fixes F-3 unconditionally.
3. **Input hygiene:** `registerCredentialSchema` now **rejects** any `namespace`/`providerId` containing an ASCII control character (`\x00`–`\x1F`, `\x7F`) via `CredentialSchemaError`. Control bytes never occur in legitimate identifiers, and rejecting them keeps every downstream derivation provably unambiguous.

As a side benefit, the two raw `NUL` bytes that were embedded in `src/session.ts` and `src/manager.ts` are gone — the source is now free of control bytes entirely.

**Regression tests:** `hardening — identifier hygiene & key injectivity (F-1/F-2/F-3)` (2 tests) and `hardening — identity isolation (exact-key, no prefix aliasing)` (1 test).

---

### F-6 — `multi` schema set to `[]`: `has()` and `get()` disagreed · **Low · FIXED**

**Location:** `src/manager.ts` (`setCredentials`, `getCredentials`).

Setting a `multi` provider to an empty array yielded `hasCredentials(ref) === false` but `getCredentials(ref)` returned `[]` (not `null`), and `listProviders` still listed it — three probes giving three different answers for the same state.

**Fix (chosen semantics — "empty list = cleared"):** `setCredentials(ref, [])` on a `multi` schema now **removes the provider** from both the encrypted blob and the plaintext index (and drops any warmed cache entry); `getCredentials` returns `null` for an absent *or* empty stored list. All four probes now agree: `has=false`, `get=null`, `listProviders` omits it, `getSummary=null`. Other providers in the same namespace are untouched. This aligns with the SDK's documented "`null` = unconfigured" contract and is the cleanest UX signal for a rotating key-list that currently holds no keys.

**Regression tests:** `hardening — empty-multi consistency (F-6)` (2 tests).

---

### F-7 — Logout-wipe correctness depends on host `getIdentity()` ordering · **Info · VERIFIED SATISFIED (host contract documented)**

`SessionCache.onLockSignal` reads `getIdentity()` at the moment the injected lock signal fires to decide whether to wipe (identity → `null`) or keep (same identity). This assumes the host vault has **already updated `getIdentity()` to its post-event value before broadcasting the lock**. If a host fired the callback *before* nulling identity on logout, a switched-away account's decrypted values would linger in memory until the next signal — never cross-account **readable** (reads are identity-scoped), but not promptly dropped.

**Verification (this audit):** the actual host, `@tetrac/login-sdk` (`src/client/session.ts`), **satisfies the contract as-is** — `clearSession()` removes the public key *before* `notify()`, and `setSession()` writes the new public key *before* `armAppKey()/notify()`. Idle auto-lock (`lockVault()`) never touches the public key, so the B2 "survive-auto-lock" behavior is preserved. The contract is now documented in `SKILL.md §7`, including the wiring rule for Phase 2 (see §7.5).

---

### F-8 — Plaintext secrets cannot be zeroized in a JS heap · **Info · ACCEPTED**

Once decrypted, secret values exist as immutable JavaScript strings that cannot be explicitly wiped; they persist until GC. This is an inherent limitation of browser JS crypto, mitigated by the B2 policy (cache scoped to identity, wiped on logout) and by keeping fund-custody keys out of this SDK entirely (`custody: true` hard-exclusion, verified). No action.

---

### F-9 — KDF had no salt / domain separation / versioning · **Info · FIXED**

**Location:** `src/crypto.ts` (`deriveAesKey`, `KDF_DOMAIN`).

`deriveAesKey` derived the AES-GCM key as `SHA-256(appKey)`. This was **appropriate** for a high-entropy vault key (a slow password KDF would buy nothing), but the raw hash was neither domain-separated (a second system hashing the same app key would derive the identical key) nor versioned.

**Fix:** the key is now `SHA-256("tetrac-credentials-sdk:aes-256-gcm:v1:" + appKey)`. Prepending a **fixed prefix is injective in `appKey`**, so distinct app keys still yield distinct keys; the prefix binds the key to this SDK and this KDF version (bump the trailing `v1` to rotate). This is a **deliberate, one-time format break** — it invalidates any blob written by the earlier unversioned KDF — which is safe here because the SDK is pre-production with **zero persisted blobs and zero consumers** (confirmed in §7.5; consistent with the Q3 "no migration" decision). If the app-key contract ever changes to a low-entropy secret, revisit to HKDF/PBKDF2.

**Regression tests:** `hardening — KDF domain separation (F-9)` (2 tests) — proves a plain `SHA-256(appKey)` key can no longer decrypt SDK ciphertext, and that the SDK's own derivation still round-trips.

---

## 4. Confirmed-good (verified positives)

These properties were tested adversarially and hold:

- **AEAD at rest:** AES-256-GCM; a single flipped ciphertext byte, a wrong app key, an AAD mismatch, an unknown envelope version, and a truncated envelope are all **rejected** (fail-closed) — never forged plaintext.
- **Slot binding:** a secret blob copied into another identity's storage slot **fails to decrypt** (AAD = `${prefix}:${enc(namespace)}:secrets:${enc(identity)}`).
- **IV hygiene:** a fresh CSPRNG 96-bit IV per encryption; two encryptions of identical plaintext differ.
- **No secret leakage:** secret values never appear in the plaintext index or in clear within the stored ciphertext; only non-secret fields and secret field *names* are indexed.
- **Key handling:** the derived `CryptoKey` is imported **non-extractable**.
- **Custody exclusion:** `custody: true` is never cached even with `sessionCacheable: true`.
- **Lock semantics:** index probes work while locked; `getCredentials`/`setCredentials`/`removeCredentials` throw the distinct `VaultLockedError` (≠ `null` "unconfigured").
- **Prototype-pollution resistant:** a crafted plaintext index containing `__proto__` does not pollute `Object.prototype`.
- **Concurrent writes serialized:** per-namespace `withNamespaceLock` plus the F-10 clear-epoch guard means overlapping `set`/`remove`/`clear` operations resolve deterministically with the clear winning.
- **Provider-agnostic:** zero provider-name literals in `src/` **or `dist/`** (CI guard green); a never-before-seen schema round-trips with no SDK change.

### Accepted residuals (raised by the adversarial pass, no change warranted)

- **`getCredentials` is not lock-serialized** — a single-schema read that overlaps a concurrent `setCredentials` *commit* can merge the old plaintext-index half with the new decrypted-secret half. Same-provider data, never a cross-account leak; pre-existing and low-impact. Left as-is to keep reads lock-free. (Note: the `clearNamespace`-vs-read race is *not* in this residual — F-10 closes it via the read-path epoch guard.)
- **Two-key write is not crash-atomic** — the secret blob and plaintext index are separate storage keys; a *process crash* between the two synchronous stores could desync them. Unavoidable in `localStorage` without a journal; pre-existing (same in `removeCredentials`). The F-10 fix made the two stores adjacent (no `await` between), so nothing short of a hard crash can split them.
- **UTF-8 encoding of ill-formed app keys is not injective** — distinct lone surrogates both encode to U+FFFD, so they would derive the same key. Pre-existing, unaffected by F-9, and irrelevant for well-formed high-entropy vault keys.
- **KDF version lives in `KDF_DOMAIN`, not the envelope** — `ENVELOPE_VERSION` stays `1`, so a pre-existing blob fails GCM auth (opaque) rather than a clean "unsupported version". Intentional and harmless (zero persisted blobs). If two KDF versions ever need to coexist, embed a KDF-version byte in the envelope (v0.2).

---

## 5. Changes applied (both passes, all in-repo)

| File | Change | Finding |
|------|--------|---------|
| `src/storage.ts` | Percent-encode `namespace` + `identity` in `secretsKey`/`indexKey`; match encoded prefix in `namespaceKeys`. | F-4 |
| `src/session.ts` | Rewrote `SessionCache` to a nested `identity→namespace→providerId` `Map`; exact-key account eviction; deep-clone on read/write. | F-1, F-2, F-5 |
| `src/manager.ts` | Injective `JSON.stringify` schema key; `assertSafeSegment` control-char rejection; empty-`multi` clears the provider + reads back `null`; per-namespace **clear-epoch** guard on `setCredentials`/`removeCredentials`/`getCredentials` + `encryptBlob`/`commitBlob` split; `listProviders`/`getSummary` skip `count:0` entries. | F-3, F-1/F-2, F-6, F-10 |
| `src/crypto.ts` | Versioned, domain-separated KDF: `SHA-256(KDF_DOMAIN + appKey)`. | F-9 |
| `src/storage.ts` | `readIndex` now validates each **entry's** shape and drops malformed ones, copying survivors through a **null-prototype** accumulator; top-level arrays treated as unconfigured. | F-11 |
| `src/manager.ts` | `getCredentials` strips schema-declared **secret** keys from the plaintext-index half before the merge (secrets only from the AEAD blob); `assertSafeSegment` + field loop reject reserved object keys (`__proto__`/`constructor`/`prototype`). | F-12, F-13 |
| `tests/tamper.test.ts` | **New** at-rest-tamperer suite — malformed-index-entry probe fail-safe (F-11), secret-only-from-blob (F-12), reserved-key rejection (F-13); 25 tests, negative-control-verified. | F-11/F-12/F-13 |
| `src/manager.ts` | **Uniform async error handling:** `setCredentials`'s `requireSchema` moved inside the returned promise, so an unregistered ref now **rejects** rather than throwing synchronously — `set`/`get`/`remove` are all reject-only (a `.catch()` can no longer miss an error). | DX |
| `tests/security.test.ts` | Adversarial suite — findings repro + at-rest crypto + isolation + KDF + empty-multi + concurrency (38 tests). | all |
| `tests/errors.test.ts` | **New** dedicated error-handling & async-consistency suite — every `VaultLockedError`/`CredentialSchemaError`/`CredentialValidationError` path, sync-vs-async throw contract, malformed-schema branches, and adjacent edge use-cases. | DX |
| `tests/blob.test.ts` | **New** shared-namespace-blob suite — the branches that only appear with >1 provider per namespace: set-merge-preserve, remove non-empty re-encrypt, populated-multi probes, concurrent write serialization + error isolation, set-warmed cache, clearNamespace breadth (warm cache, all identities, cross-namespace no-false-abort), last-writer-wins registration. | coverage |
| `tests/env.test.ts` | **New** runtime-guard suite — `resolveStorage` no-storage throw, WebCrypto-unavailable reject. | coverage |
| `tests/security.test.ts` | Fixed a **vacuous** prototype-pollution test (an object-literal `__proto__` is dropped by `JSON.stringify`; now uses a raw `"__proto__"` JSON key); added `readIndex` fail-safe on malformed JSON, remove-deletes-both-keys, multi no-leak, and base64 edge-input (empty / 200 KB / multi-byte-unicode) round-trips. | coverage |
| `tests/universality.test.ts` | Guard now scans `dist/` (broad extension match + silent-no-op assertion) and asserts `src/` has no stray control bytes. | CI |
| `.claude/skills/credentials-sdk/SKILL.md` | Documented the versioned KDF (F-9), the empty-`multi`→`null` contract (F-6), the F-7 wiring rule, the uniform-async-rejection contract, and precise error/probe semantics. | docs |

No public API **signatures** changed (`clearNamespace` stays synchronous). One behavior change: `setCredentials` now reports an unregistered-ref error as a promise rejection instead of a synchronous throw (strictly safer for callers). No provider names introduced. `dist/` rebuilt after all passes.

---

## 6. Test coverage

```
Test Files  8 passed (8)
     Tests  132 passed (132)    # 24 pre-existing + 108 new (hardening + error-handling + coverage + pass-3 tamper)
typecheck   clean (tsc --noEmit)
guard       green (zero provider literals in src/ AND dist/; zero control bytes in src/)
```

**Pass-3 methodology note:** the three pass-3 findings came from an independent re-audit centered on the **at-rest tamperer** (adversary #1) and ordinary storage corruption — the class of inputs the earlier fail-safe test only exercised at whole-index granularity, not per-entry. Each fix was **negative-control-verified**: with the fix reverted, 20/25 of the new `tamper.test.ts` cases fail; with it restored, all pass. The `tamper.test.ts` suite (25) brings the total to 132.

Suites: `manager.test.ts` (round-trips, probes, validation), `session.test.ts` (B2 policy), `universality.test.ts` (runtime-schema + no-provider-literal guard over `src/`+`dist/` + control-byte check), `security.test.ts` (storage-key delimiter F-4, identifier hygiene & key injectivity F-1/F-2/F-3, session-cache reference hygiene F-5, identity isolation, at-rest crypto IV/AAD/wrong-key/tamper/version/truncation, KDF domain separation F-9, empty-multi consistency F-6, clearNamespace concurrency F-10, probe agreement on a stray `count:0` entry, storage fail-safe, base64 edge inputs, end-to-end confidentiality & fail-safe), `errors.test.ts` (uniform async rejection, every error type × condition, sync-vs-async throw contract, `.catch()` catchability), `blob.test.ts` (shared-namespace blob, populated-multi, write serialization, cache warming, clearNamespace breadth), and `env.test.ts` (runtime guards).

**Methodology note:** findings F-1..F-9 came from manual red-team review; **F-10 was found by a follow-up multi-agent adversarial-verification pass** (four independent skeptics each trying to refute a specific change), which refuted the `clearNamespace` concurrency safety of the pass-2 code — fixed and re-verified the same way. Finally a **4-lens multi-agent coverage-critic** audited the whole suite for uncovered use cases/error paths; it surfaced the untested shared-namespace-blob branches (the reason `set`/`remove` are async), the untested runtime guards, and a **vacuous** prototype-pollution test — all now covered/fixed. Test count grew 24 → 107.

---

## 7. Recommendations for v0.2 (non-blocking)

All prior in-repo recommendations (F-6, F-9, the `dist/` scan, and the control-byte check) are **done**. Remaining items are the two **out-of-scope** advisories in §7.5 — a Phase-2 wiring precondition in `next-ttc` and an optional ordering-regression test in `@tetrac/login-sdk` — plus:

1. **HKDF** — only if the injected app-key contract ever changes from high-entropy vault material to a low-entropy secret.

---

## 7.5. Out-of-scope impact analysis (edits required OUTSIDE `tetrac-credentials-sdk`)

A discovery sweep across the consumer repos (`next-ttc`, `tetrac-login-sdk-demo`) and `@tetrac/login-sdk` was run to determine whether either format-breaking change (F-9 blob break, F-6 empty-multi→null) forces any change elsewhere.

**Result: NO edits are required outside this repo for the applied changes.**

- **No consumers exist yet.** `@tetrac/credentials-sdk` has **zero** importers: no `createCredentialManager`, no `credmgr:` keys, no `registerCredentialSchema` anywhere in `next-ttc` or the demo, and the package is absent from `package.json`/lockfile/`node_modules`. Phase-2/Phase-3 wiring has **not** started. The similarly-named `src/services/ApiKeyManager.ts` and `src/utils/localstorage/telegramStore.ts` are the **legacy pre-SDK** stores the SDK will eventually replace; they use `@tetrac/login-sdk` and their **own separate** crypto path, so F-9 cannot touch them and F-6 is unobservable to them. There is **no persisted SDK-format data**, so the F-9 blob break costs nothing.
- **F-7 host contract already holds.** `@tetrac/login-sdk` (`src/client/session.ts`) updates the public key **before** it broadcasts (`clearSession` removes the pubkey before `notify()`; `setSession` writes it before `armAppKey()/notify()`). No login-sdk change is strictly required.

**Advisory (future work, not forced by these changes):**

1. **Phase-2 wiring precondition — `next-ttc` (out of scope).** When the SDK is finally wired, pass `getIdentity: getPublicKey` and `subscribeLock` from `@tetrac/login-sdk`. **Do not** wire `getIdentity` to `isLocked()`/`getAppKey()` — that would make an idle auto-lock look like a logout and defeat the B2 "unlock-once" cache. (Now documented in `SKILL.md §7`.) Whoever migrates `ApiKeyManager`/`telegramStore` onto the SDK adopts the post-F-9 blob format and the F-6 `null`-on-empty contract from the start.
2. **Optional ordering-regression test — `@tetrac/login-sdk` (out of scope).** Add a test asserting the F-7 invariant (pubkey write precedes `notify()` in `setSession`, pubkey removal precedes `notify()` in `clearSession`) so a future refactor can't silently reorder them.

---

## 8. Sign-off

**v0.1.0 — APPROVED** for release under its stated scope (revocable API credentials only; no fund-custody keys). All three Medium findings and all four Low findings are fixed and regression-tested; the concurrency defect (F-10) found by adversarial verification is fixed and re-verified; the two format-breaking hardenings (F-9, F-6) were verified to require no cross-repo edits (§7.5); the one host-dependent Info finding (F-7) was verified already satisfied by `@tetrac/login-sdk`.

*RedHat Team — 2026-07-24 (audit + hardening pass 1 & 2 + adversarial verification)*
