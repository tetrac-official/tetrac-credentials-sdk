// Regression tests for the correctness/security defects found by the v0.1.0 multi-agent
// re-review (post the original F-1..F-13 audit). Blocks R-A..R-D are NEGATIVE-CONTROL-verified
// regressions: each was observed to FAIL against the pre-fix source and to PASS after the fix, so it
// can't silently rot into a no-op. R-E is a defensive INVARIANT test (see its note): the race it
// guards is timing-dependent and does not reliably reproduce under real WebCrypto, so it pins the
// post-fix invariant rather than serving as a strict negative control.
//
//   R-A  storage.ts readIndex fail-OPEN on an absent/corrupt index: a prototype-named providerId
//        ("toString"/"valueOf"/…) aliased an inherited Object.prototype member because only the
//        POPULATED path returned Object.create(null). has() reported a phantom credential present;
//        getSummary()/getCredentials() threw a TypeError instead of "unconfigured".
//   R-B  count divergence: isValidEntry admitted a negative count and getSummary gated on
//        `count===0` while has/list gated on `count>0`, so the three lock-free probes disagreed.
//   R-C  crypto.ts decryptString stripped a leading U+FEFF (BOM) — a lossy round-trip.
//   R-D  cross-identity cache leak: a set/get whose account switched mid-crypto-await filed (or
//        returned) the previous account's plaintext under the NEW identity.
//   R-E  read-after-write staleness: a getCredentials racing a committed set re-warmed the cache
//        with the pre-write value.
import { afterEach, describe, expect, it } from "vitest";
import {
  createCredentialManager,
  type CredentialManager,
  type CredentialSchema,
  type CredentialValues,
} from "../src/index.js";
// Deep import of the internal crypto module — mirrors tests/security.test.ts. Exercises the exported
// (internal) primitive directly, the only surface where the BOM bug is reachable.
import { decryptString, encryptString } from "../src/crypto.js";
import { createMemoryStorage, createVault } from "./helpers.js";

let live: CredentialManager[] = [];
function makeManager(
  vault: ReturnType<typeof createVault>,
  storage = createMemoryStorage(),
): CredentialManager {
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

// Names that resolve to a truthy INHERITED member on a plain {} — the fail-open surface for R-A.
const PROTO_NAMES = [
  "toString",
  "valueOf",
  "constructor",
  "hasOwnProperty",
  "isPrototypeOf",
  "__proto__",
];

describe("R-A — readIndex must fail SAFE (null-proto) on an absent/corrupt index", () => {
  it("lock-free probes treat a prototype-named providerId as ABSENT on an empty store", () => {
    const mgr = makeManager(createVault());
    for (const providerId of PROTO_NAMES) {
      const ref = { namespace: "exchange", providerId };
      expect(mgr.hasCredentials(ref)).toBe(false);
      expect(mgr.getSummary(ref)).toBeNull(); // must NOT throw
    }
    expect(mgr.listProviders("exchange")).toEqual([]);
  });

  it("getCredentials on a registered prototype-named provider resolves null, never TypeError", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema({
      ref: { namespace: "exchange", providerId: "toString" },
      fields: [{ key: "apiKey", secret: true, required: true }],
    });
    expect(
      await mgr.getCredentials({
        namespace: "exchange",
        providerId: "toString",
      }),
    ).toBeNull();
  });

  it("a CORRUPT index blob also fails safe for a prototype-named providerId", () => {
    const storage = createMemoryStorage();
    const vault = createVault();
    const mgr = makeManager(vault, storage);
    // Plant non-JSON under the index key so readIndex takes its catch path.
    storage.setItem("credmgr:exchange:index:user-1", "}{not json");
    expect(
      mgr.hasCredentials({ namespace: "exchange", providerId: "valueOf" }),
    ).toBe(false);
    expect(
      mgr.getSummary({ namespace: "exchange", providerId: "toString" }),
    ).toBeNull();
  });

  it("a real credential under a normal providerId still round-trips (fail-safe is not over-broad)", async () => {
    const mgr = makeManager(createVault());
    const ref = { namespace: "exchange", providerId: "venue" };
    mgr.registerCredentialSchema({
      ref,
      fields: [{ key: "apiKey", secret: true, required: true }],
    });
    await mgr.setCredentials(ref, { apiKey: "real" });
    expect(mgr.hasCredentials(ref)).toBe(true);
    expect(await mgr.getCredentials(ref)).toEqual({ apiKey: "real" });
    // …and a prototype-named sibling in the SAME (now populated) namespace is still absent.
    expect(
      mgr.hasCredentials({ namespace: "exchange", providerId: "toString" }),
    ).toBe(false);
  });
});

describe("R-B — the three lock-free probes AGREE on a tampered/legacy count", () => {
  const MULTI: CredentialSchema = {
    ref: { namespace: "service", providerId: "ghost" },
    fields: [{ key: "apiKey", secret: true, required: true }],
    multi: true,
  };
  function plantIndex(
    storage: ReturnType<typeof createMemoryStorage>,
    count: number,
  ) {
    storage.setItem(
      "credmgr:service:index:user-1",
      JSON.stringify({
        ghost: { publicFields: {}, secretKeys: [], updatedAt: 1, count },
      }),
    );
  }

  it("a NEGATIVE count is dropped at the storage gate → has/list/summary all say absent", () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    mgr.registerCredentialSchema(MULTI);
    plantIndex(storage, -1);
    expect(mgr.hasCredentials(MULTI.ref)).toBe(false);
    expect(mgr.listProviders("service")).toEqual([]);
    expect(mgr.getSummary(MULTI.ref)).toBeNull(); // pre-fix: returned a non-null summary
  });

  it("a fractional count is dropped too", () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    mgr.registerCredentialSchema(MULTI);
    plantIndex(storage, 1.5);
    expect(mgr.hasCredentials(MULTI.ref)).toBe(false);
    expect(mgr.getSummary(MULTI.ref)).toBeNull();
  });

  it("a legacy count:0 (admitted, but non-positive) reads as absent from ALL probes", () => {
    const storage = createMemoryStorage();
    const mgr = makeManager(createVault(), storage);
    mgr.registerCredentialSchema(MULTI);
    plantIndex(storage, 0);
    expect(mgr.hasCredentials(MULTI.ref)).toBe(false);
    expect(mgr.listProviders("service")).toEqual([]);
    expect(mgr.getSummary(MULTI.ref)).toBeNull(); // pre-fix: getSummary said present (count===0 only)
  });

  it("a valid positive count is still present everywhere", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(MULTI);
    await mgr.setCredentials(MULTI.ref, [{ apiKey: "a" }, { apiKey: "b" }]);
    expect(mgr.hasCredentials(MULTI.ref)).toBe(true);
    expect(mgr.listProviders("service")).toEqual(["ghost"]);
    expect(mgr.getSummary(MULTI.ref)).not.toBeNull();
  });
});

describe("R-C — a leading-BOM plaintext round-trips losslessly through the crypto layer", () => {
  const k = "app-key";
  const aad = "credmgr:exchange:secrets:user-1";
  it("U+FEFF-prefixed value survives encrypt → decrypt", async () => {
    for (const pt of ["﻿token", "﻿", "﻿﻿x", "no-bom"]) {
      expect(await decryptString(k, await encryptString(k, pt, aad), aad)).toBe(
        pt,
      );
    }
  });

  it("a secret whose VALUE starts with a BOM round-trips through the manager", async () => {
    const mgr = makeManager(createVault());
    const ref = { namespace: "exchange", providerId: "venue" };
    mgr.registerCredentialSchema({
      ref,
      fields: [{ key: "apiKey", secret: true, required: true }],
    });
    await mgr.setCredentials(ref, { apiKey: "﻿secret-with-bom" });
    expect(await mgr.getCredentials(ref)).toEqual({
      apiKey: "﻿secret-with-bom",
    });
  });
});

describe("R-D — an account switch during a crypto await must never leak A's secret to B", () => {
  const CACHEABLE: CredentialSchema = {
    ref: { namespace: "exchange", providerId: "venue" },
    fields: [{ key: "apiKey", secret: true, required: true }],
    sessionCacheable: true,
  };

  it("READ path: a switch during a COLD decrypt returns null for B and caches nothing under B", async () => {
    const vault = createVault({ identity: "user-1" });
    const storage = createMemoryStorage();
    // Writer persists user-1's secret.
    const w = makeManager(vault, storage);
    w.registerCredentialSchema(CACHEABLE);
    await w.setCredentials(CACHEABLE.ref, { apiKey: "USER1-SECRET" });
    // Fresh manager (cold cache = a page reload) so the read must decrypt from storage.
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(CACHEABLE);
    const p = mgr.getCredentials(CACHEABLE.ref); // parks on the decrypt await
    vault.switchTo("user-2"); // straddles the await
    expect(await p).not.toEqual({ apiKey: "USER1-SECRET" });
    // user-2's cache must not now hold user-1's decrypted secret.
    expect(await mgr.getCredentials(CACHEABLE.ref)).toBeNull();
  });

  it("WRITE path: a switch during an in-flight set files the write under the CALLER's account, not B", async () => {
    const vault = createVault({ identity: "user-1" });
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(CACHEABLE);
    const p = mgr.setCredentials(CACHEABLE.ref, { apiKey: "USER1-SECRET" });
    vault.switchTo("user-2"); // straddles the deferred task / encrypt await
    await p;
    // B sees nothing — user-1's plaintext was neither stored under nor cached under user-2.
    expect(await mgr.getCredentials(CACHEABLE.ref)).toBeNull();
    // Switch back: the write actually landed in user-1's slot and is still readable.
    vault.switchTo("user-1");
    expect(
      (await mgr.getCredentials(CACHEABLE.ref)) as CredentialValues,
    ).toEqual({ apiKey: "USER1-SECRET" });
  });
});

describe("R-E — a get racing a committed write must not re-warm the cache with the stale value", () => {
  // NOTE: the underlying race is timing-dependent — under real WebCrypto a concurrent set (decrypt +
  // encrypt) usually resolves AFTER a get (one decrypt), so the get-loses-the-write interleaving is
  // rare and this test also passed against the pre-fix source. It is kept as a DEFENSIVE invariant:
  // with the writeGen guard the read-after-write result is deterministically the latest write for
  // every interleaving. It is not a strict negative control for the fix.
  const CACHEABLE: CredentialSchema = {
    ref: { namespace: "exchange", providerId: "venue" },
    fields: [{ key: "apiKey", secret: true, required: true }],
    sessionCacheable: true,
  };

  it("after concurrent get + set, the (auto-locked) cached read reflects the LATEST write, never stale", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(CACHEABLE);
    // Loop to exercise many decrypt/encrypt interleavings; the guard must hold for all of them.
    for (let i = 0; i < 25; i += 1) {
      vault.unlock();
      await mgr.setCredentials(CACHEABLE.ref, { apiKey: "v1" }); // storage v1, cache v1
      // Fire get (reads v1 ciphertext synchronously, parks on decrypt) then commit v2 concurrently.
      const g = mgr.getCredentials(CACHEABLE.ref);
      const s = mgr.setCredentials(CACHEABLE.ref, { apiKey: "v2" });
      await Promise.all([g, s]);
      // Auto-lock so the next read can ONLY come from the in-memory cache.
      vault.autoLock();
      expect(await mgr.getCredentials(CACHEABLE.ref)).toEqual({ apiKey: "v2" });
    }
  });
});
