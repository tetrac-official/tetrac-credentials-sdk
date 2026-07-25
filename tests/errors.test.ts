// Error-handling & async-consistency suite for @tetrac/credentials-sdk.
// Exhaustively exercises every error path and asserts the contract:
//   - the async methods (set/get/remove) ALWAYS reject (never throw synchronously);
//   - the sync methods (registerCredentialSchema) throw synchronously;
//   - VaultLockedError / CredentialSchemaError / CredentialValidationError fire on the
//     right conditions and are catchable via both `try/await` and `.catch()`.
// All schemas are FAKE/runtime — no provider names (R-4).
import { afterEach, describe, expect, it } from "vitest";
import {
  CredentialSchemaError,
  CredentialValidationError,
  VaultLockedError,
  createCredentialManager,
  type CredentialManager,
  type CredentialSchema,
  type CredentialValues,
} from "../src/index.js";
import { createMemoryStorage, createVault } from "./helpers.js";

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
// A manager whose vault is unlocked (appKey present) but has NO identity (logged out).
function makeIdentitylessManager(): CredentialManager {
  const mgr = createCredentialManager({
    getAppKey: () => "app-key",
    getIdentity: () => null,
    subscribeLock: () => () => {},
    storage: createMemoryStorage(),
  });
  live.push(mgr);
  return mgr;
}
afterEach(() => {
  for (const mgr of live) mgr.dispose();
  live = [];
});

const SINGLE: CredentialSchema = {
  ref: { namespace: "exchange", providerId: "venue" },
  fields: [
    { key: "apiKey", secret: true, required: true },
    { key: "apiSecret", secret: true, required: true },
    { key: "note", secret: false },
  ],
  sessionCacheable: true,
};
const MULTI: CredentialSchema = {
  ref: { namespace: "service", providerId: "keys" },
  fields: [{ key: "apiKey", secret: true, required: true }],
  multi: true,
  sessionCacheable: true,
};

// ---- async methods never throw synchronously (uniform rejection) ------------

describe("uniform async error handling — set/get/remove reject, never throw synchronously", () => {
  it("an unregistered ref makes set/get/remove RETURN a promise (no synchronous throw)", async () => {
    const mgr = makeManager(createVault());
    const ref = { namespace: "unregistered", providerId: "nope" };
    let setP: Promise<unknown> | undefined;
    let getP: Promise<unknown> | undefined;
    let remP: Promise<unknown> | undefined;
    // The CALL itself must not throw — the failure lives in the returned promise.
    expect(() => (setP = mgr.setCredentials(ref, { apiKey: "x" }))).not.toThrow();
    expect(() => (getP = mgr.getCredentials(ref))).not.toThrow();
    expect(() => (remP = mgr.removeCredentials(ref))).not.toThrow();
    expect(setP).toBeInstanceOf(Promise);
    expect(getP).toBeInstanceOf(Promise);
    expect(remP).toBeInstanceOf(Promise);
    // set/get require a schema → reject; remove is schema-independent (just deletes) → resolves.
    await expect(setP).rejects.toBeInstanceOf(CredentialSchemaError);
    await expect(getP).rejects.toBeInstanceOf(CredentialSchemaError);
    await expect(remP).resolves.toBeUndefined();
  });

  it(".catch() catches the unregistered-ref error from setCredentials (regression: it used to throw sync)", async () => {
    const mgr = makeManager(createVault());
    let caught: unknown = null;
    await mgr.setCredentials({ namespace: "u", providerId: "u" }, { apiKey: "x" }).catch((e) => {
      caught = e;
    });
    expect(caught).toBeInstanceOf(CredentialSchemaError);
  });

  it(".catch() catches a validation error from setCredentials", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(SINGLE);
    let caught: unknown = null;
    await mgr.setCredentials(SINGLE.ref, { apiKey: "a" }).catch((e) => {
      caught = e;
    });
    expect(caught).toBeInstanceOf(CredentialValidationError);
  });

  it(".catch() catches a locked-vault error from setCredentials", async () => {
    const vault = createVault();
    vault.autoLock();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    let caught: unknown = null;
    await mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b" }).catch((e) => {
      caught = e;
    });
    expect(caught).toBeInstanceOf(VaultLockedError);
  });
});

// ---- CredentialSchemaError (sync) — registerCredentialSchema -----------------

describe("CredentialSchemaError — registerCredentialSchema throws synchronously", () => {
  it("rejects an empty namespace or providerId", () => {
    const mgr = makeManager(createVault());
    expect(() => mgr.registerCredentialSchema({ ref: { namespace: "", providerId: "p" }, fields: [{ key: "k", secret: true }] })).toThrow(
      CredentialSchemaError,
    );
    expect(() => mgr.registerCredentialSchema({ ref: { namespace: "n", providerId: "" }, fields: [{ key: "k", secret: true }] })).toThrow(
      CredentialSchemaError,
    );
  });

  it("rejects a schema with no fields", () => {
    const mgr = makeManager(createVault());
    expect(() => mgr.registerCredentialSchema({ ref: { namespace: "n", providerId: "p" }, fields: [] })).toThrow(CredentialSchemaError);
  });

  it("rejects duplicate field keys", () => {
    const mgr = makeManager(createVault());
    expect(() =>
      mgr.registerCredentialSchema({
        ref: { namespace: "n", providerId: "p" },
        fields: [
          { key: "dup", secret: true },
          { key: "dup", secret: false },
        ],
      }),
    ).toThrow(CredentialSchemaError);
  });

  it("rejects control characters in the namespace or providerId", () => {
    const mgr = makeManager(createVault());
    expect(() => mgr.registerCredentialSchema({ ref: { namespace: "a\u0000b", providerId: "p" }, fields: [{ key: "k", secret: true }] })).toThrow(
      CredentialSchemaError,
    );
    expect(() => mgr.registerCredentialSchema({ ref: { namespace: "n", providerId: "p\u007f" }, fields: [{ key: "k", secret: true }] })).toThrow(
      CredentialSchemaError,
    );
  });
});

// ---- VaultLockedError (async) — locked OR no identity -----------------------

describe("VaultLockedError — thrown when locked or logged out", () => {
  it("set/get/remove reject when the app key is null (idle auto-lock, identity present)", async () => {
    const vault = createVault();
    vault.autoLock(); // appKey → null, identity stays
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    await expect(mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b" })).rejects.toBeInstanceOf(VaultLockedError);
    await expect(mgr.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(VaultLockedError);
    await expect(mgr.removeCredentials(SINGLE.ref)).rejects.toBeInstanceOf(VaultLockedError);
  });

  it("set/get/remove reject when identity is null even if the app key is present (logged out)", async () => {
    const mgr = makeIdentitylessManager();
    mgr.registerCredentialSchema(SINGLE);
    await expect(mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b" })).rejects.toBeInstanceOf(VaultLockedError);
    await expect(mgr.getCredentials(SINGLE.ref)).rejects.toBeInstanceOf(VaultLockedError);
    await expect(mgr.removeCredentials(SINGLE.ref)).rejects.toBeInstanceOf(VaultLockedError);
  });

  it("a cache hit lets getCredentials succeed while locked (no throw)", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b" });
    await mgr.getCredentials(SINGLE.ref); // warm cache
    vault.autoLock(); // appKey null, identity present, same identity → cache survives
    expect(await mgr.getCredentials(SINGLE.ref)).toEqual({ apiKey: "a", apiSecret: "b" });
  });

  it("VaultLockedError has a stable name and satisfies instanceof across the boundary", async () => {
    const vault = createVault();
    vault.autoLock();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(SINGLE);
    let err: unknown;
    try {
      await mgr.getCredentials(SINGLE.ref);
      expect.unreachable("expected a VaultLockedError");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(VaultLockedError);
    expect((err as Error).name).toBe("VaultLockedError");
  });
});

// ---- CredentialValidationError (async) --------------------------------------

describe("CredentialValidationError — bad input to setCredentials", () => {
  it("rejects a missing required field", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(SINGLE);
    await expect(mgr.setCredentials(SINGLE.ref, { apiKey: "a" })).rejects.toBeInstanceOf(CredentialValidationError);
  });

  it("treats an empty-string required field as missing", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(SINGLE);
    await expect(mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "" })).rejects.toBeInstanceOf(CredentialValidationError);
  });

  it("rejects an unknown field", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(SINGLE);
    await expect(mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b", nope: "x" })).rejects.toBeInstanceOf(
      CredentialValidationError,
    );
  });

  it("rejects wrong arity — a single schema handed an array", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(SINGLE);
    await expect(mgr.setCredentials(SINGLE.ref, [{ apiKey: "a", apiSecret: "b" }])).rejects.toBeInstanceOf(
      CredentialValidationError,
    );
  });

  it("rejects wrong arity — a multi schema handed a single object", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(MULTI);
    await expect(mgr.setCredentials(MULTI.ref, { apiKey: "k" })).rejects.toBeInstanceOf(CredentialValidationError);
  });

  it("validates every set in a multi list (a bad set anywhere rejects the whole call)", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(MULTI);
    await expect(mgr.setCredentials(MULTI.ref, [{ apiKey: "ok" }, { nope: "x" } as unknown as CredentialValues])).rejects.toBeInstanceOf(
      CredentialValidationError,
    );
    // The rejected call must not have partially written the list.
    expect(mgr.hasCredentials(MULTI.ref)).toBe(false);
  });
});

// ---- adjacent use cases the error paths interact with -----------------------

describe("use cases adjacent to the error paths", () => {
  it("removeCredentials on an unregistered ref is a resolved no-op when unlocked", async () => {
    const mgr = makeManager(createVault());
    await expect(mgr.removeCredentials({ namespace: "never", providerId: "set" })).resolves.toBeUndefined();
  });

  it("the sync probes never throw and return empty for an unregistered/absent ref", () => {
    const mgr = makeManager(createVault());
    expect(mgr.hasCredentials({ namespace: "x", providerId: "y" })).toBe(false);
    expect(mgr.listProviders("x")).toEqual([]);
    expect(mgr.getSummary({ namespace: "x", providerId: "y" })).toBeNull();
  });

  it("the sync probes go dark (empty) when logged out, even for a configured ref", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b" });
    expect(mgr.hasCredentials(SINGLE.ref)).toBe(true); // configured
    vault.logout(); // identity → null
    expect(mgr.hasCredentials(SINGLE.ref)).toBe(false);
    expect(mgr.listProviders("exchange")).toEqual([]);
    expect(mgr.getSummary(SINGLE.ref)).toBeNull();
  });

  it("an optional field simply omitted is absent from the round-trip", async () => {
    const mgr = makeManager(createVault());
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "a", apiSecret: "b" }); // no `note`
    expect(await mgr.getCredentials(SINGLE.ref)).toEqual({ apiKey: "a", apiSecret: "b" });
  });

  it("getSummary reports field names + updatedAt, never secret values", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(SINGLE);
    await mgr.setCredentials(SINGLE.ref, { apiKey: "SECRET", apiSecret: "ALSO-SECRET", note: "n" });
    const summary = mgr.getSummary(SINGLE.ref);
    expect(summary?.fields.sort()).toEqual(["apiKey", "apiSecret", "note"].sort());
    expect(typeof summary?.updatedAt).toBe("number");
    expect(JSON.stringify(summary)).not.toContain("SECRET");
  });
});

// ---- registerCredentialSchema — remaining malformed-input branches ----------

describe("CredentialSchemaError — more malformed schema inputs", () => {
  it("throws when ref is entirely absent", () => {
    const mgr = makeManager(createVault());
    expect(() =>
      mgr.registerCredentialSchema({ fields: [{ key: "k", secret: true }] } as unknown as CredentialSchema),
    ).toThrow(CredentialSchemaError);
  });

  it("throws when fields is missing / not an array", () => {
    const mgr = makeManager(createVault());
    expect(() =>
      mgr.registerCredentialSchema({ ref: { namespace: "n", providerId: "p" } } as unknown as CredentialSchema),
    ).toThrow(CredentialSchemaError);
  });
});
