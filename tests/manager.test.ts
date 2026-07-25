// Manager round-trip tests (PRD §11.1): set → get for a single set, a multi key-list,
// and a two-field set; index probes (has/list/summary) work WITHOUT unlocking; a null
// app key throws VaultLockedError on get only. All schemas here are FAKE/runtime.
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

// A single-set schema standing in for an exchange credential (secret + non-secret split).
const VENUE_SCHEMA: CredentialSchema = {
  ref: { namespace: "exchange", providerId: "venue-x" },
  fields: [
    { key: "apiKey", secret: true, required: true },
    { key: "apiSecret", secret: true, required: true },
    { key: "passphrase", secret: true },
    { key: "walletAddress", secret: false },
  ],
  sessionCacheable: true,
};

// A multi schema standing in for a rotating key list (all-secret, list of sets).
const KEYLIST_SCHEMA: CredentialSchema = {
  ref: { namespace: "service", providerId: "ai-provider" },
  fields: [{ key: "apiKey", secret: true, required: true }],
  multi: true,
};

// A two-field schema standing in for a bot token + non-secret chat id.
const BOT_SCHEMA: CredentialSchema = {
  ref: { namespace: "service", providerId: "bot-service" },
  fields: [
    { key: "token", secret: true, required: true },
    { key: "chatId", secret: false },
  ],
  sessionCacheable: true,
};

// Track managers so we can dispose their lock listeners after each test.
let live: CredentialManager[] = [];
function makeManager(vault: ReturnType<typeof createVault>, storage = createMemoryStorage()): CredentialManager {
  // Construct with injected vault accessors + in-memory storage.
  const mgr = createCredentialManager({
    getAppKey: vault.getAppKey,
    getIdentity: vault.getIdentity,
    subscribeLock: vault.subscribeLock,
    storage,
  });
  // Remember it for teardown.
  live.push(mgr);
  return mgr;
}

afterEach(() => {
  // Detach every manager's lock listener between tests.
  for (const mgr of live) mgr.dispose();
  live = [];
});

describe("manager round-trips", () => {
  it("single set: set → get merges secret + non-secret fields", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(VENUE_SCHEMA);
    // Store a full set.
    await mgr.setCredentials(VENUE_SCHEMA.ref, {
      apiKey: "ak",
      apiSecret: "as",
      passphrase: "pp",
      walletAddress: "0xWALLET",
    });
    // Read it back — merged view.
    const got = (await mgr.getCredentials(VENUE_SCHEMA.ref)) as CredentialValues;
    expect(got).toEqual({ apiKey: "ak", apiSecret: "as", passphrase: "pp", walletAddress: "0xWALLET" });
  });

  it("multi set: set → get returns the list of sets", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(KEYLIST_SCHEMA);
    // Store two keys.
    await mgr.setCredentials(KEYLIST_SCHEMA.ref, [{ apiKey: "k1" }, { apiKey: "k2" }]);
    // Read the array back in order.
    const got = (await mgr.getCredentials(KEYLIST_SCHEMA.ref)) as CredentialValues[];
    expect(got).toEqual([{ apiKey: "k1" }, { apiKey: "k2" }]);
  });

  it("two-field set: token stays secret, chatId lives in the plaintext index", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchema(BOT_SCHEMA);
    await mgr.setCredentials(BOT_SCHEMA.ref, { token: "secret-token", chatId: "12345" });
    // Round-trips fully.
    expect(await mgr.getCredentials(BOT_SCHEMA.ref)).toEqual({ token: "secret-token", chatId: "12345" });
    // The non-secret chatId is in the plaintext index; the secret token must NOT appear in clear.
    const indexRaw = storage.getItem("credmgr:service:index:user-1") ?? "";
    expect(indexRaw).toContain("12345");
    expect(indexRaw).not.toContain("secret-token");
  });

  it("has / listProviders / getSummary work WITHOUT unlocking (index probe)", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(VENUE_SCHEMA);
    await mgr.setCredentials(VENUE_SCHEMA.ref, { apiKey: "ak", apiSecret: "as", walletAddress: "0xW" });
    // Now LOCK the vault: app key is null, identity remains.
    vault.autoLock();
    expect(vault.getAppKey()).toBeNull();
    // Index probes still answer while locked.
    expect(mgr.hasCredentials(VENUE_SCHEMA.ref)).toBe(true);
    expect(mgr.listProviders("exchange")).toEqual(["venue-x"]);
    const summary = mgr.getSummary(VENUE_SCHEMA.ref);
    expect(summary?.fields.sort()).toEqual(["apiKey", "apiSecret", "walletAddress"].sort());
    expect(typeof summary?.updatedAt).toBe("number");
  });

  it("null app key → VaultLockedError on get (only), not on the index probes", async () => {
    // Start logged in, then LOCK (identity present, app key null).
    const vault = createVault({ identity: "user-1" });
    vault.autoLock(); // app key → null
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(VENUE_SCHEMA);
    // Probes never throw — they just report "nothing configured".
    expect(mgr.hasCredentials(VENUE_SCHEMA.ref)).toBe(false);
    expect(mgr.listProviders("exchange")).toEqual([]);
    // get throws the distinct locked error (NOT a null "unconfigured").
    await expect(mgr.getCredentials(VENUE_SCHEMA.ref)).rejects.toBeInstanceOf(VaultLockedError);
    // set also requires unlock.
    await expect(mgr.setCredentials(VENUE_SCHEMA.ref, { apiKey: "a", apiSecret: "b" })).rejects.toBeInstanceOf(
      VaultLockedError,
    );
  });

  it("getCredentials returns null (distinct from locked) when unconfigured but unlocked", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchema(VENUE_SCHEMA);
    // Unlocked, nothing stored → null, no throw.
    expect(await mgr.getCredentials(VENUE_SCHEMA.ref)).toBeNull();
  });

  it("removeCredentials deletes one provider; clearNamespace nukes the bucket", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    const mgr = makeManager(vault, storage);
    mgr.registerCredentialSchemas([VENUE_SCHEMA, BOT_SCHEMA]);
    await mgr.setCredentials(VENUE_SCHEMA.ref, { apiKey: "ak", apiSecret: "as" });
    await mgr.setCredentials(BOT_SCHEMA.ref, { token: "t", chatId: "c" });
    // Remove the venue; the bot in the SAME "service" namespace is untouched.
    await mgr.removeCredentials(VENUE_SCHEMA.ref);
    expect(mgr.hasCredentials(VENUE_SCHEMA.ref)).toBe(false);
    expect(await mgr.getCredentials(VENUE_SCHEMA.ref)).toBeNull();
    expect(mgr.hasCredentials(BOT_SCHEMA.ref)).toBe(true);
    // Nuke the whole service namespace.
    mgr.clearNamespace("service");
    expect(mgr.hasCredentials(BOT_SCHEMA.ref)).toBe(false);
    expect(mgr.listProviders("service")).toEqual([]);
  });

  it("validation: unknown fields, missing required fields, and wrong arity are rejected", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    mgr.registerCredentialSchemas([VENUE_SCHEMA, KEYLIST_SCHEMA]);
    // Missing required apiSecret.
    await expect(mgr.setCredentials(VENUE_SCHEMA.ref, { apiKey: "ak" })).rejects.toBeInstanceOf(
      CredentialValidationError,
    );
    // Unknown field "nope".
    await expect(
      mgr.setCredentials(VENUE_SCHEMA.ref, { apiKey: "ak", apiSecret: "as", nope: "x" }),
    ).rejects.toBeInstanceOf(CredentialValidationError);
    // Single schema handed an array.
    await expect(mgr.setCredentials(VENUE_SCHEMA.ref, [{ apiKey: "ak" }])).rejects.toBeInstanceOf(
      CredentialValidationError,
    );
    // Multi schema handed a single object.
    await expect(mgr.setCredentials(KEYLIST_SCHEMA.ref, { apiKey: "k1" })).rejects.toBeInstanceOf(
      CredentialValidationError,
    );
  });

  it("get/set against an unregistered ref throws CredentialSchemaError", async () => {
    const vault = createVault();
    const mgr = makeManager(vault);
    // No schema registered for this ref.
    await expect(mgr.getCredentials({ namespace: "x", providerId: "y" })).rejects.toBeInstanceOf(
      CredentialSchemaError,
    );
  });

  it("data survives a real encrypt/decrypt round-trip across a fresh manager instance", async () => {
    const vault = createVault();
    const storage = createMemoryStorage();
    // First manager writes.
    const writer = makeManager(vault, storage);
    writer.registerCredentialSchema(VENUE_SCHEMA);
    await writer.setCredentials(VENUE_SCHEMA.ref, { apiKey: "persist-ak", apiSecret: "persist-as" });
    // A brand-new manager over the SAME storage must decrypt it back (no shared memory cache).
    const reader = makeManager(vault, storage);
    reader.registerCredentialSchema(VENUE_SCHEMA);
    expect(await reader.getCredentials(VENUE_SCHEMA.ref)).toEqual({ apiKey: "persist-ak", apiSecret: "persist-as" });
    // And the on-disk secret blob must NOT contain the plaintext secret.
    const blob = storage.getItem("credmgr:exchange:secrets:user-1") ?? "";
    expect(blob).not.toContain("persist-ak");
    expect(blob.length).toBeGreaterThan(0);
  });
});
