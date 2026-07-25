// WebCrypto AES-256-GCM encrypt/decrypt for @tetrac/credentials-sdk.
// Zero dependencies: everything here is the platform Web Crypto API (a global).
// The AES key is DERIVED from the injected vault app-key string — the SDK never
// stores a key of its own (PRD §4, §7, Q3).

// Envelope format version byte. Bump if the on-disk layout ever changes.
// (Q3: we intentionally break old crypto-es blobs; there is no v0 to migrate.)
const ENVELOPE_VERSION = 1;

// Key-derivation domain-separation + version tag, hashed together with the app key so this
// SDK's AES key can never coincide with the raw SHA-256 of the same app key used by another
// system, and so the KDF is explicitly versioned for future rotation. Bump the trailing
// version if the derivation ever changes. Prepending a FIXED prefix is injective in appKey,
// so distinct app keys still yield distinct AES keys. (R-audit F-9; pre-production: this
// changes the derived key and thus intentionally breaks any pre-existing v0.1.0 dev blobs.)
const KDF_DOMAIN = "tetrac-credentials-sdk:aes-256-gcm:v1:";

// AES-GCM nonce length in bytes. 96 bits is the standard/recommended size for GCM.
const IV_LENGTH = 12;

// Reused text codecs (allocating once is cheaper than per-call).
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Encode a string to UTF-8 bytes backed by a plain ArrayBuffer. `TextEncoder.encode`
 * is typed `Uint8Array<ArrayBufferLike>`, which TS won't accept as WebCrypto's
 * `BufferSource`; copying through the array constructor yields a `Uint8Array<ArrayBuffer>`.
 * The copy is negligible for credential-sized inputs.
 */
function utf8(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(textEncoder.encode(text));
}

/**
 * Fetch the platform SubtleCrypto, or throw a clear error if the runtime lacks it.
 * Browsers always have it; Node ≥20 exposes it as `globalThis.crypto`.
 */
function getSubtle(): SubtleCrypto {
  // Read the global crypto object defensively (it may be undefined on ancient runtimes).
  const cryptoObj = (globalThis as { crypto?: Crypto }).crypto;
  // Bail loudly rather than dereferencing undefined downstream.
  if (!cryptoObj?.subtle) {
    throw new Error("WebCrypto (globalThis.crypto.subtle) is unavailable in this runtime.");
  }
  // The SubtleCrypto instance used for all AES-GCM operations.
  return cryptoObj.subtle;
}

/**
 * Generate a cryptographically-random IV for one encryption. A fresh random IV per
 * message keeps (key, IV) pairs unique, which is the security requirement for GCM.
 */
function randomIv(): Uint8Array<ArrayBuffer> {
  // Allocate the nonce buffer.
  const iv = new Uint8Array(IV_LENGTH);
  // Fill it from the platform CSPRNG.
  (globalThis as { crypto: Crypto }).crypto.getRandomValues(iv);
  // Hand back the filled nonce.
  return iv;
}

/**
 * Derive a 256-bit AES-GCM key from the injected vault app-key string.
 *
 * The app key is the login-SDK vault key — already high-entropy key material, not a
 * user password — so a single SHA-256 to normalise any string to exactly 32 bytes is
 * appropriate and fast (a slow password KDF would buy nothing here). We hash a fixed
 * domain-separation/version prefix together with the app key (see {@link KDF_DOMAIN}) so
 * the derived key is bound to this SDK and this KDF version. If the app key format ever
 * changes to a low-entropy secret, revisit this to use PBKDF2/HKDF.
 */
async function deriveAesKey(appKey: string): Promise<CryptoKey> {
  // The SubtleCrypto instance.
  const subtle = getSubtle();
  // Hash the domain-separated app key down to a fixed 32-byte digest.
  const digest = await subtle.digest("SHA-256", utf8(KDF_DOMAIN + appKey));
  // Import those 32 bytes as a non-extractable AES-GCM key usable for encrypt+decrypt.
  return subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * Encode raw bytes to base64 using platform primitives (btoa), avoiding Node's
 * Buffer so the code runs identically in the browser. Iterates char-by-char to
 * dodge call-stack limits on `String.fromCharCode(...big)`.
 */
function bytesToBase64(bytes: Uint8Array): string {
  // Accumulate a binary (Latin-1) string one byte at a time.
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    // Append the code unit for this byte.
    binary += String.fromCharCode(bytes[i] as number);
  }
  // btoa turns the binary string into base64.
  return btoa(binary);
}

/**
 * Decode base64 back to raw bytes using platform primitives (atob).
 */
function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
  // atob yields a binary (Latin-1) string.
  const binary = atob(base64);
  // Allocate the output buffer of the right length.
  const bytes = new Uint8Array(binary.length);
  // Copy each char's code unit into the byte array.
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  // Return the decoded bytes.
  return bytes;
}

/**
 * Encrypt a UTF-8 string under the app key and return a compact base64 envelope:
 *   [1 byte version][12 byte IV][ciphertext + 16 byte GCM tag]
 *
 * `aad` (additional authenticated data) binds the ciphertext to its logical slot
 * (namespace+identity): a blob copied into a different slot fails authentication.
 */
export async function encryptString(appKey: string, plaintext: string, aad: string): Promise<string> {
  // The SubtleCrypto instance.
  const subtle = getSubtle();
  // Derive the per-app-key AES key.
  const key = await deriveAesKey(appKey);
  // Fresh random nonce for this message.
  const iv = randomIv();
  // Encrypt; GCM appends the 128-bit authentication tag to the ciphertext.
  const cipherBuffer = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(aad) },
    key,
    utf8(plaintext),
  );
  // View the ciphertext (with tag) as bytes.
  const cipherBytes = new Uint8Array(cipherBuffer);
  // Assemble version || iv || ciphertext into one contiguous buffer.
  const envelope = new Uint8Array(1 + IV_LENGTH + cipherBytes.length);
  // Byte 0: format version.
  envelope[0] = ENVELOPE_VERSION;
  // Bytes 1..12: the IV.
  envelope.set(iv, 1);
  // Bytes 13..: the ciphertext+tag.
  envelope.set(cipherBytes, 1 + IV_LENGTH);
  // Base64 the whole envelope for string storage.
  return bytesToBase64(envelope);
}

/**
 * Decrypt an envelope produced by `encryptString`, using the same app key and AAD.
 * Throws if the version is unknown or authentication fails (wrong key/AAD/tampering).
 */
export async function decryptString(appKey: string, envelopeB64: string, aad: string): Promise<string> {
  // The SubtleCrypto instance.
  const subtle = getSubtle();
  // Decode the base64 envelope back to bytes.
  const envelope = base64ToBytes(envelopeB64);
  // Reject anything too short to even contain version + IV.
  if (envelope.length < 1 + IV_LENGTH) {
    throw new Error("Credential ciphertext is malformed (too short).");
  }
  // Byte 0 must be a version we understand.
  if (envelope[0] !== ENVELOPE_VERSION) {
    throw new Error(`Unsupported credential ciphertext version: ${envelope[0]}.`);
  }
  // Extract the IV (bytes 1..12).
  const iv = envelope.subarray(1, 1 + IV_LENGTH);
  // Extract the ciphertext+tag (bytes 13..end).
  const cipherBytes = envelope.subarray(1 + IV_LENGTH);
  // Derive the same AES key from the app key.
  const key = await deriveAesKey(appKey);
  // Decrypt+verify; a wrong key, wrong AAD, or tampering throws here.
  const plainBuffer = await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: utf8(aad) },
    key,
    cipherBytes,
  );
  // Decode the recovered bytes back to a UTF-8 string.
  return textDecoder.decode(plainBuffer);
}
