// Public API for @tetrac/credentials-sdk.
// Everything a host app needs: the factory, the types, and the error classes.
// There are NO provider/exchange names anywhere in this package's source (R-4).

// The one factory: construct a manager with injected vault accessors (PRD §4).
export { createCredentialManager } from "./manager.js";

// Public types the app uses to describe and address credentials.
export type {
  CredentialFieldSpec,
  CredentialInput,
  CredentialManager,
  CredentialManagerConfig,
  CredentialOutput,
  CredentialRef,
  CredentialSchema,
  CredentialSummary,
  CredentialValues,
  StorageLike,
} from "./types.js";

// Error classes. VaultLockedError is deliberately distinct from a null result so read
// sites never confuse "locked" with "unconfigured" (R-1).
export { CredentialSchemaError, CredentialValidationError, VaultLockedError } from "./types.js";
