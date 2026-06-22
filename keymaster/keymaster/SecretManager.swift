// The Foundation-only secret-management contract and orchestration.
//
// Like RunSupport.swift, this file is intentionally Foundation-only — no
// Security/LocalAuthentication/OSStatus types in any signature, no `@main` or
// ArgumentParser symbols — so it compiles into BOTH the app target (via the
// synchronized folder group) and the HOST-LESS `keymasterTests` bundle (via a
// synchronized-group membership exception). The raw SecItem*/LAContext syscalls
// can never run in automated tests (they need code signing, the
// keychain-access-groups entitlement, and real Touch ID hardware), so they are
// hidden behind the `KeychainBackend` protocol here and implemented by the
// app-only `SystemKeychain` adapter, which is verified manually.
//
// Everything here is `nonisolated` so it compiles identically in the app target
// (which defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`) and the test
// target (which has no such default).
import Foundation

// A secret-management failure. The case drives control flow; `message` drives the
// user-facing stderr text. The text is byte-identical to the strings the
// pre-refactor `secretString`/`envSecret`/`failKeychain` printed, so the CLI's
// observable error output is unchanged.
//
// The error stays Foundation-only by carrying the already-formatted display
// string (not an `OSStatus`): the adapter maps every keychain status to
// `.status(SecCopyErrorMessageString(status))`, so no Security types leak into
// this layer or its tests.
nonisolated enum KeychainError: Error, Equatable {
  case duplicate          // control-flow only (set upsert); never surfaced to the user
  case noData             // success status but nil data
  case invalidData        // stored bytes are not valid UTF-8
  case containsNul        // env value has an embedded NUL
  case status(String)     // an OSStatus mapped to its SecCopyErrorMessageString text

  // The user-facing message. `.duplicate` is internal control flow and never
  // reaches the user, but carries a sensible string for completeness.
  var message: String {
    switch self {
    case .duplicate:
      return "item already exists in the keychain"
    case .noData:
      return "keychain returned no data"
    case .invalidData:
      return "stored secret is not valid UTF-8"
    case .containsNul:
      return "stored secret contains a NUL byte and cannot be used as an environment variable"
    case .status(let message):
      return message
    }
  }
}

// An opaque, pre-authenticated batch token. `run` authenticates once (one Touch ID
// prompt) and then reads every secret through the returned session without
// re-prompting. The adapter wraps a pre-authenticated `LAContext` in a concrete
// conformer; the protocol keeps `LocalAuthentication` out of this layer.
nonisolated protocol AuthSession {}

// The thin seam over the raw Keychain/biometric syscalls. Kept primitive
// (`add`/`read`/`delete`) so the security-critical ORDERING (upsert: add, then on
// a duplicate force an authenticated read before delete/re-add; remove:
// read-before-delete) lives in the testable `SecretManager`, not buried in the
// adapter. The `authenticate` + `read(key:using:)` pair keeps the single shared
// `LAContext` adapter-side while letting the `run` batch loop be tested and each
// read failure be attributed to its key.
nonisolated protocol KeychainBackend {
  // Add a biometric-protected item. Throws `.duplicate` if one already exists
  // under this key (so the caller can run the upsert path), any other failure as
  // `.status`.
  func add(key: String, secret: Data) throws

  // Read an item, forcing a fresh Touch ID challenge whose prompt names `key` and
  // uses `verb` (e.g. "Read", "Update", "Remove"). The biometric ACL only
  // challenges on decryption, so this read is what gates overwrite/remove behind
  // Touch ID. Returns the decrypted bytes; throws `.noData`/`.status` on failure.
  func read(key: String, verb: String) throws -> Data

  // Delete an item. `SecItemDelete` does not decrypt, so this does not challenge
  // on its own — callers force an authenticated `read` first.
  func delete(key: String) throws

  // Pre-authenticate ONE batch with a single Touch ID prompt (the `run` flow).
  // `reason` names every key and the program. Throws `.status` if the user
  // cancels or auth fails, so the caller aborts before exec.
  func authenticate(reason: String) throws -> AuthSession

  // Read an item through a pre-authenticated session (no further prompt). Used by
  // the `run` batch so all secrets unlock under the one `authenticate` prompt.
  func read(key: String, using session: AuthSession) throws -> Data
}

// Decode stored bytes into the secret string. Non-UTF-8 is rejected because
// secrets are stored and surfaced as text. Mirrors the old `secretString` decode.
nonisolated func decodeSecret(_ data: Data) throws -> String {
  guard let secret = String(data: data, encoding: .utf8) else {
    throw KeychainError.invalidData
  }
  return secret
}

// Decode bytes read for `run` into an environment-variable value. Like
// `decodeSecret`, but additionally rejects an embedded NUL: a POSIX environment
// value cannot contain one, and although UTF-8 admits U+0000 (so it survives the
// decode), Process.run() would then abort with an uncatchable NSException from
// -[NSString fileSystemRepresentation] rather than a Swift error. Rejecting it
// here lets the batch abort before exec with a controlled message. The caller
// (`SecretManager.resolveEnvironment`) tags the thrown message with the key.
nonisolated func decodeEnvValue(_ data: Data) throws -> String {
  let secret = try decodeSecret(data)
  guard !secret.contains("\0") else {
    throw KeychainError.containsNul
  }
  return secret
}
