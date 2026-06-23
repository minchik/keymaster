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
  case duplicate          // set upsert control flow; only surfaces if a concurrent writer re-creates the key mid-upsert
  case noData             // success status but nil data
  case invalidData        // stored bytes are not valid UTF-8
  case containsNul        // value has an embedded NUL — refused at the write seam and again on read (decodeEnvValue)
  case status(String)     // an OSStatus mapped to its SecCopyErrorMessageString text
  // set/oauth set refused: name already lives in the OTHER namespace (one name, one store)
  case crossNamespaceConflict(name: String, existsIn: KeychainNamespace)

  // The user-facing message. `.duplicate` normally stays internal to the `set`
  // upsert, but can still reach the user if a concurrent writer re-creates the key
  // between the upsert's delete and re-add, so it carries a real string too. That
  // string is the exact text `SecCopyErrorMessageString(errSecDuplicateItem)`
  // returns, so this race prints byte-identically to the pre-refactor
  // `failKeychain(errSecDuplicateItem)` (this Foundation-only layer can't call
  // `SecCopyErrorMessageString` itself, so the text is mirrored here).
  var message: String {
    switch self {
    case .duplicate:
      return "The specified item already exists in the keychain."
    case .noData:
      return "keychain returned no data"
    case .invalidData:
      return "stored secret is not valid UTF-8"
    case .containsNul:
      // Read correctly at BOTH sites: the write-time store guard (storeSecret) and the
      // read-time defense-in-depth check (decodeEnvValue), both of which concern a value
      // that would be injected as an environment variable.
      return "secret contains a NUL byte and cannot be used as an environment variable"
    case .status(let message):
      return message
    case .crossNamespaceConflict(let name, let existsIn):
      // `set`/`oauth set` refuse to write a name that already lives in the other
      // namespace (one name, one store). Name the existing item's kind and the exact
      // `rm` command so the user can remove it first.
      switch existsIn {
      case .secret:
        return "\(name) already exists as a plain secret; remove it first with `keymaster rm \(name)`"
      case .oauth:
        return "\(name) already exists as an OAuth record; remove it first with `keymaster oauth rm \(name)`"
      }
    }
  }
}

// Which Keychain store an operation addresses. Both namespaces live in the same
// access group and are reached through the one `SystemKeychain` adapter; the
// adapter maps each case to a service-name prefix (`dev.mnck.` / `dev.mnck.oauth.`)
// so plain secrets and OAuth records never collide. Defaulting `SecretManager` to
// `.secret` keeps every existing call site (and its behavior) unchanged.
nonisolated enum KeychainNamespace: Hashable {
  case secret
  case oauth
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
  // Add a biometric-protected item in `namespace`. Throws `.duplicate` if one
  // already exists under this key (so the caller can run the upsert path), any
  // other failure as `.status`.
  func add(key: String, secret: Data, namespace: KeychainNamespace) throws

  // Read an item from `namespace`, forcing a fresh Touch ID challenge whose prompt
  // names `key` and uses `verb` (e.g. "Read", "Update", "Remove"). The biometric
  // ACL only challenges on decryption, so this read is what gates overwrite/remove
  // behind Touch ID. Returns the decrypted bytes; throws `.noData`/`.status` on
  // failure.
  func read(key: String, verb: String, namespace: KeychainNamespace) throws -> Data

  // Delete an item from `namespace`. `SecItemDelete` does not decrypt, so this does
  // not challenge on its own — callers force an authenticated `read` first.
  func delete(key: String, namespace: KeychainNamespace) throws

  // Pre-authenticate ONE batch with a single Touch ID prompt (the `run` flow).
  // `reason` names every key and the program. Throws `.status` if the user
  // cancels or auth fails, so the caller aborts before exec. Namespace-agnostic:
  // one `LAContext` reads across both stores in the same access group.
  func authenticate(reason: String) throws -> AuthSession

  // Read an item from `namespace` through a pre-authenticated session (no further
  // prompt). Used by the `run` batch so all secrets unlock under the one
  // `authenticate` prompt.
  func read(key: String, using session: AuthSession, namespace: KeychainNamespace) throws -> Data

  // Probe for an item's presence WITHOUT decrypting it, so it does NOT trigger
  // Touch ID. Used to classify a name's namespace (`.secret` vs `.oauth`) before
  // any prompt. Returns true iff an item exists under `key` in `namespace`, false
  // only on a definitive "not found"; any other status (e.g. a locked keychain or
  // `errSecInteractionNotAllowed`) THROWS rather than reading as absent. This
  // fail-closed behavior is security-relevant: the namespace classifier and the
  // cross-namespace guard must refuse to act on an unknown state rather than guess
  // "absent" (which would false-not-found a real item, or let both creators write
  // the same name into different stores, breaking "one name, one store").
  func exists(key: String, namespace: KeychainNamespace) throws -> Bool

  // Classify presence THROUGH a pre-authenticated session, so the probe rides the
  // caller's single approval (no extra prompt) instead of evaluating the item's ACL
  // on its own. Used by the authenticate-first `get`/`run` resolver to classify a
  // name's namespace AFTER the one Touch ID prompt. Same fail-closed contract as
  // `exists(key:namespace:)`: `false` only on a definitive "not found", THROWS on any
  // other status so a transient error never reads as "absent".
  func exists(key: String, using session: AuthSession, namespace: KeychainNamespace) throws -> Bool

  // Replace an item's data in place THROUGH a pre-authenticated session, so the write
  // rides the caller's single approval (atomic, no extra prompt). Lets the rotation
  // write-back persist a new refresh token under the same prompt that authorized the
  // read, instead of triggering a separate biometric challenge. This is the only
  // `update` form: on a `.biometryAny` item a context-less update would modify the
  // protected item WITHOUT the caller's approval, so the OS would authorize it
  // separately — a SECOND Touch ID prompt — which is exactly what the session-aware
  // form avoids. Throws `.status` if the item is absent or the update fails.
  func update(key: String, secret: Data, using session: AuthSession, namespace: KeychainNamespace) throws
}

// The testable orchestration over a `KeychainBackend`. The security-critical
// ordering of primitive calls lives here (not in the adapter) so it can be
// exercised against a fake: `set` is an upsert that forces an authenticated read
// before overwriting; `remove` reads before it deletes. (The `run` batch flow now
// lives in `OAuthManager.resolveRunEnvironment`, which resolves mixed plain+OAuth
// batches under one prompt.) Everything maps to the same observable behavior the
// pre-refactor CLI had — same prompt verbs, same error text, same abort-before-exec.
nonisolated struct SecretManager {
  let backend: KeychainBackend
  // Which store every operation targets. Defaulted to `.secret` so the existing
  // plain-secret call sites are unchanged; OAuth-record management constructs the
  // manager with `.oauth`.
  let namespace: KeychainNamespace

  init(backend: KeychainBackend, namespace: KeychainNamespace = .secret) {
    self.backend = backend
    self.namespace = namespace
  }

  // Retrieve and decode a secret. The backend's `read` forces a Touch ID prompt
  // (verb "Read") and throws `.noData`/`.status` on failure; non-UTF-8 bytes are
  // rejected here as `.invalidData`. Mirrors the old get → `secretString` path.
  func get(key: String) throws -> String {
    let data = try backend.read(key: key, verb: "Read", namespace: namespace)
    return try decodeSecret(data)
  }

  // Store a secret, upserting. A first create is a plain `add` — no read, so no
  // Touch ID prompt. On a `.duplicate`, the existing item's ACL can't be trusted
  // (another binary in the access group could have created it with a weaker one),
  // so force an authenticated read (verb "Update", which prompts), then delete and
  // re-add so the stored secret always carries our biometric ACL. The read is what
  // gates the overwrite behind Touch ID; if it throws, we abort BEFORE deleting or
  // re-adding — the existing secret is left intact. This ordering is the critical
  // invariant and is asserted in the tests.
  func set(key: String, secret: Data) throws {
    do {
      try backend.add(key: key, secret: secret, namespace: namespace)
    } catch KeychainError.duplicate {
      _ = try backend.read(key: key, verb: "Update", namespace: namespace)
      try backend.delete(key: key, namespace: namespace)
      try backend.add(key: key, secret: secret, namespace: namespace)
    }
  }

  // Remove a secret. `delete` does not decrypt, so the biometric ACL would not
  // challenge it on its own; force an authenticated read (verb "Remove", which
  // prompts) first and delete only when it succeeds. A read failure aborts before
  // the delete, so a cancelled prompt leaves the secret in place.
  func remove(key: String) throws {
    _ = try backend.read(key: key, verb: "Remove", namespace: namespace)
    try backend.delete(key: key, namespace: namespace)
  }

  // Resolve a batch of `--key` mappings into an [env: value] dictionary for `run`,
  // unlocking every secret with a SINGLE Touch ID prompt: `authenticate(reason:)`
  // prompts once (its `reason` names every key and the program), then each secret
  // is read through that pre-authenticated session without re-prompting. Last write
  // wins when two mappings target the same env name. Any read or decode failure is
  // re-thrown tagged "<key>: <message>" so the caller can abort before exec naming
  // the offending key — matching the old `envSecret` text exactly. An `authenticate`
  // failure throws before any read, so a cancelled prompt runs nothing.
  func resolveEnvironment(
    mappings: [KeyMapping],
    reason: String
  ) throws -> [String: String] {
    let session = try backend.authenticate(reason: reason)
    var injected: [String: String] = [:]
    for mapping in mappings {
      do {
        let data = try backend.read(key: mapping.key, using: session, namespace: namespace)
        injected[mapping.env] = try decodeEnvValue(data)
      } catch let error as KeychainError {
        throw KeychainError.status("\(mapping.key): \(error.message)")
      }
    }
    return injected
  }
}

// Store `secret` under `name` in `target`, refusing if `name` already lives in the
// `other` namespace. A name must live in exactly one store (one name, one store), so
// a no-prompt `exists` probe of `other` runs FIRST: on a hit nothing is written and
// `.crossNamespaceConflict` is thrown (its message names the existing item's kind and
// the `rm` command to remove it). Otherwise this delegates to the namespaced upsert,
// which is unchanged (first-create no prompt; same-namespace overwrite prompts via
// read-before-overwrite). Shared by `set` and `oauth set`; the refusal is unit-tested.
//
// The probe-then-write is a BEST-EFFORT refusal, not an atomic guarantee. Like the
// upsert's own non-atomic add→read→delete→add (see the `.duplicate` note above), it
// is a check-then-write across two separate Keychain operations: SecItem offers no
// cross-(service,account) atomic check-and-add, so two CONCURRENT conflicting writers
// (`keymaster set K` and `keymaster oauth set K` racing on the same name) could each
// probe the other store, both see "absent", and both `add` — leaving `K` in both
// stores. This is an accepted edge case for a single-user Touch ID CLI: the only
// possible racer is the user invoking two conflicting commands at once, the worst
// case is benign (a name briefly resolvable in both stores; `get`/`run` still resolve
// deterministically — `.oauth` wins the tie — and either `rm` clears it), and a
// post-write rollback would not close the window (it only moves it) while risking
// mutual deletion when both racers roll back. So the guard stays a refusal, not a
// concurrency control.
nonisolated func storeSecret(
  _ secret: Data,
  name: String,
  in target: KeychainNamespace,
  conflictingWith other: KeychainNamespace,
  backend: KeychainBackend
) throws {
  // Refuse to store a value with an embedded NUL — it could never be injected as an
  // environment variable later: `get`/`run` decode through `decodeEnvValue` (which
  // rejects NUL) and `Process.run()` aborts on one, so a stored NUL value would be
  // permanently unretrievable. Reject it here, at the shared write seam, rather than
  // accept a write that can never be read back. The guard runs FIRST — before the
  // cross-namespace probe — so a bad value triggers no keychain I/O at all, and it
  // protects BOTH namespaces uniformly (in practice only plain `set` can receive a raw
  // NUL; `oauth set` passes canonical JSON, which never contains a `0x00` byte).
  guard !secret.contains(0) else { throw KeychainError.containsNul }
  if try backend.exists(key: name, namespace: other) {
    throw KeychainError.crossNamespaceConflict(name: name, existsIn: other)
  }
  try SecretManager(backend: backend, namespace: target).set(key: name, secret: secret)
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
// (`OAuthManager.resolveRunEnvironment`) tags the thrown message with the key.
//
// `storeSecret` now refuses to WRITE a NUL value in the first place, so this
// read-time check is defense-in-depth for legacy or out-of-band bytes (an item
// written by an older keymaster before the write guard, or by another tool in the
// access group) — a NUL can never originate from a current `set`/`oauth set`.
nonisolated func decodeEnvValue(_ data: Data) throws -> String {
  let secret = try decodeSecret(data)
  guard !secret.contains("\0") else {
    throw KeychainError.containsNul
  }
  return secret
}
