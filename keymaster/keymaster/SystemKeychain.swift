// The real KeychainBackend adapter: the raw Security/LocalAuthentication syscalls.
//
// This is the un-runnable half of the seam. Every call here needs code signing,
// the `keychain-access-groups` entitlement, the data-protection keychain, and
// real Touch ID hardware, so it can NEVER run in automated tests. It is therefore
// kept out of the host-less `keymasterTests` bundle (NOT listed in the pbxproj
// `membershipExceptions`) and is covered by the manual Touch ID checklist in
// CLAUDE.md instead. The testable orchestration lives in `SecretManager.swift`,
// which talks to this only through the `KeychainBackend` protocol.
//
// Everything here is `nonisolated`: `KeychainBackend` is `nonisolated`, so the
// conforming methods are too, and the helper free functions they call must match
// (the app target defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, which
// would otherwise isolate these to the main actor and make the synchronous
// cross-call from a nonisolated method ill-formed).
import Dispatch
import Foundation
import LocalAuthentication
import Security

// Map a namespace to the fixed account that — together with the service prefix —
// forms the generic-password primary key. Plain secrets keep the historical
// `keymaster` account; OAuth records get a DISTINCT account so the two stores can
// never alias. This matters because the plain service prefix (`dev.mnck.`) is a
// textual prefix of the OAuth one (`dev.mnck.oauth.`): a plain key like
// `oauth.GitHub` computes the SAME `kSecAttrService` (`dev.mnck.oauth.GitHub`) as
// OAuth record `GitHub`, so without a discriminator they would be one keychain
// item. Since the (service, account) pair is the primary key, a per-namespace
// account keeps them separate for ALL key text, preserving the "each name lives in
// exactly one store" invariant.
private nonisolated func account(for namespace: KeychainNamespace) -> String {
  switch namespace {
  case .secret:
    return "keymaster"
  case .oauth:
    return "keymaster.oauth"
  }
}

// Map a namespace to its Keychain service-name prefix. Combined with the
// per-namespace `account` above, this separates a plain secret (`dev.mnck.<key>`,
// account `keymaster`) from an OAuth record (`dev.mnck.oauth.<key>`, account
// `keymaster.oauth`).
private nonisolated func servicePrefix(for namespace: KeychainNamespace) -> String {
  switch namespace {
  case .secret:
    return "dev.mnck."
  case .oauth:
    return "dev.mnck.oauth."
  }
}

// The real Keychain/biometric backend. Translates each primitive of the
// `KeychainBackend` contract into the matching SecItem*/LAContext call and maps
// every raw `OSStatus` to a Foundation-only `KeychainError` (carrying the same
// `SecCopyErrorMessageString` text the pre-refactor `failKeychain` printed), so no
// Security types leak past this adapter.
nonisolated struct SystemKeychain: KeychainBackend {
  // Add a biometric-protected item. The added item carries an access-control
  // object so the Keychain challenges for Touch ID OR a paired Apple Watch on
  // every later read/modify/remove. A pre-existing item surfaces as `.duplicate` so the
  // caller's upsert path (read→delete→add) can replace it under our ACL rather
  // than preserving whatever ACL the existing item carried. A nil access control
  // maps to the `errSecParam` text the old `setPassword` returned.
  func add(key: String, secret: Data, namespace: KeychainNamespace) throws {
    guard let accessControl = makeAccessControl() else {
      throw statusError(errSecParam)
    }
    var addQuery = baseQuery(for: key, namespace: namespace)
    addQuery[kSecValueData as String] = secret
    addQuery[kSecAttrAccessControl as String] = accessControl
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    if status == errSecDuplicateItem { throw KeychainError.duplicate }
    guard status == errSecSuccess else { throw statusError(status) }
  }

  // Read an item with a fresh per-key Touch ID prompt naming `key`/`verb`. The
  // biometric ACL only challenges on decryption, so this read is what gates
  // overwrite/remove behind Touch ID (those callers run it first and proceed only
  // when it succeeds). Returns the raw bytes; UTF-8 validation is the
  // SecretManager layer's job.
  func read(key: String, verb: String, namespace: KeychainNamespace) throws -> Data {
    let (status, data) = readItem(verb: verb, key: key, namespace: namespace)
    return try bytes(status: status, data: data)
  }

  // Delete an item. `SecItemDelete` does not decrypt, so it does not challenge on
  // its own — callers force an authenticated `read` first.
  func delete(key: String, namespace: KeychainNamespace) throws {
    let status = SecItemDelete(baseQuery(for: key, namespace: namespace) as CFDictionary)
    guard status == errSecSuccess else { throw statusError(status) }
  }

  // Pre-authenticate ONE batch with a single Touch ID prompt (the `run` flow),
  // wrapping the authenticated `LAContext` in an opaque session. A nil context
  // means the user canceled or auth failed; the thrown message matches the old
  // `run` abort text exactly so the caller aborts before exec with identical
  // output.
  func authenticate(reason: String) throws -> AuthSession {
    guard let context = authenticatedContext(reason: reason) else {
      throw KeychainError.status("Touch ID authentication failed or was canceled")
    }
    return LAAuthSession(context: context)
  }

  // Read an item through the pre-authenticated batch session (no further prompt),
  // reusing its `LAContext` so every secret in a `run` batch unlocks under the one
  // `authenticate` prompt.
  func read(key: String, using session: AuthSession, namespace: KeychainNamespace) throws -> Data {
    guard let session = session as? LAAuthSession else {
      throw KeychainError.status("internal error: unexpected authentication session")
    }
    let (status, data) = readItem(key: key, context: session.context, namespace: namespace)
    return try bytes(status: status, data: data)
  }

  // Probe for an item WITHOUT requesting its data: kSecReturnData is false, so the
  // Keychain never decrypts and the biometric ACL is never evaluated — no Touch ID.
  // Used to classify a name's namespace before any prompt.
  //
  // Fail-closed: only `errSecSuccess` (present) and `errSecItemNotFound` (truly
  // absent) are conclusive. Any other status — a locked keychain,
  // `errSecInteractionNotAllowed`, etc. — means the presence could NOT be determined,
  // so it throws rather than guessing "absent". Reading "absent" on a transient error
  // would both false-not-found a real item AND let the cross-namespace guard skip its
  // refusal, allowing the same name in both stores; throwing makes callers refuse to
  // act on an unknown state.
  func exists(key: String, namespace: KeychainNamespace) throws -> Bool {
    var query = baseQuery(for: key, namespace: namespace)
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecReturnData as String] = false
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
    case errSecSuccess:
      return true
    case errSecItemNotFound:
      return false
    default:
      throw statusError(status)
    }
  }

  // Probe presence THROUGH a pre-authenticated session, riding the caller's single
  // approval. kSecReturnData is false (no decrypt), and the session's authenticated
  // context is attached via kSecUseAuthenticationContext, so this classify probe runs
  // under the one Touch ID prompt the caller already obtained. Same fail-closed
  // contract as the context-less `exists`: only `errSecSuccess`/`errSecItemNotFound`
  // are conclusive; any other status throws rather than guessing "absent".
  func exists(key: String, using session: AuthSession, namespace: KeychainNamespace) throws -> Bool {
    guard let session = session as? LAAuthSession else {
      throw KeychainError.status("internal error: unexpected authentication session")
    }
    var query = baseQuery(for: key, namespace: namespace)
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecReturnData as String] = false
    query[kSecUseAuthenticationContext as String] = session.context
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
    case errSecSuccess:
      return true
    case errSecItemNotFound:
      return false
    default:
      throw statusError(status)
    }
  }

  // Replace an item's stored bytes in place via SecItemUpdate, THROUGH a
  // pre-authenticated session. This rewrites only kSecValueData, leaving the access
  // control intact, and does NOT decrypt the existing value. It still touches a
  // biometric/watch-protected item (the `[.biometryAny, .or, .companion]` ACL), so it
  // attaches the session's authenticated context via kSecUseAuthenticationContext — the
  // in-place write rides the caller's single approval (atomic and prompt-free) instead
  // of provoking a SEPARATE Touch ID / Apple Watch prompt.
  // This is the rotation write-back's path under the authenticate-first `get`/`run`
  // resolver. A non-success status (e.g. errSecItemNotFound when the item is absent)
  // maps to `.status`.
  func update(key: String, secret: Data, using session: AuthSession, namespace: KeychainNamespace) throws {
    guard let session = session as? LAAuthSession else {
      throw KeychainError.status("internal error: unexpected authentication session")
    }
    let attributes = [kSecValueData as String: secret]
    var query = baseQuery(for: key, namespace: namespace)
    query[kSecUseAuthenticationContext as String] = session.context
    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    guard status == errSecSuccess else { throw statusError(status) }
  }
}

// The opaque batch token returned by `authenticate`: a pre-authenticated
// `LAContext` shared by every read in a `run` batch so they unlock under one
// prompt. Private to the adapter — the `AuthSession` protocol keeps
// `LocalAuthentication` out of the SecretManager layer.
private nonisolated struct LAAuthSession: AuthSession {
  let context: LAContext
}

// Map a non-success `OSStatus` to a `KeychainError.status`, carrying the exact
// `SecCopyErrorMessageString` text the pre-refactor `failKeychain` printed (with
// the same "OSStatus <n>" fallback).
private nonisolated func statusError(_ status: OSStatus) -> KeychainError {
  let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
  return .status(message)
}

// Turn a raw (status, data) read result into bytes or a `KeychainError`, mirroring
// the old `secretString` status checks: a non-success status → `.status`, a
// success status with nil data → `.noData` ("keychain returned no data"). UTF-8
// validation stays in the SecretManager layer (`decodeSecret`/`decodeEnvValue`),
// so this returns the raw `Data` unchanged.
private nonisolated func bytes(status: OSStatus, data: Data?) throws -> Data {
  guard status == errSecSuccess else { throw statusError(status) }
  guard let data = data else { throw KeychainError.noData }
  return data
}

// Build a biometric access-control object so the Keychain itself challenges for
// Touch ID OR a paired Apple Watch (side-button double-click) on every
// read/modify/remove. The `[.biometryAny, .or, .companion]` flags add the watch
// as a second *presence* factor; no passcode fallback is introduced
// (`.userPresence`/`.devicePasscode` are deliberately not used). Returns nil if
// creation fails.
nonisolated func makeAccessControl() -> SecAccessControl? {
  // Success is indicated by a non-nil return value, per the Security API
  // contract; a nil return (with the error populated) means creation failed.
  var error: Unmanaged<CFError>?
  return SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryAny, .or, .companion],   // Touch ID OR a paired Apple Watch
    &error
  )
}

// Produce an LAContext whose prompt names the requested key, so a caller asking
// for the wrong secret is visible at approval time.
nonisolated func authContext(verb: String, key: String) -> LAContext {
  let context = LAContext()
  context.localizedReason = "\(verb) keychain secret: \"\(key)\""
  return context
}

// Pre-authenticate ONE LAContext so a whole batch of secrets (the `run`
// subcommand) can be read with a SINGLE Touch ID / Apple Watch prompt.
// evaluateAccessControl(.useItem) forces one fresh biometric-grade challenge
// (Touch ID OR a paired Apple Watch, per the `[.biometryAny, .or, .companion]`
// ACL); the returned context is then handed to each readItem via
// kSecUseAuthenticationContext, and the Keychain reuses that authentication for
// every item instead of re-prompting. Returns nil if the user cancels or auth
// fails, so the caller aborts before launching the command.
//
// Security: touchIDAuthenticationAllowableReuseDuration is left at its default
// (0). The single prompt comes solely from sharing one already-authenticated
// context, NOT from a reuse time window in which a recent device unlock could
// satisfy a read — so keymaster's guarantee that every secret access forces a
// fresh Touch ID / Apple Watch approval is preserved.
//
// Concurrency: evaluateAccessControl(...:reply:) is async, so this bridges it to a
// synchronous flow with a DispatchSemaphore. This function is `nonisolated`, so
// `semaphore.wait()` blocks whatever thread calls it; that is safe because
// LocalAuthentication delivers the reply on a background queue (which signals the
// semaphore) and the CLI has no AppKit run loop to starve.
nonisolated func authenticatedContext(reason: String) -> LAContext? {
  guard let accessControl = makeAccessControl() else { return nil }
  let context = LAContext()
  let semaphore = DispatchSemaphore(value: 0)
  var granted = false
  context.evaluateAccessControl(
    accessControl,
    operation: .useItem,
    localizedReason: reason
  ) { success, _ in
    granted = success
    semaphore.signal()
  }
  semaphore.wait()
  return granted ? context : nil
}

// The fields every Keychain query shares: the item class plus the namespaced
// service and namespaced account that together identify one stored secret. Each
// operation extends this with the keys specific to add/read/remove.
//
// kSecUseDataProtectionKeychain pins every operation to the modern
// data-protection keychain. The biometric access control and the
// keychain-access-groups entitlement are only honored there; without this the
// items would target the legacy file keychain. The single access group from
// the entitlement is applied by default, so kSecAttrAccessGroup is not set.
nonisolated func baseQuery(for key: String, namespace: KeychainNamespace) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: servicePrefix(for: namespace) + key,
    kSecAttrAccount as String: account(for: namespace),
    kSecUseDataProtectionKeychain as String: true
  ]
}

// Read the item, forcing a Touch ID challenge whose prompt names the key and
// uses `verb` (e.g. "Read", "Remove", "Update"). Delegates to the context-based
// overload with a fresh per-key context, so set/get/rm keep prompting exactly as
// before. Returns the raw OSStatus alongside the secret data (nil unless success).
nonisolated func readItem(verb: String, key: String, namespace: KeychainNamespace) -> (OSStatus, Data?) {
  readItem(key: key, context: authContext(verb: verb, key: key), namespace: namespace)
}

// Read one item through a caller-supplied LAContext. `run` passes a single
// pre-authenticated context (see authenticatedContext) so a batch of reads share
// one Touch ID prompt; the per-key callers above pass a fresh context each time.
// Returns the raw OSStatus alongside the secret data (nil unless success).
nonisolated func readItem(key: String, context: LAContext, namespace: KeychainNamespace) -> (OSStatus, Data?) {
  var query = baseQuery(for: key, namespace: namespace)
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = true
  query[kSecUseAuthenticationContext as String] = context
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  return (status, item as? Data)
}
