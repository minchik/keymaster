//
//  FakeKeychainBackend.swift
//  keymasterTests
//
//  A dictionary-backed KeychainBackend test double. The real SecItem*/LAContext
//  syscalls can never run in automated tests, so SecretManager's orchestration is
//  exercised against this fake instead: it stores secrets in a dictionary, can be
//  programmed to throw a chosen KeychainError per (operation, key), and records an
//  ordered log of every primitive call so the security-critical ORDERING
//  invariants (add → read → delete on upsert; read-before-delete on remove; a
//  single authenticate for the run batch) are assertable.
//
//  Like the other test sources this reaches KeychainBackend/KeychainError through a
//  plain `import Foundation`: SecretManager.swift is compiled directly into this
//  host-less bundle via a synchronized-group membership exception, not imported.
import Foundation

// One recorded primitive call. Equatable so tests can assert the exact ordered
// sequence the orchestration issued. Each store-touching case carries the
// namespace it targeted, so tests can prove plain writes hit `.secret` and OAuth
// writes hit `.oauth`. (`authenticate` is namespace-agnostic, like the protocol.)
enum KeychainCall: Equatable {
  case add(String, namespace: KeychainNamespace)
  case read(String, verb: String, namespace: KeychainNamespace)
  case delete(String, namespace: KeychainNamespace)
  case authenticate(reason: String)
  case readUsing(String, namespace: KeychainNamespace)
  case exists(String, namespace: KeychainNamespace)
  case existsUsing(String, namespace: KeychainNamespace)
  case updateUsing(String, namespace: KeychainNamespace)
  case listUsing(namespace: KeychainNamespace)
}

// The opaque batch token handed back by authenticate(). Carries an `id` so a test
// can prove the session-aware primitives (`readUsing`/`existsUsing`/`updateUsing`)
// all ran through the SAME session returned by a single `authenticate` — the core
// "one approval" guarantee. The fake reads straight from its dictionary and does not
// need a real LAContext.
struct FakeAuthSession: AuthSession, Equatable {
  let id: Int
}

final class FakeKeychainBackend: KeychainBackend {
  // The stored secrets, namespaced: `store[namespace][key]`. A name in `.secret`
  // and the same name in `.oauth` are independent, mirroring the real adapter's
  // distinct service prefixes.
  private var store: [KeychainNamespace: [String: Data]]
  // Ordered log of every primitive call, for asserting ordering invariants.
  private(set) var calls: [KeychainCall] = []
  // Ordered log of the session ids presented to the session-aware primitives
  // (`readUsing`/`existsUsing`/`updateUsing`), so a test can assert classify + read +
  // rotation-update all rode the SAME session returned by `authenticate`.
  private(set) var sessionUses: [Int] = []
  // Hands out a fresh id to each `authenticate`, so two batches get distinct sessions.
  private var nextSessionID = 0

  // Programmable failures: when an entry is present, that op throws the given
  // error instead of running. Keyed by keychain key (namespace-agnostic — tests
  // never need to fail the same key in two namespaces at once). `authenticateError`,
  // when set, fails the one batch prompt.
  var addErrors: [String: KeychainError] = [:]
  var readErrors: [String: KeychainError] = [:]
  var deleteErrors: [String: KeychainError] = [:]
  var readUsingErrors: [String: KeychainError] = [:]
  var updateErrors: [String: KeychainError] = [:]
  // The `exists` probe is the only primitive called per-namespace within a single
  // operation (the cross-namespace guard and the classifier each probe `.oauth` then
  // `.secret`), so its programmed failures are keyed by `[key][namespace]` — a test
  // can fail ONLY the `.secret` probe while the `.oauth` probe passes, which a
  // namespace-agnostic dictionary structurally could not express.
  var existsErrors: [String: [KeychainNamespace: KeychainError]] = [:]
  var authenticateError: KeychainError?
  // When set, `list(using:namespace:)` throws this instead of enumerating — models a
  // transient enumeration failure so a test can prove `list(reason:)` propagates it.
  var listError: KeychainError?

  // Seed the `.secret` namespace from a plain `[key: Data]`, so the existing
  // plain-secret tests construct the fake exactly as before. `.oauth` entries are
  // seeded with the explicit overload.
  init(store: [String: Data] = [:]) {
    self.store = store.isEmpty ? [:] : [.secret: store]
  }

  init(store: [KeychainNamespace: [String: Data]]) {
    self.store = store
  }

  // Read a stored value for assertions. Defaults to `.secret` so the existing
  // plain-secret tests read it as `backend.storedData("K")`, unchanged in spirit.
  func storedData(_ key: String, namespace: KeychainNamespace = .secret) -> Data? {
    store[namespace]?[key]
  }

  func add(key: String, secret: Data, namespace: KeychainNamespace) throws {
    calls.append(.add(key, namespace: namespace))
    // Mirror the real backend: adding over a present key collides as .duplicate
    // (driving SecretManager's upsert path) BEFORE any programmed failure is
    // checked — the real SecItemAdd reports errSecDuplicateItem for a present item,
    // not some unrelated error. Checking the duplicate first also lets a test fail
    // only the upsert's re-add (set's second add, after the delete clears the key)
    // without also tripping the first add.
    guard store[namespace]?[key] == nil else { throw KeychainError.duplicate }
    if let error = addErrors[key] { throw error }
    store[namespace, default: [:]][key] = secret
  }

  func read(key: String, verb: String, namespace: KeychainNamespace) throws -> Data {
    calls.append(.read(key, verb: verb, namespace: namespace))
    if let error = readErrors[key] { throw error }
    guard let data = store[namespace]?[key] else { throw KeychainError.status("item not found") }
    return data
  }

  func delete(key: String, namespace: KeychainNamespace) throws {
    calls.append(.delete(key, namespace: namespace))
    if let error = deleteErrors[key] { throw error }
    store[namespace]?[key] = nil
  }

  func authenticate(reason: String) throws -> AuthSession {
    calls.append(.authenticate(reason: reason))
    if let error = authenticateError { throw error }
    nextSessionID += 1
    return FakeAuthSession(id: nextSessionID)
  }

  func read(key: String, using session: AuthSession, namespace: KeychainNamespace) throws -> Data {
    calls.append(.readUsing(key, namespace: namespace))
    recordSession(session)
    if let error = readUsingErrors[key] { throw error }
    guard let data = store[namespace]?[key] else { throw KeychainError.status("item not found") }
    return data
  }

  // No-prompt presence probe: never mutates, reports whether an item exists under
  // this key/namespace (mirrors the real `SecItemCopyMatching` with
  // `kSecReturnData: false`). Fail-closed like the real adapter: when an
  // `existsErrors` entry is programmed for this (key, namespace), it throws that
  // error (modelling a transient/undeterminable status) INSTEAD of reporting
  // presence — so a test can fail one namespace's probe independently of the other.
  func exists(key: String, namespace: KeychainNamespace) throws -> Bool {
    calls.append(.exists(key, namespace: namespace))
    if let error = existsErrors[key]?[namespace] { throw error }
    return store[namespace]?[key] != nil
  }

  // Session-aware presence probe: same fail-closed behavior as `exists`, but records
  // the presented session so a test can prove the classify probe rode the batch's one
  // `authenticate` (no extra prompt).
  func exists(key: String, using session: AuthSession, namespace: KeychainNamespace) throws -> Bool {
    calls.append(.existsUsing(key, namespace: namespace))
    recordSession(session)
    if let error = existsErrors[key]?[namespace] { throw error }
    return store[namespace]?[key] != nil
  }

  // Session-aware in-place replace. Like the real `SecItemUpdate`, it fails when the
  // item is absent (errSecItemNotFound → `.status`) rather than creating it, and it
  // records the presented session so a test can prove the rotation write-back rode the
  // same approval as the read (atomic, no extra prompt).
  func update(key: String, secret: Data, using session: AuthSession, namespace: KeychainNamespace) throws {
    calls.append(.updateUsing(key, namespace: namespace))
    recordSession(session)
    if let error = updateErrors[key] { throw error }
    guard store[namespace]?[key] != nil else { throw KeychainError.status("item not found") }
    store[namespace]?[key] = secret
  }

  // Session-aware name enumeration: records the call + presented session (so a test can
  // prove the listing rode the batch's one `authenticate`), throws a programmed
  // `listError` if set, otherwise returns the namespace's keys UNSORTED — the
  // orchestration (`SecretManager.list`) is what sorts, so returning unsorted here lets
  // the sort be asserted load-bearing rather than incidentally satisfied by dictionary
  // order.
  func list(using session: AuthSession, namespace: KeychainNamespace) throws -> [String] {
    calls.append(.listUsing(namespace: namespace))
    recordSession(session)
    if let error = listError { throw error }
    return Array((store[namespace] ?? [:]).keys)
  }

  // Note the id of a session-aware call's session, so a test can assert every such
  // call reused the one session `authenticate` returned.
  private func recordSession(_ session: AuthSession) {
    if let session = session as? FakeAuthSession {
      sessionUses.append(session.id)
    }
  }
}
