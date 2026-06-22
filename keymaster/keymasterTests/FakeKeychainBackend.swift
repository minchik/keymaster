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
// sequence the orchestration issued.
enum KeychainCall: Equatable {
  case add(String)
  case read(String, verb: String)
  case delete(String)
  case authenticate(reason: String)
  case readUsing(String)
}

// The opaque batch token handed back by authenticate(). Trivial — the fake reads
// straight from its dictionary and does not need a real LAContext.
struct FakeAuthSession: AuthSession {}

final class FakeKeychainBackend: KeychainBackend {
  // The stored secrets, keyed by keychain key.
  var store: [String: Data]
  // Ordered log of every primitive call, for asserting ordering invariants.
  private(set) var calls: [KeychainCall] = []

  // Programmable failures: when an entry is present, that op throws the given
  // error instead of running. `authenticateError`, when set, fails the one batch
  // prompt.
  var addErrors: [String: KeychainError] = [:]
  var readErrors: [String: KeychainError] = [:]
  var deleteErrors: [String: KeychainError] = [:]
  var readUsingErrors: [String: KeychainError] = [:]
  var authenticateError: KeychainError?

  init(store: [String: Data] = [:]) {
    self.store = store
  }

  func add(key: String, secret: Data) throws {
    calls.append(.add(key))
    // Mirror the real backend: adding over a present key collides as .duplicate
    // (driving SecretManager's upsert path) BEFORE any programmed failure is
    // checked — the real SecItemAdd reports errSecDuplicateItem for a present item,
    // not some unrelated error. Checking the duplicate first also lets a test fail
    // only the upsert's re-add (set's second add, after the delete clears the key)
    // without also tripping the first add.
    guard store[key] == nil else { throw KeychainError.duplicate }
    if let error = addErrors[key] { throw error }
    store[key] = secret
  }

  func read(key: String, verb: String) throws -> Data {
    calls.append(.read(key, verb: verb))
    if let error = readErrors[key] { throw error }
    guard let data = store[key] else { throw KeychainError.status("item not found") }
    return data
  }

  func delete(key: String) throws {
    calls.append(.delete(key))
    if let error = deleteErrors[key] { throw error }
    store[key] = nil
  }

  func authenticate(reason: String) throws -> AuthSession {
    calls.append(.authenticate(reason: reason))
    if let error = authenticateError { throw error }
    return FakeAuthSession()
  }

  func read(key: String, using session: AuthSession) throws -> Data {
    calls.append(.readUsing(key))
    if let error = readUsingErrors[key] { throw error }
    guard let data = store[key] else { throw KeychainError.status("item not found") }
    return data
  }
}
