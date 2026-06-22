//
//  SecretManagerTests.swift
//  keymasterTests
//
//  Unit tests for the SecretManager orchestration in SecretManager.swift. These
//  exercise the security-critical ordering of primitive backend calls (upsert:
//  add → authenticated read → delete → re-add; remove: read-before-delete; run:
//  one authenticate then per-key reads) against FakeKeychainBackend, which records
//  the ordered call log and can be programmed to throw chosen KeychainErrors.
//
//  Like the other test sources, the shared SecretManager.swift is compiled
//  directly into this host-less bundle via a synchronized-group membership
//  exception, so a plain `import Foundation` reaches its symbols — no app import.
import Foundation
import Testing

struct SecretManagerTests {

  // MARK: set — new key

  @Test func setNewKeyAddsOnlyNoReadOrDelete() throws {
    // A first create must not read or delete — that is what keeps `set` from
    // prompting Touch ID on a brand-new key (the ACL is evaluated on access).
    let backend = FakeKeychainBackend()
    try SecretManager(backend: backend).set(key: "K", secret: Data("secret".utf8))
    #expect(backend.calls == [.add("K")])
    #expect(backend.store["K"] == Data("secret".utf8))
  }

  // MARK: set — overwrite

  @Test func setDuplicateReadsThenDeletesThenReadds() throws {
    // An overwrite must force an authenticated read (verb "Update", which prompts)
    // BEFORE delete/re-add, so the overwrite is gated by Touch ID and the stored
    // secret ends up carrying our biometric ACL.
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    #expect(backend.calls == [
      .add("K"),
      .read("K", verb: "Update"),
      .delete("K"),
      .add("K")
    ])
    #expect(backend.store["K"] == Data("new".utf8))
  }

  @Test func setAuthReadFailureAbortsWithNoDeleteOrReadd() {
    // THE critical invariant: if the authenticated read on overwrite fails (the
    // user cancels Touch ID), abort with NO delete and NO re-add — the existing
    // secret must be left untouched, never destroyed by a cancelled overwrite.
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    backend.readErrors["K"] = .status("Touch ID failed")
    #expect(throws: KeychainError.status("Touch ID failed")) {
      try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    }
    #expect(backend.calls == [.add("K"), .read("K", verb: "Update")])
    #expect(backend.store["K"] == Data("old".utf8))
  }

  @Test func setPropagatesNonDuplicateAddFailure() {
    // A failure on the first add that is NOT .duplicate (a real keychain error)
    // propagates as-is — no upsert path, no read.
    let backend = FakeKeychainBackend()
    backend.addErrors["K"] = .status("disk full")
    #expect(throws: KeychainError.status("disk full")) {
      try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    }
    #expect(backend.calls == [.add("K")])
  }

  // MARK: remove

  @Test func removeReadsBeforeDelete() throws {
    // Remove must force an authenticated read (verb "Remove", which prompts) before
    // deleting, since delete does not decrypt and would not challenge on its own.
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    try SecretManager(backend: backend).remove(key: "K")
    #expect(backend.calls == [.read("K", verb: "Remove"), .delete("K")])
    #expect(backend.store["K"] == nil)
  }

  @Test func removeReadFailureAbortsWithNoDelete() {
    // A cancelled/failed read must abort before the delete, leaving the secret.
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    backend.readErrors["K"] = .status("Touch ID failed")
    #expect(throws: KeychainError.status("Touch ID failed")) {
      try SecretManager(backend: backend).remove(key: "K")
    }
    #expect(backend.calls == [.read("K", verb: "Remove")])
    #expect(backend.store["K"] == Data("v".utf8))
  }

  // MARK: get

  @Test func getReadsWithReadVerbAndDecodes() throws {
    let backend = FakeKeychainBackend(store: ["K": Data("hunter2".utf8)])
    let secret = try SecretManager(backend: backend).get(key: "K")
    #expect(secret == "hunter2")
    #expect(backend.calls == [.read("K", verb: "Read")])
  }

  @Test func getRejectsNonUtf8AsInvalidData() {
    // 0xFF is never a valid UTF-8 lead byte, so the decode fails as .invalidData.
    let backend = FakeKeychainBackend(store: ["K": Data([0xFF])])
    #expect(throws: KeychainError.invalidData) {
      _ = try SecretManager(backend: backend).get(key: "K")
    }
  }

  @Test func getPropagatesNoData() {
    // The backend surfaces a success-status-but-nil-data read as .noData; get
    // propagates it (and its byte-identical message) unchanged.
    let backend = FakeKeychainBackend()
    backend.readErrors["K"] = .noData
    #expect(throws: KeychainError.noData) {
      _ = try SecretManager(backend: backend).get(key: "K")
    }
  }

  @Test func getPropagatesStatusWithMessageIntact() {
    // A keychain failure mapped to .status(msg) propagates with its message intact.
    let backend = FakeKeychainBackend()
    backend.readErrors["K"] = .status("The user name or passphrase you entered is not correct.")
    #expect(throws: KeychainError.status("The user name or passphrase you entered is not correct.")) {
      _ = try SecretManager(backend: backend).get(key: "K")
    }
  }

  // MARK: resolveEnvironment

  @Test func resolveAuthenticatesExactlyOnceForTheBatch() throws {
    // The single Touch ID prompt comes from a single authenticate call; every
    // secret is then read through that one session (readUsing), never re-prompting.
    let backend = FakeKeychainBackend(store: ["a": Data("1".utf8), "b": Data("2".utf8)])
    _ = try SecretManager(backend: backend).resolveEnvironment(
      mappings: [KeyMapping(env: "A", key: "a"), KeyMapping(env: "B", key: "b")],
      reason: "Run \"x\" with keychain secrets: \"a\", \"b\""
    )
    #expect(backend.calls == [
      .authenticate(reason: "Run \"x\" with keychain secrets: \"a\", \"b\""),
      .readUsing("a"),
      .readUsing("b")
    ])
  }

  @Test func resolveMapsEnvNamesToDecodedValues() throws {
    // "ENV=key" injects env ENV from keychain key 'key': the result is keyed by the
    // env name, valued by the decoded secret.
    let backend = FakeKeychainBackend(store: ["bar": Data("secret".utf8)])
    let env = try SecretManager(backend: backend).resolveEnvironment(
      mappings: [KeyMapping(env: "FOO", key: "bar")],
      reason: "reason"
    )
    #expect(env == ["FOO": "secret"])
  }

  @Test func resolveLastWriteWinsOnDuplicateEnvName() throws {
    // Two mappings targeting the same env name: the later one wins, mirroring the
    // old loop's last-assignment-into-the-dictionary behavior.
    let backend = FakeKeychainBackend(store: ["a": Data("first".utf8), "b": Data("second".utf8)])
    let env = try SecretManager(backend: backend).resolveEnvironment(
      mappings: [KeyMapping(env: "DUP", key: "a"), KeyMapping(env: "DUP", key: "b")],
      reason: "reason"
    )
    #expect(env == ["DUP": "second"])
  }

  @Test func resolveUnreadableKeyAbortsNamingTheKey() {
    // A failed read is re-thrown tagged "<key>: <message>" so the caller can abort
    // before exec naming the offending key.
    let backend = FakeKeychainBackend(store: ["a": Data("1".utf8)])
    backend.readUsingErrors["bar"] = .status("item not found")
    #expect(throws: KeychainError.status("bar: item not found")) {
      _ = try SecretManager(backend: backend).resolveEnvironment(
        mappings: [KeyMapping(env: "BAR", key: "bar")],
        reason: "reason"
      )
    }
  }

  @Test func resolveNulValueAbortsNamingTheKey() {
    // An embedded NUL can't be a POSIX env value; abort before exec, key-named.
    let backend = FakeKeychainBackend(store: ["bar": Data("a\0b".utf8)])
    #expect(throws: KeychainError.status(
      "bar: stored secret contains a NUL byte and cannot be used as an environment variable"
    )) {
      _ = try SecretManager(backend: backend).resolveEnvironment(
        mappings: [KeyMapping(env: "BAR", key: "bar")],
        reason: "reason"
      )
    }
  }

  @Test func resolveNonUtf8ValueAbortsNamingTheKey() {
    let backend = FakeKeychainBackend(store: ["bar": Data([0xFF])])
    #expect(throws: KeychainError.status("bar: stored secret is not valid UTF-8")) {
      _ = try SecretManager(backend: backend).resolveEnvironment(
        mappings: [KeyMapping(env: "BAR", key: "bar")],
        reason: "reason"
      )
    }
  }

  @Test func resolveNilDataAbortsNamingTheKey() {
    let backend = FakeKeychainBackend()
    backend.readUsingErrors["bar"] = .noData
    #expect(throws: KeychainError.status("bar: keychain returned no data")) {
      _ = try SecretManager(backend: backend).resolveEnvironment(
        mappings: [KeyMapping(env: "BAR", key: "bar")],
        reason: "reason"
      )
    }
  }

  @Test func resolveAuthenticateFailureAbortsBeforeAnyRead() {
    // A cancelled/failed batch prompt must abort before any read, so the command
    // never launches with a partially-resolved environment.
    let backend = FakeKeychainBackend(store: ["a": Data("1".utf8)])
    backend.authenticateError = .status("Touch ID authentication failed or was canceled")
    #expect(throws: KeychainError.status("Touch ID authentication failed or was canceled")) {
      _ = try SecretManager(backend: backend).resolveEnvironment(
        mappings: [KeyMapping(env: "A", key: "a")],
        reason: "reason"
      )
    }
    #expect(backend.calls == [.authenticate(reason: "reason")])
  }

}
