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
    #expect(backend.calls == [.add("K", namespace: .secret)])
    #expect(backend.storedData("K") == Data("secret".utf8))
  }

  // MARK: set — overwrite

  @Test func setDuplicateReadsThenDeletesThenReadds() throws {
    // An overwrite must force an authenticated read (verb "Update", which prompts)
    // BEFORE delete/re-add, so the overwrite is gated by Touch ID and the stored
    // secret ends up carrying our biometric ACL.
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    #expect(backend.calls == [
      .add("K", namespace: .secret),
      .read("K", verb: "Update", namespace: .secret),
      .delete("K", namespace: .secret),
      .add("K", namespace: .secret)
    ])
    #expect(backend.storedData("K") == Data("new".utf8))
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
    #expect(backend.calls == [.add("K", namespace: .secret), .read("K", verb: "Update", namespace: .secret)])
    #expect(backend.storedData("K") == Data("old".utf8))
  }

  @Test func setPropagatesNonDuplicateAddFailure() {
    // A failure on the first add that is NOT .duplicate (a real keychain error)
    // propagates as-is — no upsert path, no read.
    let backend = FakeKeychainBackend()
    backend.addErrors["K"] = .status("disk full")
    #expect(throws: KeychainError.status("disk full")) {
      try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    }
    #expect(backend.calls == [.add("K", namespace: .secret)])
  }

  @Test func setDeleteFailureAbortsBeforeReAddLeavingOldSecret() {
    // The authenticated read succeeds but the delete fails: the error must propagate
    // and we must NOT re-add — so a half-completed overwrite leaves the old secret in
    // place rather than wiping it. Guards the same "don't destroy on failure" intent
    // as the cancelled-read case, one step later in the upsert.
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    backend.deleteErrors["K"] = .status("delete failed")
    #expect(throws: KeychainError.status("delete failed")) {
      try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    }
    #expect(backend.calls == [.add("K", namespace: .secret), .read("K", verb: "Update", namespace: .secret), .delete("K", namespace: .secret)])
    #expect(backend.storedData("K") == Data("old".utf8))
  }

  @Test func setReAddFailureAfterDeletePropagates() {
    // The inherent data-loss window of a non-atomic replace: read and delete succeed,
    // then the re-add fails. The error must propagate (so the user learns the store
    // failed) and the key is left absent. The fake fails only this second add because
    // its duplicate check precedes the programmed-error check, so the first add still
    // collides as .duplicate.
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    backend.addErrors["K"] = .status("disk full")
    #expect(throws: KeychainError.status("disk full")) {
      try SecretManager(backend: backend).set(key: "K", secret: Data("new".utf8))
    }
    #expect(backend.calls == [
      .add("K", namespace: .secret),
      .read("K", verb: "Update", namespace: .secret),
      .delete("K", namespace: .secret),
      .add("K", namespace: .secret)
    ])
    #expect(backend.storedData("K") == nil)
  }

  // MARK: remove

  @Test func removeReadsBeforeDelete() throws {
    // Remove must force an authenticated read (verb "Remove", which prompts) before
    // deleting, since delete does not decrypt and would not challenge on its own.
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    try SecretManager(backend: backend).remove(key: "K")
    #expect(backend.calls == [.read("K", verb: "Remove", namespace: .secret), .delete("K", namespace: .secret)])
    #expect(backend.storedData("K") == nil)
  }

  @Test func removeReadFailureAbortsWithNoDelete() {
    // A cancelled/failed read must abort before the delete, leaving the secret.
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    backend.readErrors["K"] = .status("Touch ID failed")
    #expect(throws: KeychainError.status("Touch ID failed")) {
      try SecretManager(backend: backend).remove(key: "K")
    }
    #expect(backend.calls == [.read("K", verb: "Remove", namespace: .secret)])
    #expect(backend.storedData("K") == Data("v".utf8))
  }

  // MARK: get

  @Test func getReadsWithReadVerbAndDecodes() throws {
    let backend = FakeKeychainBackend(store: ["K": Data("hunter2".utf8)])
    let secret = try SecretManager(backend: backend).get(key: "K")
    #expect(secret == "hunter2")
    #expect(backend.calls == [.read("K", verb: "Read", namespace: .secret)])
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
      .readUsing("a", namespace: .secret),
      .readUsing("b", namespace: .secret)
    ])
  }

  @Test func resolveEmptyMappingsAuthenticatesAndReturnsEmpty() throws {
    // An empty batch still issues the single authenticate and returns no env vars.
    // (The CLI's `run` validate() forbids zero --key, so this pins the orchestration
    // contract directly rather than a reachable CLI path.)
    let backend = FakeKeychainBackend()
    let env = try SecretManager(backend: backend).resolveEnvironment(mappings: [], reason: "reason")
    #expect(env == [:])
    #expect(backend.calls == [.authenticate(reason: "reason")])
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

  @Test func resolveAbortsOnFirstUnreadableKeyNotReadingTheRest() {
    // With multiple mappings, a failure on an early key must abort the whole batch
    // immediately — the later keys are never read. This is what lets `run` fail fast
    // naming the offending key BEFORE exec, instead of reading every secret first.
    let backend = FakeKeychainBackend(store: ["a": Data("1".utf8), "b": Data("2".utf8)])
    backend.readUsingErrors["a"] = .status("item not found")
    #expect(throws: KeychainError.status("a: item not found")) {
      _ = try SecretManager(backend: backend).resolveEnvironment(
        mappings: [KeyMapping(env: "A", key: "a"), KeyMapping(env: "B", key: "b")],
        reason: "reason"
      )
    }
    #expect(backend.calls == [.authenticate(reason: "reason"), .readUsing("a", namespace: .secret)])
  }

  @Test func resolveNulValueAbortsNamingTheKey() {
    // An embedded NUL can't be a POSIX env value; abort before exec, key-named.
    let backend = FakeKeychainBackend(store: ["bar": Data("a\0b".utf8)])
    #expect(throws: KeychainError.status(
      "bar: secret contains a NUL byte and cannot be used as an environment variable"
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

// Tests for the namespace-aware behavior the seam gained in this task: the
// no-prompt `exists` probe, the in-place `update` primitive, and the isolation of
// the `.secret` and `.oauth` stores from one another. These exercise
// FakeKeychainBackend directly (it is the only KeychainBackend conformer that can
// run headless) plus SecretManager's threading of its `namespace` through to it.
struct KeychainNamespaceTests {

  // MARK: exists

  @Test func existsReportsPresentAndAbsentWithoutMutating() throws {
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    #expect(try backend.exists(key: "K", namespace: .secret))
    #expect(!(try backend.exists(key: "missing", namespace: .secret)))
    // The probe must not mutate the store — the value is untouched after probing.
    #expect(backend.storedData("K") == Data("v".utf8))
    // It records `.exists` calls but never reads/decodes (no `.read`).
    #expect(backend.calls == [
      .exists("K", namespace: .secret),
      .exists("missing", namespace: .secret)
    ])
  }

  @Test func existsIsNamespaceScoped() throws {
    // A name present in `.secret` is NOT reported present in `.oauth`, and vice
    // versa — the two stores are independent.
    let backend = FakeKeychainBackend(store: [.secret: ["K": Data("v".utf8)]])
    #expect(try backend.exists(key: "K", namespace: .secret))
    #expect(!(try backend.exists(key: "K", namespace: .oauth)))
  }

  @Test func existsPropagatesProgrammedError() {
    // Fail-closed contract: a programmed transient error throws rather than reading
    // as absent. (The real adapter throws on any non-success / non-notFound status.)
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    backend.existsErrors["K"] = [.secret: .status("keychain locked")]
    #expect(throws: KeychainError.status("keychain locked")) {
      _ = try backend.exists(key: "K", namespace: .secret)
    }
    // The error path leaves the store unmutated — `exists` is a pure probe.
    #expect(backend.storedData("K") == Data("v".utf8))
  }

  // MARK: update

  @Test func updateReplacesPresentItemInPlace() throws {
    // `update` is session-aware only (the rotation write-back rides the caller's single
    // approval), so it is driven through a session here.
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    let session = try backend.authenticate(reason: "r")
    try backend.update(key: "K", secret: Data("new".utf8), using: session, namespace: .secret)
    #expect(backend.storedData("K") == Data("new".utf8))
    #expect(backend.calls == [.authenticate(reason: "r"), .updateUsing("K", namespace: .secret)])
  }

  @Test func updateThrowsOnAbsentItem() throws {
    // Mirrors the real SecItemUpdate: updating a missing item fails (it does not
    // create one).
    let backend = FakeKeychainBackend()
    let session = try backend.authenticate(reason: "r")
    #expect(throws: KeychainError.status("item not found")) {
      try backend.update(key: "K", secret: Data("new".utf8), using: session, namespace: .secret)
    }
    #expect(backend.storedData("K") == nil)
  }

  @Test func updatePropagatesProgrammedError() throws {
    let backend = FakeKeychainBackend(store: ["K": Data("old".utf8)])
    backend.updateErrors["K"] = .status("update failed")
    let session = try backend.authenticate(reason: "r")
    #expect(throws: KeychainError.status("update failed")) {
      try backend.update(key: "K", secret: Data("new".utf8), using: session, namespace: .secret)
    }
    // The old value is left intact when the update fails.
    #expect(backend.storedData("K") == Data("old".utf8))
  }

  // MARK: namespace isolation

  @Test func sameNameInBothNamespacesIsIndependent() throws {
    // Storing "K" in `.secret` and "K" in `.oauth` keeps two distinct values; a
    // read/update on one never touches the other.
    let backend = FakeKeychainBackend(store: [
      .secret: ["K": Data("plain".utf8)],
      .oauth: ["K": Data("record".utf8)]
    ])
    #expect(try backend.read(key: "K", verb: "Read", namespace: .secret) == Data("plain".utf8))
    #expect(try backend.read(key: "K", verb: "Read", namespace: .oauth) == Data("record".utf8))
    let session = try backend.authenticate(reason: "r")
    try backend.update(key: "K", secret: Data("record2".utf8), using: session, namespace: .oauth)
    #expect(backend.storedData("K", namespace: .secret) == Data("plain".utf8))
    #expect(backend.storedData("K", namespace: .oauth) == Data("record2".utf8))
  }

  // MARK: SecretManager threads its namespace

  @Test func secretManagerOnOauthTargetsOauthNamespace() throws {
    // A SecretManager built with `.oauth` issues every primitive against `.oauth`,
    // so OAuth-record management reuses the upsert/read-before-delete logic without
    // leaking into the plain-secret store.
    let backend = FakeKeychainBackend()
    let manager = SecretManager(backend: backend, namespace: .oauth)
    try manager.set(key: "rec", secret: Data("{}".utf8))
    #expect(backend.calls == [.add("rec", namespace: .oauth)])
    #expect(backend.storedData("rec", namespace: .oauth) == Data("{}".utf8))
    #expect(backend.storedData("rec", namespace: .secret) == nil)
  }

  @Test func secretManagerDefaultsToSecretNamespace() throws {
    // The defaulted initializer keeps the existing call sites on `.secret`.
    let backend = FakeKeychainBackend()
    try SecretManager(backend: backend).set(key: "K", secret: Data("v".utf8))
    #expect(backend.calls == [.add("K", namespace: .secret)])
  }

}
