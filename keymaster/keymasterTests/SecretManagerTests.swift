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

  // The `run` batch flow that used to live on `SecretManager.resolveEnvironment` now
  // lives on `OAuthManager.resolveRunEnvironment` (it resolves mixed plain+OAuth
  // batches under one prompt); its coverage — single authenticate, per-key reads,
  // abort-before-exec naming the key, last-write-wins, the authenticate-failure abort
  // — migrated to OAuthRunResolverTests, and the NUL/non-UTF-8 decode rejection is in
  // DecodeTests (decodeEnvValue, the shared helper the resolver still calls).

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

  @Test func secretManagerGetTargetsItsNamespace() throws {
    // The read path threads `namespace` too: a `.secret` manager's `get` reads ONLY
    // the `.secret` store, so a name living only in `.oauth` is a plain not-found —
    // this is the contract the new `secret get` command rests on (a pure plain read
    // that never resolves an OAuth record). The recorded call shows it probed `.secret`
    // alone, never `.oauth`.
    let backend = FakeKeychainBackend(store: [.oauth: ["K": Data("record".utf8)]])
    #expect(throws: KeychainError.status("item not found")) {
      _ = try SecretManager(backend: backend, namespace: .secret).get(key: "K")
    }
    // The recorded calls are the load-bearing assertion: exactly one `.secret` read and
    // no `.oauth` probe. A cross-resolving `get` (e.g. an `.oauth` fallback on a `.secret`
    // miss) would add a `.read(... namespace: .oauth)` call here and fail this check.
    #expect(backend.calls == [.read("K", verb: "Read", namespace: .secret)])
  }

}

// Tests for the cross-namespace refusal in `storeSecret`, shared by `set` and
// `oauth set`. A name must live in exactly one store (one name, one store): before
// writing, `storeSecret` runs a no-prompt `exists` probe of the OTHER namespace and,
// on a hit, throws `.crossNamespaceConflict` writing NOTHING; otherwise it delegates
// to the namespaced upsert unchanged. Exercised against FakeKeychainBackend (records
// the ordered call log — including the leading `.exists` probe — and programmable
// per-key errors).
struct CrossNamespaceConflictTests {

  @Test func noConflictProbesThenCreatesInTarget() throws {
    // Empty backend: the probe of the other namespace finds nothing, so the create
    // proceeds. The recorded log leads with the `.exists` probe, then the create.
    let backend = FakeKeychainBackend()
    try storeSecret(Data("v".utf8), name: "K", in: .secret, conflictingWith: .oauth, backend: backend)
    #expect(backend.calls == [.exists("K", namespace: .oauth), .add("K", namespace: .secret)])
    #expect(backend.storedData("K", namespace: .secret) == Data("v".utf8))
  }

  @Test func oauthSetOverPlainRefusesWritingNothing() {
    // `oauth set` over an existing plain secret: the probe of `.secret` hits, so it
    // throws `.crossNamespaceConflict(existsIn: .secret)` after the probe alone — no
    // add/read/delete — and both stores are left untouched.
    let backend = FakeKeychainBackend(store: [.secret: ["K": Data("plain".utf8)]])
    #expect(throws: KeychainError.crossNamespaceConflict(name: "K", existsIn: .secret)) {
      try storeSecret(Data("record".utf8), name: "K", in: .oauth, conflictingWith: .secret, backend: backend)
    }
    // Probe only — assert the exact sequence (the probe IS logged, so not empty).
    #expect(backend.calls == [.exists("K", namespace: .secret)])
    #expect(backend.storedData("K", namespace: .secret) == Data("plain".utf8))
    #expect(backend.storedData("K", namespace: .oauth) == nil)
  }

  @Test func plainSetOverOauthRefusesWritingNothing() {
    // The symmetric direction: plain `set` over an existing OAuth record probes
    // `.oauth`, hits, and throws `.crossNamespaceConflict(existsIn: .oauth)` with no
    // write calls; both stores untouched.
    let backend = FakeKeychainBackend(store: [.oauth: ["K": Data("record".utf8)]])
    #expect(throws: KeychainError.crossNamespaceConflict(name: "K", existsIn: .oauth)) {
      try storeSecret(Data("plain".utf8), name: "K", in: .secret, conflictingWith: .oauth, backend: backend)
    }
    #expect(backend.calls == [.exists("K", namespace: .oauth)])
    #expect(backend.storedData("K", namespace: .oauth) == Data("record".utf8))
    #expect(backend.storedData("K", namespace: .secret) == nil)
  }

  @Test func sameNamespaceOverwritePassesThroughToUpsert() throws {
    // No cross-namespace conflict (the name lives in the SAME store being written):
    // the probe of the other namespace misses, then the wrapper delegates to `set()`'s
    // full upsert (add → authenticated read → delete → re-add). This keeps the
    // delegation covered now that the old move tests are gone.
    let backend = FakeKeychainBackend(store: [.secret: ["K": Data("old".utf8)]])
    try storeSecret(Data("new".utf8), name: "K", in: .secret, conflictingWith: .oauth, backend: backend)
    #expect(backend.calls == [
      .exists("K", namespace: .oauth),
      .add("K", namespace: .secret),
      .read("K", verb: "Update", namespace: .secret),
      .delete("K", namespace: .secret),
      .add("K", namespace: .secret)
    ])
    #expect(backend.storedData("K", namespace: .secret) == Data("new".utf8))
  }

  @Test func conflictMessageNamesKindAndRmCommand() {
    // The centralized message text names the existing item's kind and the exact
    // `secret rm`/`oauth rm` command, per namespace.
    let secretConflict = KeychainError.crossNamespaceConflict(name: "GitHub", existsIn: .secret)
    #expect(secretConflict.message ==
      "GitHub already exists as a plain secret; remove it first with `keymaster secret rm GitHub`")
    let oauthConflict = KeychainError.crossNamespaceConflict(name: "GitHub", existsIn: .oauth)
    #expect(oauthConflict.message ==
      "GitHub already exists as an OAuth record; remove it first with `keymaster oauth rm GitHub`")
  }

  @Test func nulValueRefusedBeforeAnyBackendCall() {
    // A value carrying an embedded NUL is refused at the write seam BEFORE the
    // cross-namespace probe — `get`/`run` decode through `decodeEnvValue` (which rejects
    // NUL) and `Process.run()` aborts on one, so storing it would be permanently
    // unretrievable. The guard precedes the probe, so the backend records NO calls and
    // nothing is written in either namespace.
    let backend = FakeKeychainBackend()
    #expect(throws: KeychainError.containsNul) {
      try storeSecret(Data("a\0b".utf8), name: "K", in: .secret, conflictingWith: .oauth, backend: backend)
    }
    #expect(backend.calls.isEmpty)
    #expect(backend.storedData("K", namespace: .secret) == nil)
    #expect(backend.storedData("K", namespace: .oauth) == nil)
  }

  @Test func nulValueRefusedInOauthDirectionToo() {
    // The NUL guard lives at the SHARED `storeSecret` seam, so it refuses a NUL-bearing
    // value written into `.oauth` (conflicting with `.secret`) exactly as it does the
    // `.secret` direction — proving the "protects BOTH namespaces uniformly" claim, not
    // just one. Like the `.secret` case it precedes the probe, so no backend calls and
    // nothing is written in either store.
    let backend = FakeKeychainBackend()
    #expect(throws: KeychainError.containsNul) {
      try storeSecret(Data("a\0b".utf8), name: "K", in: .oauth, conflictingWith: .secret, backend: backend)
    }
    #expect(backend.calls.isEmpty)
    #expect(backend.storedData("K", namespace: .secret) == nil)
    #expect(backend.storedData("K", namespace: .oauth) == nil)
  }

  @Test func probeErrorPropagatesAndWritesNothing() {
    // Fail-closed guard: if the other-namespace `exists` probe cannot determine
    // presence (a transient error), `storeSecret` must PROPAGATE that error and write
    // NOTHING — never fall through to the create. Reading "absent" on a transient
    // error would let the same name be written into both stores, breaking "one name,
    // one store". The recorded log is the probe alone — no `.add`.
    let backend = FakeKeychainBackend()
    // The guard probes the OTHER namespace (`.oauth`) before writing into `.secret`.
    backend.existsErrors["K"] = [.oauth: .status("keychain locked")]
    #expect(throws: KeychainError.status("keychain locked")) {
      try storeSecret(Data("v".utf8), name: "K", in: .secret, conflictingWith: .oauth, backend: backend)
    }
    #expect(backend.calls == [.exists("K", namespace: .oauth)])
    #expect(backend.storedData("K", namespace: .secret) == nil)
    #expect(backend.storedData("K", namespace: .oauth) == nil)
  }

}

// Tests for `SecretManager.list(reason:)` — the authenticate-then-enumerate listing
// that backs `secret ls`/`oauth ls`. The security-critical property is the ORDER:
// authenticate (the single Touch ID / Apple Watch prompt) MUST happen first, because a
// bare metadata enumeration never decrypts and so would otherwise disclose every stored
// name with no approval. These assert the sorted output, the namespace scoping, the
// authenticate-before-list ordering riding one session, the empty store, the
// no-disclosure-on-auth-failure invariant, and programmed error propagation, all
// against FakeKeychainBackend.
struct SecretManagerListTests {

  @Test func listAuthenticatesThenReturnsSortedNames() throws {
    // Seed in NON-sorted order so the sort is load-bearing (not incidentally satisfied
    // by insertion order), and assert the calls are `.authenticate` THEN `.listUsing`
    // — authenticate-first is the gate — with the list riding the one session
    // `authenticate` returned (sessionUses records that single id).
    let backend = FakeKeychainBackend(store: [
      "zebra": Data("1".utf8),
      "apple": Data("2".utf8),
      "mango": Data("3".utf8)
    ])
    let names = try SecretManager(backend: backend).list(reason: "List stored keychain secrets")
    #expect(names == ["apple", "mango", "zebra"])
    #expect(backend.calls == [
      .authenticate(reason: "List stored keychain secrets"),
      .listUsing(namespace: .secret)
    ])
    // The listing rode the single session `authenticate` handed out (id 1) — no extra
    // prompt, proving the metadata enumeration runs under the one approval.
    #expect(backend.sessionUses == [1])
  }

  @Test func listIsNamespaceScoped() throws {
    // Seed BOTH stores; each manager lists only its own namespace's names AND records
    // `.listUsing` for its own namespace — so scoping is load-bearing at the call level,
    // mirroring `secretManagerGetTargetsItsNamespace`, not just in the result set.
    let backend = FakeKeychainBackend(store: [
      .secret: ["plainB": Data("1".utf8), "plainA": Data("2".utf8)],
      .oauth: ["oauthB": Data("3".utf8), "oauthA": Data("4".utf8)]
    ])
    let secretNames = try SecretManager(backend: backend, namespace: .secret)
      .list(reason: "List stored keychain secrets")
    #expect(secretNames == ["plainA", "plainB"])
    #expect(backend.calls == [
      .authenticate(reason: "List stored keychain secrets"),
      .listUsing(namespace: .secret)
    ])
    // Even with both stores seeded, the listing rode the single session this backend's
    // `authenticate` handed out (id 1) — one approval, no second prompt.
    #expect(backend.sessionUses == [1])

    let oauthBackend = FakeKeychainBackend(store: [
      .secret: ["plainB": Data("1".utf8), "plainA": Data("2".utf8)],
      .oauth: ["oauthB": Data("3".utf8), "oauthA": Data("4".utf8)]
    ])
    let oauthNames = try SecretManager(backend: oauthBackend, namespace: .oauth)
      .list(reason: "List stored OAuth records")
    #expect(oauthNames == ["oauthA", "oauthB"])
    #expect(oauthBackend.calls == [
      .authenticate(reason: "List stored OAuth records"),
      .listUsing(namespace: .oauth)
    ])
    #expect(oauthBackend.sessionUses == [1])
  }

  @Test func listEmptyStoreReturnsEmptyButStillAuthenticates() throws {
    // An empty namespace returns [] — but authenticate STILL runs first (the gate is
    // unconditional), so the command always prompts even when nothing is stored.
    let backend = FakeKeychainBackend()
    let names = try SecretManager(backend: backend).list(reason: "List stored keychain secrets")
    #expect(names == [])
    #expect(backend.calls == [
      .authenticate(reason: "List stored keychain secrets"),
      .listUsing(namespace: .secret)
    ])
    // The empty enumeration still rode the one session `authenticate` handed out — the
    // single-approval property holds even when nothing is stored.
    #expect(backend.sessionUses == [1])
  }

  @Test func listAuthFailureDisclosesNothing() {
    // THE security invariant: if the approval is cancelled/fails, `list(reason:)` throws
    // and `list(using:)` is NEVER called — `calls` is the authenticate alone, so NO name
    // is enumerated or disclosed without a biometric approval first.
    let backend = FakeKeychainBackend(store: ["secret": Data("v".utf8)])
    backend.authenticateError = .status("Authentication failed or was canceled")
    #expect(throws: KeychainError.status("Authentication failed or was canceled")) {
      _ = try SecretManager(backend: backend).list(reason: "List stored keychain secrets")
    }
    #expect(backend.calls == [.authenticate(reason: "List stored keychain secrets")])
    // No session was ever handed out (authenticate threw) and none was consumed: not only
    // is `list(using:)` absent from `calls`, but `sessionUses` is empty.
    #expect(backend.sessionUses == [])
  }

  @Test func listPropagatesProgrammedListError() {
    // A transient enumeration failure (after a successful authenticate) propagates out
    // of `list(reason:)` — the listing is not swallowed into an empty result.
    let backend = FakeKeychainBackend(store: ["K": Data("v".utf8)])
    backend.listError = .status("keychain locked")
    #expect(throws: KeychainError.status("keychain locked")) {
      _ = try SecretManager(backend: backend).list(reason: "List stored keychain secrets")
    }
    #expect(backend.calls == [
      .authenticate(reason: "List stored keychain secrets"),
      .listUsing(namespace: .secret)
    ])
    // The failing enumeration still rode the one approval's session (the fake records the
    // session before throwing), so a programmed list error doesn't acquire a second one.
    #expect(backend.sessionUses == [1])
  }

}
