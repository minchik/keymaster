//
//  OAuthManagerTests.swift
//  keymasterTests
//
//  Unit tests for the OAuthManager mint orchestration in OAuthManager.swift. These
//  exercise the security-critical ordering (classify → read the record → exchange →
//  conditional rotation write-back → return) against FakeKeychainBackend (records the
//  ordered primitive calls, programmable per-key errors) and FakeTokenExchanger
//  (programmed response or thrown error, records the record it received).
//
//  The `get` path is exercised through the authenticate-first `resolveSecret` wrapper,
//  so every test asserts the UNIFIED single-prompt sequence: one `authenticate`, then
//  classify (`existsUsing`) + read (`readUsing`) + (on rotation) write-back
//  (`updateUsing`) ALL through that one session — never a bare `read(verb:)` or a
//  context-less `update`. The `run`-style read-through-session is covered directly via
//  `mint(name:using:)`. Both must target the `.oauth` namespace for OAuth records.
//
//  Like the other test sources, OAuthManager.swift is compiled directly into this
//  host-less bundle via a synchronized-group membership exception, so a plain
//  `import Foundation` reaches its symbols — no app import.
import Foundation
import Testing

struct OAuthManagerTests {

  // A complete, valid record used as the stored credential across the tests.
  private static let record = OAuthRecord(
    tokenEndpoint: "https://example.com/oauth/token",
    clientID: "abc123",
    clientSecret: "shhh",
    refreshToken: "stored-refresh",
    scopes: "read write"
  )

  // The reason the `get` CLI passes for a single-name read, mirrored here so the
  // recorded `.authenticate` reason matches what `keymaster get rec` would emit.
  private static let getReason = "Read keychain secret: \"rec\""

  // Seed a backend with `record` already stored as canonical JSON under `name` in
  // the `.oauth` namespace, mirroring what `oauth set` would have written.
  private static func seededBackend(
    name: String = "rec",
    record: OAuthRecord = OAuthManagerTests.record
  ) throws -> FakeKeychainBackend {
    FakeKeychainBackend(store: [.oauth: [name: try record.encoded()]])
  }

  // MARK: get path — ordering + rotation write-back (one prompt, all through it)

  @Test func getRotatingRecordAuthenticatesOnceThenClassifyReadUpdate() throws {
    // THE single-prompt invariant for a rotating OAuth record: ONE authenticate, then
    // classify (`.oauth` hits, short-circuiting `.secret`), read, and the rotation
    // write-back — all through that session, all in `.oauth`. The returned value is the
    // minted access token and the stale flag is false (the write-back succeeded).
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at-123", refreshToken: "rotated-refresh"
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at-123")
    #expect(result.refreshTokenStale == false)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth),
      .updateUsing("rec", namespace: .oauth)
    ])
    // The record decoded from the keychain bytes is what was handed to the exchanger.
    #expect(exchanger.receivedRecord == Self.record)
  }

  @Test func getRotationCarriesTheSameSessionThroughClassifyReadUpdate() throws {
    // The core "one approval" guarantee for `get`: the classify probe, the read, and
    // the rotation write-back all rode the SAME session id returned by the single
    // `authenticate` — no operation fell back to a self-authenticating call.
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: "rotated-refresh"
    ))
    _ = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    // existsUsing + readUsing + updateUsing each recorded a session; all three match,
    // and all three are session id 1 — the FIRST (and only) session the single
    // `authenticate` handed out — proving none self-authenticated a fresh session.
    #expect(backend.sessionUses.count == 3)
    #expect(backend.sessionUses.allSatisfy { $0 == 1 })
  }

  @Test func getWriteBackBytesAreTheRecordWithOnlyTheRefreshTokenReplacedInOauth() throws {
    // THE rotation invariant: the bytes persisted by `updateUsing` decode back to the
    // ORIGINAL record with ONLY `refreshToken` swapped to the rotated value, and they
    // land in `.oauth` (never `.secret`).
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: "rotated-refresh"
    ))
    _ = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    let storedOauth = backend.storedData("rec", namespace: .oauth)
    let persisted = try JSONDecoder().decode(OAuthRecord.self, from: #require(storedOauth))
    #expect(persisted == OAuthRecord(
      tokenEndpoint: Self.record.tokenEndpoint,
      clientID: Self.record.clientID,
      clientSecret: Self.record.clientSecret,
      refreshToken: "rotated-refresh",
      scopes: Self.record.scopes
    ))
    // Nothing leaked into the plain-secret store.
    #expect(backend.storedData("rec", namespace: .secret) == nil)
  }

  @Test func getWriteBackPreservesExtraStoredKeysOnRotation() throws {
    // LOSSLESS write-back: a record carrying an EXTRA key beyond the 5 modelled fields
    // (here `audience`, e.g. from an out-of-band write) must survive a rotation — the
    // write-back edits `refresh_token` in the raw JSON object rather than re-encoding
    // the partial model, so unknown keys are not dropped. We seed the raw JSON Data
    // directly into the fake's `.oauth` store and assert by DECODING the persisted
    // `updateUsing` bytes (never byte-equality: `JSONSerialization` escapes the
    // always-https `token_endpoint` slashes, so byte-exact would falsely fail),
    // checking BOTH the rotated `refresh_token` AND the preserved `audience`.
    let rawJSON = """
    {"token_endpoint":"https://example.com/oauth/token","client_id":"abc123",\
    "client_secret":"shhh","refresh_token":"stored-refresh","scopes":"read write",\
    "audience":"https://api.example.com"}
    """
    let backend = FakeKeychainBackend(store: [.oauth: ["rec": Data(rawJSON.utf8)]])
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: "rotated-refresh"
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at")
    #expect(result.refreshTokenStale == false)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth),
      .updateUsing("rec", namespace: .oauth)
    ])
    // Decode the persisted bytes as a generic JSON object so the EXTRA `audience`
    // key (not modelled on OAuthRecord) is visible alongside the rotated token.
    let storedOauth = try #require(backend.storedData("rec", namespace: .oauth))
    let object = try #require(
      try JSONSerialization.jsonObject(with: storedOauth) as? [String: Any]
    )
    #expect(object["refresh_token"] as? String == "rotated-refresh")
    #expect(object["audience"] as? String == "https://api.example.com")
    // The modelled fields still decode correctly, with only the refresh token swapped.
    let persisted = try JSONDecoder().decode(OAuthRecord.self, from: storedOauth)
    #expect(persisted == OAuthRecord(
      tokenEndpoint: Self.record.tokenEndpoint,
      clientID: Self.record.clientID,
      clientSecret: Self.record.clientSecret,
      refreshToken: "rotated-refresh",
      scopes: Self.record.scopes
    ))
  }

  @Test func getDoesNotUpdateWhenRefreshTokenAbsent() throws {
    // No `refresh_token` in the reply → nothing to rotate → no `updateUsing` call, but
    // still exactly one authenticate + classify + read.
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: nil
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at")
    #expect(result.refreshTokenStale == false)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
    // The stored record is untouched.
    #expect(backend.storedData("rec", namespace: .oauth) == (try Self.record.encoded()))
  }

  @Test func getDoesNotUpdateWhenRefreshTokenIdentical() throws {
    // A reply echoing the SAME refresh token is not a rotation → no `updateUsing`.
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: "stored-refresh"
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at")
    #expect(result.refreshTokenStale == false)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
  }

  @Test func getDoesNotUpdateWhenRefreshTokenEmpty() throws {
    // A reply carrying an EMPTY refresh token must NOT be persisted — writing it back
    // would brick the credential. The `!rotated.isEmpty` guard skips the write-back, so
    // there is no `updateUsing`, the access token is still returned, and the stale flag
    // is false (rotation was correctly declined; nothing failed). This is the only one
    // of the three rotation-skip conditions (nil / empty / identical) that, if dropped,
    // would silently corrupt the stored credential — hence pinned with its own test.
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: ""
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at")
    #expect(result.refreshTokenStale == false)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
    // The stored record keeps its ORIGINAL refresh token — the empty one was discarded.
    #expect(backend.storedData("rec", namespace: .oauth) == (try Self.record.encoded()))
  }

  @Test func getDoesNotPersistRotatedRefreshTokenContainingNul() throws {
    // Defense-in-depth at the write boundary: a (non-conformant) exchanger that returns a
    // rotated refresh token carrying a NUL must NOT have it persisted — JSONSerialization
    // would escape U+0000 to a six-character text escape, slipping past storeSecret's byte
    // guard and silently bricking the stored record. The write-back is skipped (no
    // `updateUsing`), the just-minted access token is still returned, and the stale flag is
    // set so the CLI warns. The NUL is built from a code point so this source carries no
    // raw NUL byte.
    let nul = String(UnicodeScalar(UInt8(0)))
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at-still-good", refreshToken: "rotated" + nul + "refresh"
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at-still-good")
    #expect(result.refreshTokenStale == true)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
    // The stored record keeps its ORIGINAL refresh token — the NUL-bearing one was discarded.
    #expect(backend.storedData("rec", namespace: .oauth) == (try Self.record.encoded()))
  }

  // MARK: get path — non-fatal write-back failure

  @Test func getWriteBackFailureReturnsTokenWithStaleFlagAndDoesNotThrow() throws {
    // A failed rotation write-back must NOT abort the mint: the access token is still
    // good, so return it with `refreshTokenStale = true` (no throw) and leave the old
    // record in place. The `updateUsing` was attempted (in `.oauth`) under the session.
    let backend = try Self.seededBackend()
    backend.updateErrors["rec"] = .status("update failed")
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at-still-good", refreshToken: "rotated-refresh"
    ))
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "at-still-good")
    #expect(result.refreshTokenStale == true)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth),
      .updateUsing("rec", namespace: .oauth)
    ])
    // ...but the stored record still carries the OLD refresh token.
    #expect(backend.storedData("rec", namespace: .oauth) == (try Self.record.encoded()))
  }

  // MARK: get path — error mapping (key-prefixed once, no updateUsing)

  @Test func getMalformedRecordThrowsKeyPrefixedError() throws {
    // Bytes that are not a valid OAuth record JSON → a clear, key-prefixed error BEFORE
    // any exchange. The classify + read happened (under one prompt) but no write-back.
    let backend = FakeKeychainBackend(store: [.oauth: ["rec": Data("not json".utf8)]])
    let exchanger = FakeTokenExchanger()
    #expect(throws: KeychainError.status("rec: stored OAuth record is not valid JSON")) {
      _ = try OAuthManager(backend: backend, exchanger: exchanger)
        .resolveSecret(name: "rec", reason: Self.getReason)
    }
    #expect(exchanger.receivedRecord == nil)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
  }

  @Test func getMissingRequiredFieldThrowsAsMalformed() throws {
    // A syntactically-valid JSON object missing a REQUIRED field (`refresh_token`) is
    // also rejected as malformed before exchange, key-prefixed.
    let json = """
    { "token_endpoint": "https://example.com/token", "client_id": "id" }
    """
    let backend = FakeKeychainBackend(store: [.oauth: ["rec": Data(json.utf8)]])
    let exchanger = FakeTokenExchanger()
    #expect(throws: KeychainError.status("rec: stored OAuth record is not valid JSON")) {
      _ = try OAuthManager(backend: backend, exchanger: exchanger)
        .resolveSecret(name: "rec", reason: Self.getReason)
    }
    #expect(exchanger.receivedRecord == nil)
  }

  @Test func getInvalidStoredRecordThrowsBeforeExchange() throws {
    // A record that decodes cleanly but fails validation (here a non-https
    // `token_endpoint`, e.g. one written by an older build or injected out-of-band)
    // must surface a clear, catchable, key-prefixed error BEFORE the exchanger is
    // reached — never a crash from the URL force-unwrap in `buildTokenRequest`.
    let invalid = OAuthRecord(
      tokenEndpoint: "http://insecure.example.com/token",
      clientID: "abc123",
      clientSecret: nil,
      refreshToken: "stored-refresh",
      scopes: nil
    )
    let backend = try Self.seededBackend(record: invalid)
    let exchanger = FakeTokenExchanger()
    #expect(throws: KeychainError.status("rec: token_endpoint must be an https URL")) {
      _ = try OAuthManager(backend: backend, exchanger: exchanger)
        .resolveSecret(name: "rec", reason: Self.getReason)
    }
    #expect(exchanger.receivedRecord == nil)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
  }

  @Test func getExchangerErrorPropagatesKeyPrefixed() throws {
    // The exchanger's error currency IS KeychainError; the resolver tags it with the
    // key once (the exchanger message is un-prefixed, so tagging never doubles) so
    // `get` surfaces "<name>: <provider message>". No write-back happened on failure.
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(
      error: .status("refresh token expired or revoked; re-run oauth set")
    )
    #expect(throws: KeychainError.status(
      "rec: refresh token expired or revoked; re-run oauth set"
    )) {
      _ = try OAuthManager(backend: backend, exchanger: exchanger)
        .resolveSecret(name: "rec", reason: Self.getReason)
    }
    #expect(exchanger.receivedRecord == Self.record)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
  }

  @Test func getAbortsWhenRecordReadFails() throws {
    // The record read itself failing (item vanished mid-batch) must abort the mint
    // BEFORE any decode or exchange: the error is key-prefixed, the exchanger is never
    // reached, and no write-back is attempted.
    let backend = try Self.seededBackend()
    backend.readUsingErrors["rec"] = .status("item not found")
    let exchanger = FakeTokenExchanger()
    #expect(throws: KeychainError.status("rec: item not found")) {
      _ = try OAuthManager(backend: backend, exchanger: exchanger)
        .resolveSecret(name: "rec", reason: Self.getReason)
    }
    #expect(exchanger.receivedRecord == nil)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .readUsing("rec", namespace: .oauth)
    ])
  }

  // MARK: get path — plain secret resolves and decodes under one prompt

  @Test func getPlainSecretClassifiesThenReadsAndDecodes() throws {
    // A name present only in `.secret` is classified by probing `.oauth` (miss) then
    // `.secret` (hit), read through the same session, and its decoded value returned —
    // all under the one authenticate, with no minting and no write-back.
    let backend = FakeKeychainBackend(store: [.secret: ["rec": Data("plainval".utf8)]])
    let exchanger = FakeTokenExchanger()
    let result = try OAuthManager(backend: backend, exchanger: exchanger)
      .resolveSecret(name: "rec", reason: Self.getReason)

    #expect(result.value == "plainval")
    #expect(result.refreshTokenStale == false)
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .existsUsing("rec", namespace: .secret),
      .readUsing("rec", namespace: .secret)
    ])
    #expect(exchanger.receivedRecord == nil)
  }

  @Test func getNameInNeitherStoreAbortsAfterPromptKeyPrefixed() throws {
    // The accepted trade-off of classifying AFTER the prompt: a name in neither store
    // authenticates ONCE, probes both namespaces (miss), then aborts with a
    // key-prefixed "not found" — nothing is read or minted.
    let backend = FakeKeychainBackend()
    let exchanger = FakeTokenExchanger()
    #expect(throws: KeychainError.status("rec: no secret or OAuth record found in the keychain")) {
      _ = try OAuthManager(backend: backend, exchanger: exchanger)
        .resolveSecret(name: "rec", reason: Self.getReason)
    }
    #expect(backend.calls == [
      .authenticate(reason: Self.getReason),
      .existsUsing("rec", namespace: .oauth),
      .existsUsing("rec", namespace: .secret)
    ])
  }

  // MARK: run-style mint(name:using:) mechanic

  @Test func mintWithSessionReadsThroughSessionInOauthNamespace() throws {
    // The `run`-batch entry point reads through a pre-authenticated session (readUsing,
    // no extra prompt) and, on rotation, writes back through that SAME session
    // (updateUsing) — still in `.oauth`, minting identically to the `get` path.
    let backend = try Self.seededBackend()
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at-run", refreshToken: "rotated-refresh"
    ))
    let session = try backend.authenticate(reason: "batch")
    let result = try OAuthManager(backend: backend, exchanger: exchanger).mint(name: "rec", using: session)

    #expect(result == MintResult(accessToken: "at-run", refreshTokenStale: false))
    #expect(backend.calls == [
      .authenticate(reason: "batch"),
      .readUsing("rec", namespace: .oauth),
      .updateUsing("rec", namespace: .oauth)
    ])
    #expect(exchanger.receivedRecord == Self.record)
  }
}
