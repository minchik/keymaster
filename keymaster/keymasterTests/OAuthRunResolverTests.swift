//
//  OAuthRunResolverTests.swift
//  keymasterTests
//
//  Unit tests for the authenticate-first namespace classification + combined run
//  resolver in OAuthManager.swift: `resolveNamespace(name:using:)` (the
//  session-aware `.oauth`/`.secret`/`nil` probe that rides the single approval) and
//  `resolveRunEnvironment(mappings:reason:)` (ONE authenticate, then per-mapping
//  classify-through-session + read-and-decode for `.secret` or mint for `.oauth`,
//  returning the injected env plus the list of stale-refresh-token keys). These
//  exercise the unified single-prompt ordering and error-tagging against
//  FakeKeychainBackend (records the ordered primitive calls + the session ids
//  presented to the session-aware primitives) and FakeTokenExchanger. They subsume
//  the old all-plain resolveEnvironment coverage and add the mixed plain+OAuth cases.
//
//  Like the other test sources, OAuthManager.swift and SecretManager.swift are
//  compiled directly into this host-less bundle via synchronized-group membership
//  exceptions, so a plain `import Foundation` reaches their symbols — no app import.
import Foundation
import Testing

struct OAuthRunResolverTests {

  // A complete, valid OAuth record used as the stored credential in the mint paths.
  private static let record = OAuthRecord(
    tokenEndpoint: "https://example.com/oauth/token",
    clientID: "id",
    clientSecret: nil,
    refreshToken: "stored-refresh",
    scopes: nil
  )

  // MARK: resolveNamespace(name:using:) — classify THROUGH the one session

  @Test func resolveNamespaceReportsSecretOnly() throws {
    // A name present only in `.secret` classifies as `.secret`. The probe checks
    // `.oauth` first (miss) then `.secret` (hit), THROUGH the session, never decrypting.
    let backend = FakeKeychainBackend(store: [.secret: ["K": Data("v".utf8)]])
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let session = try backend.authenticate(reason: "r")
    #expect(try manager.resolveNamespace(name: "K", using: session) == .secret)
    #expect(backend.calls == [
      .authenticate(reason: "r"),
      .existsUsing("K", namespace: .oauth),
      .existsUsing("K", namespace: .secret)
    ])
  }

  @Test func resolveNamespaceReportsOauthOnly() throws {
    // A name present only in `.oauth` classifies as `.oauth`, short-circuiting on the
    // first probe so `.secret` is never probed.
    let backend = FakeKeychainBackend(store: [.oauth: ["K": Data("{}".utf8)]])
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let session = try backend.authenticate(reason: "r")
    #expect(try manager.resolveNamespace(name: "K", using: session) == .oauth)
    #expect(backend.calls == [
      .authenticate(reason: "r"),
      .existsUsing("K", namespace: .oauth)
    ])
  }

  @Test func resolveNamespaceReportsNeither() throws {
    // A name in neither store classifies as `nil`, so the resolver can abort the batch
    // (after the prompt) naming the key. Both stores are probed, through the session.
    let backend = FakeKeychainBackend()
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let session = try backend.authenticate(reason: "r")
    #expect(try manager.resolveNamespace(name: "K", using: session) == nil)
    #expect(backend.calls == [
      .authenticate(reason: "r"),
      .existsUsing("K", namespace: .oauth),
      .existsUsing("K", namespace: .secret)
    ])
  }

  @Test func resolveNamespacePrefersOauthWhenPresentInBoth() throws {
    // Defensive: a name should live in exactly ONE store (the creators guard against
    // collisions), but if it somehow lands in both, `.oauth` wins by being probed
    // first — the mint path is the deliberate, richer credential. Short-circuits, so
    // the `.secret` store is not probed.
    let backend = FakeKeychainBackend(store: [
      .secret: ["K": Data("plain".utf8)],
      .oauth: ["K": Data("{}".utf8)]
    ])
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let session = try backend.authenticate(reason: "r")
    #expect(try manager.resolveNamespace(name: "K", using: session) == .oauth)
    #expect(backend.calls == [
      .authenticate(reason: "r"),
      .existsUsing("K", namespace: .oauth)
    ])
  }

  @Test func resolveNamespacePropagatesProbeError() throws {
    // Fail-closed: a transient `existsUsing` error must PROPAGATE (not collapse to
    // `nil`). Reading "absent" here would false-not-found a real item. The error on the
    // first (`.oauth`) probe surfaces; `.secret` is never probed.
    let backend = FakeKeychainBackend(store: [.oauth: ["K": Data("{}".utf8)]])
    backend.existsErrors["K"] = [.oauth: .status("keychain locked")]
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let session = try backend.authenticate(reason: "r")
    #expect(throws: KeychainError.status("keychain locked")) {
      _ = try manager.resolveNamespace(name: "K", using: session)
    }
    #expect(backend.calls == [
      .authenticate(reason: "r"),
      .existsUsing("K", namespace: .oauth)
    ])
  }

  @Test func resolveNamespacePropagatesSecondProbeError() throws {
    // Fail-closed on the SECOND probe too: the name is absent in `.oauth` (so that
    // probe returns false), but the `.secret` probe then hits a transient error. That
    // error must PROPAGATE — a regression that swallowed only the second probe's error
    // (returning `nil`) would slip past the first-probe test above.
    let backend = FakeKeychainBackend()
    backend.existsErrors["K"] = [.secret: .status("keychain locked")]
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let session = try backend.authenticate(reason: "r")
    #expect(throws: KeychainError.status("keychain locked")) {
      _ = try manager.resolveNamespace(name: "K", using: session)
    }
    #expect(backend.calls == [
      .authenticate(reason: "r"),
      .existsUsing("K", namespace: .oauth),
      .existsUsing("K", namespace: .secret)
    ])
  }

  // MARK: resolveRunEnvironment — all-plain (subsumes the old resolveEnvironment)

  @Test func resolveRunEnvironmentAllPlainAuthenticatesOnceAndClassifiesAndReadsEach() throws {
    // The all-plain batch reproduces the old behavior under the new shape: a single
    // authenticate, then each name classified (existsUsing `.oauth` miss → `.secret`
    // hit) and read (readUsing) THROUGH that one session, keyed by env name and valued
    // by the decoded secret. No stale keys.
    let backend = FakeKeychainBackend(store: [.secret: ["a": Data("1".utf8), "b": Data("2".utf8)]])
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let result = try manager.resolveRunEnvironment(
      mappings: [
        KeyMapping(env: "A", key: "a", namespace: .secret),
        KeyMapping(env: "B", key: "b", namespace: .secret)
      ],
      reason: "Run \"x\" with keychain secrets: \"a\", \"b\""
    )
    #expect(result.env == ["A": "1", "B": "2"])
    #expect(result.staleKeys == [])
    #expect(backend.calls == [
      .authenticate(reason: "Run \"x\" with keychain secrets: \"a\", \"b\""),
      .existsUsing("a", namespace: .oauth),
      .existsUsing("a", namespace: .secret),
      .readUsing("a", namespace: .secret),
      .existsUsing("b", namespace: .oauth),
      .existsUsing("b", namespace: .secret),
      .readUsing("b", namespace: .secret)
    ])
  }

  // MARK: resolveRunEnvironment — mixed plain + OAuth, one prompt

  @Test func resolveRunEnvironmentMixedBatchMintsUnderOnePrompt() throws {
    // A mixed batch resolves under EXACTLY one authenticate: the plain key is classified
    // (`.oauth` miss → `.secret` hit) and read+decoded; the OAuth key is classified
    // (`.oauth` hit, short-circuit), read, and minted — all through the same session.
    // No rotation here (reply carries no refresh_token), so no `updateUsing`.
    let backend = FakeKeychainBackend(store: [
      .secret: ["plain": Data("plainval".utf8)],
      .oauth: ["oauthkey": try Self.record.encoded()]
    ])
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "minted-at", refreshToken: nil
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    let result = try manager.resolveRunEnvironment(
      mappings: [
        KeyMapping(env: "PLAIN", key: "plain", namespace: .secret),
        KeyMapping(env: "TOKEN", key: "oauthkey", namespace: .oauth)
      ],
      reason: "batch"
    )
    #expect(result.env == ["PLAIN": "plainval", "TOKEN": "minted-at"])
    #expect(result.staleKeys == [])
    #expect(backend.calls == [
      .authenticate(reason: "batch"),
      .existsUsing("plain", namespace: .oauth),
      .existsUsing("plain", namespace: .secret),
      .readUsing("plain", namespace: .secret),
      .existsUsing("oauthkey", namespace: .oauth),
      .readUsing("oauthkey", namespace: .oauth)
    ])
    // The bytes read from `.oauth` decoded to the stored record before exchange.
    #expect(exchanger.receivedRecord == Self.record)
  }

  @Test func resolveRunEnvironmentRotatingOauthKeyCarriesOneSessionThroughout() throws {
    // The core "one approval" guarantee for `run`: every session-aware primitive in a
    // rotating OAuth batch — classify, read, and the rotation write-back — rode the
    // SAME session id returned by the single authenticate.
    let backend = FakeKeychainBackend(store: [.oauth: ["oauthkey": try Self.record.encoded()]])
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "minted-at", refreshToken: "rotated-refresh"
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    _ = try manager.resolveRunEnvironment(
      mappings: [KeyMapping(env: "TOKEN", key: "oauthkey", namespace: .oauth)],
      reason: "batch"
    )
    // existsUsing(.oauth) + readUsing(.oauth) + updateUsing(.oauth) each recorded a
    // session id; all three are the one session from authenticate.
    #expect(backend.calls == [
      .authenticate(reason: "batch"),
      .existsUsing("oauthkey", namespace: .oauth),
      .readUsing("oauthkey", namespace: .oauth),
      .updateUsing("oauthkey", namespace: .oauth)
    ])
    #expect(backend.sessionUses.count == 3)
    #expect(Set(backend.sessionUses).count == 1)
  }

  // MARK: resolveRunEnvironment — abort before exec

  @Test func resolveRunEnvironmentUnreadableKeyAbortsNamingItNotReadingTheRest() throws {
    // A failed read on an early key aborts the whole batch immediately, tagged
    // "<key>: <message>", and the later keys are never classified or read — this is
    // what lets `run` fail fast before exec naming the offending key.
    let backend = FakeKeychainBackend(store: [.secret: ["a": Data("1".utf8), "b": Data("2".utf8)]])
    backend.readUsingErrors["a"] = .status("item not found")
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    #expect(throws: KeychainError.status("a: item not found")) {
      _ = try manager.resolveRunEnvironment(
        mappings: [
          KeyMapping(env: "A", key: "a", namespace: .secret),
          KeyMapping(env: "B", key: "b", namespace: .secret)
        ],
        reason: "reason"
      )
    }
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .existsUsing("a", namespace: .oauth),
      .existsUsing("a", namespace: .secret),
      .readUsing("a", namespace: .secret)
    ])
  }

  @Test func resolveRunEnvironmentNameInNeitherStoreAbortsNamingTheKey() throws {
    // A name in neither store aborts the batch (after the one prompt) tagged with the
    // key, so the command never launches with a silently-missing secret. The later key
    // is never classified.
    let backend = FakeKeychainBackend(store: [.secret: ["b": Data("2".utf8)]])
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    #expect(throws: KeychainError.status("a: no secret or OAuth record found in the keychain")) {
      _ = try manager.resolveRunEnvironment(
        mappings: [
          KeyMapping(env: "A", key: "a", namespace: .secret),
          KeyMapping(env: "B", key: "b", namespace: .secret)
        ],
        reason: "reason"
      )
    }
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .existsUsing("a", namespace: .oauth),
      .existsUsing("a", namespace: .secret)
    ])
  }

  @Test func resolveRunEnvironmentOauthMintErrorAbortsTaggedWithKey() throws {
    // An OAuth key whose exchange fails aborts the batch, tagged with the key name —
    // the exchanger's message is un-prefixed, so tagging here never doubles. The mint
    // read happened (in `.oauth`) but no write-back, and the next key is not classified.
    let backend = FakeKeychainBackend(store: [
      .oauth: ["oauthkey": try Self.record.encoded()],
      .secret: ["plain": Data("plainval".utf8)]
    ])
    let exchanger = FakeTokenExchanger(
      error: .status("refresh token expired or revoked; re-run oauth set oauthkey")
    )
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    #expect(throws: KeychainError.status(
      "oauthkey: refresh token expired or revoked; re-run oauth set oauthkey"
    )) {
      _ = try manager.resolveRunEnvironment(
        mappings: [
          KeyMapping(env: "TOKEN", key: "oauthkey", namespace: .oauth),
          KeyMapping(env: "PLAIN", key: "plain", namespace: .secret)
        ],
        reason: "reason"
      )
    }
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .existsUsing("oauthkey", namespace: .oauth),
      .readUsing("oauthkey", namespace: .oauth)
    ])
  }

  @Test func resolveRunEnvironmentNulSecretAbortsKeyPrefixed() throws {
    // A plain secret whose bytes carry an embedded NUL cannot be a POSIX env value, so
    // the batch aborts before exec, tagged with the key (decodeEnvValue rejects it).
    let backend = FakeKeychainBackend(store: [.secret: ["a": Data("ab\0cd".utf8)]])
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    #expect(throws: KeychainError.status(
      "a: secret contains a NUL byte and cannot be used as an environment variable"
    )) {
      _ = try manager.resolveRunEnvironment(
        mappings: [KeyMapping(env: "A", key: "a", namespace: .secret)],
        reason: "reason"
      )
    }
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .existsUsing("a", namespace: .oauth),
      .existsUsing("a", namespace: .secret),
      .readUsing("a", namespace: .secret)
    ])
  }

  // MARK: resolveRunEnvironment — duplicate env name

  @Test func resolveRunEnvironmentLastWriteWinsOnDuplicateEnvName() throws {
    // Two mappings targeting the same env name: the later one wins, even across
    // namespaces — here a minted OAuth token overrides a plain secret of the same
    // env var, mirroring the dictionary's last-assignment behavior.
    let backend = FakeKeychainBackend(store: [
      .secret: ["plain": Data("plainval".utf8)],
      .oauth: ["oauthkey": try Self.record.encoded()]
    ])
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "minted-at", refreshToken: nil
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    let result = try manager.resolveRunEnvironment(
      mappings: [
        KeyMapping(env: "DUP", key: "plain", namespace: .secret),
        KeyMapping(env: "DUP", key: "oauthkey", namespace: .oauth)
      ],
      reason: "reason"
    )
    #expect(result.env == ["DUP": "minted-at"])
  }

  // MARK: resolveRunEnvironment — stale refresh token surfaced

  @Test func resolveRunEnvironmentSurfacesStaleKeyButStillInjectsToken() throws {
    // The provider rotated the refresh token but persisting it failed: the just-minted
    // access token is still injected (the run is not aborted), and the key is reported
    // in `staleKeys` so the CLI can warn the user to re-run `oauth set`.
    let backend = FakeKeychainBackend(store: [.oauth: ["oauthkey": try Self.record.encoded()]])
    backend.updateErrors["oauthkey"] = .status("update failed")
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at-still-good", refreshToken: "rotated-refresh"
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    let result = try manager.resolveRunEnvironment(
      mappings: [KeyMapping(env: "TOKEN", key: "oauthkey", namespace: .oauth)],
      reason: "reason"
    )
    #expect(result.env == ["TOKEN": "at-still-good"])
    #expect(result.staleKeys == ["oauthkey"])
    // The write-back was attempted (in `.oauth`, through the session) but failed.
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .existsUsing("oauthkey", namespace: .oauth),
      .readUsing("oauthkey", namespace: .oauth),
      .updateUsing("oauthkey", namespace: .oauth)
    ])
    // The stored record still carries the OLD refresh token.
    #expect(backend.storedData("oauthkey", namespace: .oauth) == (try Self.record.encoded()))
  }

  @Test func resolveRunEnvironmentSurfacesEveryStaleKeyInMappingOrder() throws {
    // Two rotating OAuth keys in one batch whose write-backs BOTH fail: each token is
    // still injected (the run is not aborted), and BOTH keys are reported in
    // `staleKeys` in mapping order so the CLI warns once per stale key. Guards the
    // `staleKeys` accumulation (append, not overwrite) that the single-key test cannot.
    let backend = FakeKeychainBackend(store: [.oauth: [
      "k1": try Self.record.encoded(),
      "k2": try Self.record.encoded()
    ]])
    backend.updateErrors["k1"] = .status("update failed")
    backend.updateErrors["k2"] = .status("update failed")
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "at", refreshToken: "rotated-refresh"
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    let result = try manager.resolveRunEnvironment(
      mappings: [
        KeyMapping(env: "T1", key: "k1", namespace: .oauth),
        KeyMapping(env: "T2", key: "k2", namespace: .oauth)
      ],
      reason: "reason"
    )
    #expect(result.env == ["T1": "at", "T2": "at"])
    #expect(result.staleKeys == ["k1", "k2"])
  }

  // MARK: resolveRunEnvironment — authenticate / empty batch edges

  @Test func resolveRunEnvironmentAuthenticateFailureAbortsBeforeAnyResolution() throws {
    // A cancelled/failed batch prompt aborts before any classify, read, or mint, so the
    // command never launches with a partially-resolved environment.
    let backend = FakeKeychainBackend(store: [.secret: ["a": Data("1".utf8)]])
    backend.authenticateError = .status("Authentication failed or was canceled")
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    #expect(throws: KeychainError.status("Authentication failed or was canceled")) {
      _ = try manager.resolveRunEnvironment(
        mappings: [KeyMapping(env: "A", key: "a", namespace: .secret)],
        reason: "reason"
      )
    }
    #expect(backend.calls == [.authenticate(reason: "reason")])
  }

  @Test func resolveRunEnvironmentEmptyMappingsAuthenticatesOnceAndReturnsEmpty() throws {
    // An empty batch still authenticates exactly once (the single prompt happens up
    // front, before the per-mapping loop), then returns an empty environment and no
    // stale keys — nothing else is touched.
    let backend = FakeKeychainBackend()
    let manager = OAuthManager(backend: backend, exchanger: FakeTokenExchanger())
    let result = try manager.resolveRunEnvironment(mappings: [], reason: "reason")
    #expect(result.env == [:])
    #expect(result.staleKeys == [])
    #expect(backend.calls == [.authenticate(reason: "reason")])
  }
}
