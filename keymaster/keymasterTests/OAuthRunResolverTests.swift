//
//  OAuthRunResolverTests.swift
//  keymasterTests
//
//  Unit tests for the authenticate-first combined run resolver in OAuthManager.swift:
//  `resolveRunEnvironment(mappings:reason:)` (ONE authenticate, then per-mapping
//  read-and-decode for `.secret` or mint for `.oauth` — each mapping carries its
//  explicit namespace, so there is no classify probe — returning the injected env plus
//  the list of stale-refresh-token keys). These exercise the unified single-prompt
//  ordering and error-tagging against FakeKeychainBackend (records the ordered
//  primitive calls + the session ids presented to the session-aware primitives) and
//  FakeTokenExchanger. They subsume the old all-plain resolveEnvironment coverage and
//  add the mixed plain+OAuth cases.
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

  // MARK: resolveRunEnvironment — all-plain (subsumes the old resolveEnvironment)

  @Test func resolveRunEnvironmentAllPlainAuthenticatesOnceAndReadsEach() throws {
    // The all-plain batch reproduces the old behavior under the new shape: a single
    // authenticate, then each `.secret` name read (readUsing) THROUGH that one session
    // (no classify probe — the namespace is explicit), keyed by env name and valued by
    // the decoded secret. No stale keys.
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
      .readUsing("a", namespace: .secret),
      .readUsing("b", namespace: .secret)
    ])
  }

  // MARK: resolveRunEnvironment — mixed plain + OAuth, one prompt

  @Test func resolveRunEnvironmentMixedBatchMintsUnderOnePrompt() throws {
    // A mixed batch resolves under EXACTLY one authenticate: the `.secret` key is
    // read+decoded; the `.oauth` key is read and minted — both straight in their explicit
    // namespace through the same session, with no classify probe. No rotation here (reply
    // carries no refresh_token), so no `updateUsing`.
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
      .readUsing("plain", namespace: .secret),
      .readUsing("oauthkey", namespace: .oauth)
    ])
    // The bytes read from `.oauth` decoded to the stored record before exchange.
    #expect(exchanger.receivedRecord == Self.record)
  }

  @Test func resolveRunEnvironmentRotatingOauthKeyCarriesOneSessionThroughout() throws {
    // The core "one approval" guarantee for `run`: every session-aware primitive in a
    // rotating OAuth batch — the read and the rotation write-back — rode the SAME session
    // id returned by the single authenticate.
    let backend = FakeKeychainBackend(store: [.oauth: ["oauthkey": try Self.record.encoded()]])
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "minted-at", refreshToken: "rotated-refresh"
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    _ = try manager.resolveRunEnvironment(
      mappings: [KeyMapping(env: "TOKEN", key: "oauthkey", namespace: .oauth)],
      reason: "batch"
    )
    // readUsing(.oauth) + updateUsing(.oauth) each recorded a session id; both are the
    // one session from authenticate.
    #expect(backend.calls == [
      .authenticate(reason: "batch"),
      .readUsing("oauthkey", namespace: .oauth),
      .updateUsing("oauthkey", namespace: .oauth)
    ])
    #expect(backend.sessionUses.count == 2)
    #expect(Set(backend.sessionUses).count == 1)
  }

  // MARK: resolveRunEnvironment — abort before exec

  @Test func resolveRunEnvironmentUnreadableKeyAbortsNamingItNotReadingTheRest() throws {
    // A failed read on an early key aborts the whole batch immediately, tagged
    // "<key>: <message>", and the later keys are never read — this is what lets `run`
    // fail fast before exec naming the offending key.
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
      .readUsing("a", namespace: .secret)
    ])
  }

  @Test func resolveRunEnvironmentMissingKeyFailsAtReadNamingTheKey() throws {
    // A name absent in its declared namespace aborts the batch (after the one prompt) at
    // the authenticated read, tagged with the key (the fake's read not-found text), so the
    // command never launches with a silently-missing secret. With classify gone the abort
    // comes from the read rather than a separate probe; the later key is never read.
    let backend = FakeKeychainBackend(store: [.secret: ["b": Data("2".utf8)]])
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
      .readUsing("a", namespace: .secret)
    ])
  }

  @Test func resolveRunEnvironmentOauthMintErrorAbortsTaggedWithKey() throws {
    // An OAuth key whose exchange fails aborts the batch, tagged with the key name —
    // the exchanger's message is un-prefixed, so tagging here never doubles. The mint
    // read happened (in `.oauth`) but no write-back, and the next key is not read.
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
    // Both mappings were resolved (the losing `.secret` read still happened); the
    // dictionary's last assignment — not a short-circuit — is what dropped the loser.
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .readUsing("plain", namespace: .secret),
      .readUsing("oauthkey", namespace: .oauth)
    ])
  }

  // MARK: resolveRunEnvironment — same name in both namespaces (the duplicate-keys payoff)

  @Test func resolveRunEnvironmentSameNameInBothNamespacesResolvesByNamespaceNotName() throws {
    // The headline payoff of cross-namespace duplicates: a plain secret AND an OAuth
    // record share the name "Dup", and one batch resolves BOTH — the `.secret` mapping
    // reads the plain value, the `.oauth` mapping mints from the record, into DISTINCT
    // env vars. This proves the switch keys off `mapping.namespace`, not the bare name:
    // a regression aliasing the second mapping to the first would yield equal values.
    let backend = FakeKeychainBackend(store: [
      .secret: ["Dup": Data("plainval".utf8)],
      .oauth: ["Dup": try Self.record.encoded()]
    ])
    let exchanger = FakeTokenExchanger(response: TokenResponse(
      accessToken: "minted-at", refreshToken: nil
    ))
    let manager = OAuthManager(backend: backend, exchanger: exchanger)
    let result = try manager.resolveRunEnvironment(
      mappings: [
        KeyMapping(env: "PLAIN", key: "Dup", namespace: .secret),
        KeyMapping(env: "TOKEN", key: "Dup", namespace: .oauth)
      ],
      reason: "reason"
    )
    #expect(result.env == ["PLAIN": "plainval", "TOKEN": "minted-at"])
    #expect(result.staleKeys == [])
    // The same name routed to two different stores under the one prompt.
    #expect(backend.calls == [
      .authenticate(reason: "reason"),
      .readUsing("Dup", namespace: .secret),
      .readUsing("Dup", namespace: .oauth)
    ])
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
    // A cancelled/failed batch prompt aborts before any read or mint, so the command
    // never launches with a partially-resolved environment.
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
