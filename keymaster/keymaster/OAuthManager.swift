// The Foundation-only OAuth minting orchestration shared by `get` and `run`.
//
// Like SecretManager.swift, RunSupport.swift, OAuthRecord.swift, and
// TokenExchanger.swift, this file is intentionally Foundation-only — no
// Security/LocalAuthentication symbols, no real network *call* (the exchange is
// behind the `TokenExchanger` protocol), no `@main`/ArgumentParser — so it
// compiles into BOTH the app target (via the synchronized folder group) and the
// HOST-LESS `keymasterTests` bundle (via a synchronized-group membership
// exception). The mint flow (read record → decode → exchange → conditional
// rotation write-back) is the security-relevant orchestration, so it lives here
// and is unit-tested against `FakeKeychainBackend` + `FakeTokenExchanger`; only
// the real `URLSession` send (`URLSessionTokenExchanger`) and the real `SecItem*`
// adapter (`SystemKeychain`) stay manual.
//
// `nonisolated` keeps these types compiling identically in the app target (which
// defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`) and the test target
// (which has no such default), matching the rest of the Foundation-only layer.
import Foundation

// The outcome of a mint: the fresh access token to inject/print, plus a flag set
// when the provider rotated the refresh token but persisting the new one failed.
// A stale write-back is NON-fatal — the access token is still valid for this run,
// so the CLI warns on stderr and proceeds rather than aborting.
nonisolated struct MintResult: Equatable {
  let accessToken: String
  let refreshTokenStale: Bool
}

// Mints fresh access tokens from stored OAuth records and resolves the mixed
// plain+OAuth batches `get`/`run` inject. Mirrors `SecretManager`: the
// security-critical ordering lives here over the same `KeychainBackend` seam (so it
// is exercised against the fake), and the one networked syscall is hidden behind
// the `TokenExchanger` seam. Every OAuth store access targets the `.oauth`
// namespace, so an OAuth record can never be confused with a plain secret.
//
// SINGLE PROMPT, classify-after-prompt: `get` and `run` funnel through the one
// authenticate-first `resolve` core. It calls `authenticate(reason:)` exactly once
// (the single Touch ID prompt) and then does everything else THROUGH that session —
// the namespace classify (`exists(using:)`), the record/secret read (`read(using:)`),
// and the rotation write-back (`update(using:)`) — so all three ride the one
// approval instead of prompting separately. Classifying AFTER the prompt is the
// intended security property, not a cost: keymaster never discloses whether a name
// exists — in either namespace — without a biometric approval, so unauthenticated
// key-existence probing is impossible. The visible consequence is deliberate and by
// design: a name in NEITHER store aborts AFTER the prompt (you are asked once, then
// told "not found, nothing ran") rather than leaking its absence before the prompt.
nonisolated struct OAuthManager {
  let backend: KeychainBackend
  let exchanger: TokenExchanger

  // The shared authenticate-first core for BOTH `get` and `run`: prompt ONCE, then
  // resolve every mapping under that single session — `.secret` keys are read+decoded,
  // `.oauth` keys are minted into a fresh access token (rotation write-back included).
  // `reason` names every key and (for `run`) the program. Last write wins when two
  // mappings target the same env name. Any classify/read/mint/decode failure is
  // re-thrown tagged "<key>: <message>" so the caller aborts before printing/exec
  // naming the offending key (the underlying messages are un-prefixed, so tagging here
  // never doubles); a name in neither store throws the same way. The returned
  // `staleKeys` lists OAuth keys whose rotated refresh token failed to persist —
  // non-fatal, so the CLI warns and proceeds rather than aborting.
  private func resolve(
    _ mappings: [KeyMapping],
    reason: String
  ) throws -> (env: [String: String], staleKeys: [String]) {
    let session = try backend.authenticate(reason: reason)
    var injected: [String: String] = [:]
    var staleKeys: [String] = []
    for mapping in mappings {
      do {
        switch try resolveNamespace(name: mapping.key, using: session) {
        case .secret:
          let data = try backend.read(key: mapping.key, using: session, namespace: .secret)
          injected[mapping.env] = try decodeEnvValue(data)
        case .oauth:
          let result = try mint(name: mapping.key, using: session)
          injected[mapping.env] = result.accessToken
          if result.refreshTokenStale {
            staleKeys.append(mapping.key)
          }
        case nil:
          throw KeychainError.status("no secret or OAuth record found in the keychain")
        }
      } catch let error as KeychainError {
        throw KeychainError.status("\(mapping.key): \(error.message)")
      }
    }
    return (injected, staleKeys)
  }

  // The `run` wrapper: resolve a batch of `--key` mappings into an [env: value]
  // dictionary under the single prompt. Replaces the old pre-classified
  // `resolveRunEnvironment(classified:)` — classification now happens inside the core
  // (after the prompt), so the CLI no longer probes namespaces before authenticating.
  func resolveRunEnvironment(
    mappings: [KeyMapping],
    reason: String
  ) throws -> (env: [String: String], staleKeys: [String]) {
    try resolve(mappings, reason: reason)
  }

  // The `get` wrapper: resolve a SINGLE name under the single prompt and return its
  // value (a plain secret as-is, or a freshly-minted access token for an OAuth record).
  // `refreshTokenStale` is true only when the name was an OAuth record whose rotated
  // refresh token failed to persist, so the CLI can warn (the access token is still
  // returned). Errors are key-prefixed ("<name>: <message>") exactly like the `run`
  // path, so the CLI surfaces them verbatim without re-prefixing.
  func resolveSecret(
    name: String,
    reason: String
  ) throws -> (value: String, refreshTokenStale: Bool) {
    let (env, staleKeys) = try resolve([KeyMapping(env: name, key: name)], reason: reason)
    // `resolve` throws unless it injected a value for the one mapping, so `env[name]`
    // is present on success; the `?? ""` only guards an unreachable nil.
    return (env[name] ?? "", staleKeys.contains(name))
  }

  // Classify a name's store THROUGH the batch's pre-authenticated session, so the
  // probe rides the single Touch ID approval (no extra prompt) instead of evaluating
  // the item's ACL on its own. Running the classify under the approval is the
  // intended guarantee, not just a prompt-saving convenience: existence is never
  // disclosed without a biometric approval first, so a caller cannot probe whether a
  // name is stored. `get`/`run` use this to decide whether to mint (`.oauth`) or read
  // a plain secret (`.secret`) — and abort cleanly (after the one prompt) when the
  // name is in neither (`nil`).
  //
  // Each name should live in exactly ONE store (the two creators guard against
  // cross-namespace collisions). Should a name defensively exist in both, `.oauth`
  // wins by probing it first: an OAuth record is the deliberate, richer credential,
  // so the mint path takes precedence over a stray plain secret of the same name.
  //
  // Fail-closed: `exists(using:)` throws when presence could not be determined (a
  // transient keychain error), and that error propagates here rather than collapsing
  // to `nil`. The CLI surfaces it key-prefixed, so an undeterminable state aborts
  // cleanly instead of a misleading "no secret or OAuth record found".
  func resolveNamespace(name: String, using session: AuthSession) throws -> KeychainNamespace? {
    if try backend.exists(key: name, using: session, namespace: .oauth) { return .oauth }
    if try backend.exists(key: name, using: session, namespace: .secret) { return .secret }
    return nil
  }

  // Read an OAuth record through the batch's pre-authenticated session (no extra
  // prompt — it unlocks under the single `get`/`run` Touch ID prompt) and mint a
  // fresh access token. Used by the shared resolver for `.oauth` mappings.
  func mint(name: String, using session: AuthSession) throws -> MintResult {
    let data = try backend.read(key: name, using: session, namespace: .oauth)
    return try finish(name: name, recordData: data, session: session)
  }

  // The shared finisher once the record bytes are in hand: decode → exchange →
  // conditional rotation write-back → return.
  //
  // - A record that is not valid JSON (or is missing a required field) throws an
  //   un-prefixed `.status` — the caller (`resolve`) prepends the key.
  // - The exchanger's errors propagate verbatim (also un-prefixed).
  // - If the reply carries a NEW, non-empty `refresh_token` that DIFFERS from the
  //   stored one, the updated record is written back in place via `update(using:)`,
  //   riding the same session that authorized the read — atomic and prompt-free. A
  //   write-back failure is swallowed and surfaced as `refreshTokenStale = true`
  //   rather than thrown, because the just-minted access token is still good.
  private func finish(name: String, recordData: Data, session: AuthSession) throws -> MintResult {
    let record: OAuthRecord
    do {
      record = try JSONDecoder().decode(OAuthRecord.self, from: recordData)
    } catch {
      throw KeychainError.status("stored OAuth record is not valid JSON")
    }
    // Defense-in-depth: re-validate the decoded record before use. `oauth set`
    // validates at write time, but a record written by an older build or injected
    // out-of-band could carry an empty or non-https `token_endpoint`, which would
    // otherwise crash `buildTokenRequest`'s URL force-unwrap. Re-validating turns
    // that latent trap into a clear, catchable error and keeps the mint path total.
    try record.validate()

    let response = try exchanger.exchange(record)

    // Rotate only when the provider returned a genuinely different, non-empty
    // refresh token — persisting an empty or unchanged token would be pointless
    // (and an empty one would brick the credential).
    guard let rotated = response.refreshToken,
          !rotated.isEmpty,
          rotated != record.refreshToken else {
      return MintResult(accessToken: response.accessToken, refreshTokenStale: false)
    }

    // Lossless write-back: edit `refresh_token` IN the raw stored JSON object
    // rather than re-encoding the 5-field model, so any extra/unknown keys an
    // out-of-band write stored survive the rotation. `recordData` is guaranteed a
    // JSON object — it already decoded as `OAuthRecord` above. NOTE:
    // `JSONSerialization` has no `.withoutEscapingSlashes`, so the rotated bytes
    // escape the always-https `token_endpoint` slashes (`https:\/\/…`); the record
    // still decodes identically — true byte-canonical form is only guaranteed at
    // `oauth set` time. A parse/re-serialize failure (defensive) is treated like a
    // write-back failure below rather than aborting the otherwise-good mint.
    let payload: Data
    do {
      guard var object = try JSONSerialization.jsonObject(with: recordData) as? [String: Any] else {
        return MintResult(accessToken: response.accessToken, refreshTokenStale: true)
      }
      object["refresh_token"] = rotated
      payload = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    } catch {
      return MintResult(accessToken: response.accessToken, refreshTokenStale: true)
    }
    do {
      try backend.update(key: name, secret: payload, using: session, namespace: .oauth)
      return MintResult(accessToken: response.accessToken, refreshTokenStale: false)
    } catch {
      // Non-fatal: the access token is still valid for this run; flag the stale
      // refresh token so the CLI can warn the user to re-run `oauth set`.
      return MintResult(accessToken: response.accessToken, refreshTokenStale: true)
    }
  }
}
