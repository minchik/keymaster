// The Foundation-only OAuth data model: the stored credential record and the
// token-endpoint reply.
//
// Like SecretManager.swift and RunSupport.swift, this file is intentionally
// Foundation-only — no Security/LocalAuthentication/URLSession-syscall types in
// any signature, no `@main`/ArgumentParser symbols — so it compiles into BOTH the
// app target (via the synchronized folder group) and the HOST-LESS
// `keymasterTests` bundle (via a synchronized-group membership exception). The
// `Codable` decode/validate logic is the security-relevant surface (a malformed
// or non-https record must be rejected before any token is minted), so it lives
// here behind plain `import Foundation` and is unit-tested without any Keychain
// or network access.
//
// `nonisolated` keeps these types compiling identically in the app target (which
// defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`) and the test target
// (which has no such default), matching the rest of the Foundation-only layer.
import Foundation

// The full OAuth credential, stored as canonical JSON in the item's secret data
// under `dev.mnck.oauth.<name>`. Decode is deliberately TOLERANT: unknown keys are
// ignored (the synthesized `Decodable` does this by default), the optional fields
// may be absent, but a missing required field (`token_endpoint`/`client_id`/
// `refresh_token`) throws. Field *content* is not checked on decode — that is
// `validate()`'s job, kept separate so the `oauth set` creator can surface a clear
// per-field message before storing.
nonisolated struct OAuthRecord: Codable, Equatable {
  let tokenEndpoint: String   // required, must be an https URL
  let clientID: String        // required
  let clientSecret: String?   // optional (empty/absent = public client)
  let refreshToken: String    // required
  let scopes: String?         // optional, space-delimited per RFC 6749 §3.3

  enum CodingKeys: String, CodingKey {
    case tokenEndpoint = "token_endpoint"
    case clientID = "client_id"
    case clientSecret = "client_secret"
    case refreshToken = "refresh_token"
    case scopes
  }

  // Serialize to canonical JSON for storage. `.sortedKeys` makes the bytes
  // deterministic (so a rotation write-back only differs when the data actually
  // changed) and `.withoutEscapingSlashes` keeps the `token_endpoint` URL readable
  // rather than `\/`-escaped. Any encoding failure maps to the shared
  // `KeychainError` currency so the CLI's `catch let error as KeychainError`
  // glue handles it unchanged.
  func encoded() throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do {
      return try encoder.encode(self)
    } catch {
      throw KeychainError.status("could not encode OAuth record: \(error.localizedDescription)")
    }
  }

  // Reject a record that could not produce a working token request: the three
  // required fields must be non-empty, no field may contain an embedded NUL byte,
  // and `token_endpoint` must parse as an `https` URL (a plain `http` endpoint or
  // non-URL garbage is refused so a refresh token is never POSTed in the clear).
  // Messages are un-prefixed; callers (`oauth set`) prepend context as needed.
  // Throws `KeychainError.status` on the first failure.
  func validate() throws {
    guard !tokenEndpoint.isEmpty else {
      throw KeychainError.status("token_endpoint is required")
    }
    guard !clientID.isEmpty else {
      throw KeychainError.status("client_id is required")
    }
    guard !refreshToken.isEmpty else {
      throw KeychainError.status("refresh_token is required")
    }
    // Reject an embedded NUL in ANY field, required or optional. `oauth set` re-encodes
    // the record with `JSONEncoder`, which escapes U+0000 to a six-character text escape
    // rather than a literal `0x00` byte — so `storeSecret`'s write-time
    // `secret.contains(0)` guard never sees it, and a NUL-bearing field would be
    // persisted, re-decode with the NUL intact, and be re-sent (e.g. `refresh_token=…%00…`)
    // on every later mint: a silently bricked credential. This is the same escaped-NUL
    // bypass `parseTokenResponse` already rejects for the rotated refresh token; closing
    // it here covers the creation path.
    let fields: [(label: String, value: String?)] = [
      ("token_endpoint", tokenEndpoint),
      ("client_id", clientID),
      ("client_secret", clientSecret),
      ("refresh_token", refreshToken),
      ("scopes", scopes)
    ]
    for field in fields where field.value?.contains("\0") == true {
      throw KeychainError.status("\(field.label) must not contain a NUL byte")
    }
    guard let url = URL(string: tokenEndpoint),
          url.scheme?.lowercased() == "https",
          let host = url.host, !host.isEmpty else {
      throw KeychainError.status("token_endpoint must be an https URL")
    }
  }
}

// The token-endpoint reply (RFC 6749 §5.1). Only `access_token` is required;
// any other keys (e.g. `token_type`/`expires_in`) are ignored — keymaster never
// caches a minted access token, so the lifetime/type fields are not modelled,
// and JSONDecoder dropping unknown keys means a non-conformant value there can't
// break the decode. A present `refresh_token` signals rotation: when it differs
// from the stored one, `OAuthManager` writes the updated record back.
nonisolated struct TokenResponse: Codable {
  let accessToken: String     // required, must be non-empty (checked by the parser)
  let refreshToken: String?   // present + differing → rotation write-back

  enum CodingKeys: String, CodingKey {
    case accessToken = "access_token"
    case refreshToken = "refresh_token"
  }
}

extension TokenResponse {
  // Custom decode so a present-but-wrong-typed `refresh_token` (e.g. a JSON number
  // or bool — non-conformant, since RFC 6749 §5.1 requires a string) is tolerated
  // as "no rotation" (nil) rather than failing the whole decode. The synthesized
  // `Decodable` would `decodeIfPresent(String.self, …)` and THROW `typeMismatch` on
  // such a value, which `parseTokenResponse`'s `try?` then swallows into the
  // misleading "no access_token" error — even though a valid `access_token` was
  // present. This is the same hazard the unmodelled `token_type`/`expires_in` keys
  // avoid by being dropped; `refresh_token` is modelled (rotation needs it), so it
  // gets explicit tolerant handling here instead. `access_token` stays strictly
  // required: a missing/non-string value is a real decode failure.
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    accessToken = try container.decode(String.self, forKey: .accessToken)
    refreshToken = try? container.decodeIfPresent(String.self, forKey: .refreshToken)
  }
}
