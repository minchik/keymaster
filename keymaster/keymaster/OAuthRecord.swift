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
  // required fields must be non-empty and `token_endpoint` must parse as an `https`
  // URL (a plain `http` endpoint or non-URL garbage is refused so a refresh token
  // is never POSTed in the clear). Messages are un-prefixed; callers (`oauth set`)
  // prepend context as needed. Throws `KeychainError.status` on the first failure.
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
