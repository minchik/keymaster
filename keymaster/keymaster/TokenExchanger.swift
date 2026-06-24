// The Foundation-only token-exchange seam plus its two pure helpers.
//
// Like SecretManager.swift, RunSupport.swift, and OAuthRecord.swift, this file is
// intentionally Foundation-only — no Security/LocalAuthentication symbols, no real
// `URLSession` *call* (only the `URLRequest`/`JSONDecoder` value types, which are
// Foundation), no `@main`/ArgumentParser — so it compiles into BOTH the app target
// (via the synchronized folder group) and the HOST-LESS `keymasterTests` bundle
// (via a synchronized-group membership exception). The request-building and
// response-parsing logic is the security-relevant surface (an `http` POST must
// never happen, a non-2xx body must be surfaced clearly, an empty `access_token`
// must be rejected), so it lives here as pure functions and is unit-tested without
// any network access. The real, networked conformer (`URLSessionTokenExchanger`)
// is app-only like `SystemKeychain`.
//
// `nonisolated` keeps these types compiling identically in the app target (which
// defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`) and the test target
// (which has no such default), matching the rest of the Foundation-only layer.
import Foundation

// The seam over the one networked syscall: exchange a stored `OAuthRecord` for a
// fresh `TokenResponse` via the RFC 6749 §6 refresh-token grant. Kept a protocol so
// `OAuthManager`'s orchestration (decode → exchange → conditional rotation
// write-back) is testable against a fake while only the real `URLSession` send
// stays manual. Failures are thrown as `KeychainError` (the single error currency),
// un-prefixed; callers (`get`/`run`) prepend `"<key>: "` as today.
nonisolated protocol TokenExchanger {
  func exchange(_ record: OAuthRecord) throws -> TokenResponse
}

// Build the form-encoded refresh-token POST (RFC 6749 §6). `grant_type`,
// `refresh_token`, and `client_id` are always sent; `client_secret` and `scope`
// (← record `scopes`) only when present and non-empty (an empty/absent
// `client_secret` denotes a public client). Every value is percent-encoded against
// the RFC 3986 unreserved set, so reserved characters in a secret or scope cannot
// corrupt the body. The caller passes a record that has already been `validate()`d
// (https URL guaranteed parseable), so the `URL` initializer cannot fail here.
nonisolated func buildTokenRequest(_ record: OAuthRecord) -> URLRequest {
  // Safe: `record.validate()` (run at `oauth set` time before storage) guarantees
  // `tokenEndpoint` parses as an https URL, so this never returns nil for a stored
  // record.
  var request = URLRequest(url: URL(string: record.tokenEndpoint)!)
  request.httpMethod = "POST"
  request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
  request.setValue("application/json", forHTTPHeaderField: "Accept")

  var pairs = [
    ("grant_type", "refresh_token"),
    ("refresh_token", record.refreshToken),
    ("client_id", record.clientID)
  ]
  if let secret = record.clientSecret, !secret.isEmpty {
    pairs.append(("client_secret", secret))
  }
  if let scopes = record.scopes, !scopes.isEmpty {
    pairs.append(("scope", scopes))
  }

  let body = pairs
    .map { "\(formEncode($0.0))=\(formEncode($0.1))" }
    .joined(separator: "&")
  request.httpBody = Data(body.utf8)
  return request
}

// Percent-encode a form value against the RFC 3986 unreserved set
// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`). Everything else — including spaces
// (→ `%20`), `&`, `=`, `+`, `/` — is escaped, so a refresh token or scope string
// with reserved characters cannot break out of its field. `addingPercentEncoding`
// only returns nil for invalid UTF-16; the fallback keeps the function total.
private nonisolated func formEncode(_ value: String) -> String {
  var allowed = CharacterSet.alphanumerics
  allowed.insert(charactersIn: "-._~")
  return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
}

// Turn an HTTP `(body, statusCode)` reply into a `TokenResponse` or a clear
// `KeychainError`. Pure (no network), so it is unit-tested directly.
//
//   2xx     → decode `TokenResponse`; require a non-empty `access_token`, else
//             `.status("token endpoint returned no access_token")`. A 2xx body we
//             cannot turn into a usable token (non-JSON, or missing the required
//             field) maps to the same "no access_token" message — the meaningful
//             problem is that the success reply carried no token. A token carrying a
//             NUL byte is rejected too (it cannot be safely injected into the exec'd
//             command's environment).
//   non-2xx → surface the RFC 6749 §5.2 error body `{ error, error_description? }`:
//             `invalid_grant` is special-cased to a re-auth hint; any other code is
//             surfaced as `"<error>: <description>"` (or just `"<error>"`). A
//             non-2xx whose body is not a recognizable RFC error maps to
//             `"token request failed: HTTP <status>"`.
//
// Messages are un-prefixed; callers prepend `"<key>: "`.
nonisolated func parseTokenResponse(data: Data, status: Int) throws -> TokenResponse {
  let decoder = JSONDecoder()

  if (200..<300).contains(status) {
    guard let response = try? decoder.decode(TokenResponse.self, from: data),
          !response.accessToken.isEmpty else {
      throw KeychainError.status("token endpoint returned no access_token")
    }
    // An access token is RFC 6749 VSCHAR (visible ASCII); a NUL is non-conformant and,
    // when `run` injects it into the `execve` envp via `strdup`, would silently truncate
    // the C string at the first NUL rather than raise a Swift error — exactly what
    // `decodeEnvValue` guards for plain secrets. Reject it here, the single choke point
    // every minted token passes through, so both `get` and `run` surface a clean error
    // instead.
    guard !response.accessToken.contains("\0") else {
      throw KeychainError.status("token endpoint returned an access_token containing a NUL byte")
    }
    // Reject a NUL in the rotated refresh_token too, symmetrically. It would
    // otherwise be persisted by `OAuthManager`'s rotation write-back, which calls
    // `backend.update` directly — bypassing `storeSecret`'s write-time NUL guard —
    // and would survive that guard anyway, because `JSONSerialization` encodes
    // U+0000 as the `\u0000` escape rather than a literal `0x00` byte. The result
    // would be a silently bricked stored credential that re-decodes with the NUL
    // intact and is re-sent as `%00` on every later mint. Catching it here, the one
    // choke point all minted/rotated tokens pass through, keeps the stored record clean.
    if let refresh = response.refreshToken, refresh.contains("\0") {
      throw KeychainError.status("token endpoint returned a refresh_token containing a NUL byte")
    }
    return response
  }

  if let rfcError = try? decoder.decode(TokenErrorResponse.self, from: data),
     !rfcError.error.isEmpty {
    if rfcError.error == "invalid_grant" {
      throw KeychainError.status("refresh token expired or revoked; re-run oauth set")
    }
    if let description = rfcError.errorDescription, !description.isEmpty {
      throw KeychainError.status("\(rfcError.error): \(description)")
    }
    throw KeychainError.status(rfcError.error)
  }

  throw KeychainError.status("token request failed: HTTP \(status)")
}

// The RFC 6749 §5.2 error reply. Only `error` is required; `error_description` is an
// optional human-readable elaboration. Other RFC fields (`error_uri`) are ignored
// by the tolerant decode. Internal to the parse path.
nonisolated struct TokenErrorResponse: Decodable {
  let error: String
  let errorDescription: String?

  enum CodingKeys: String, CodingKey {
    case error
    case errorDescription = "error_description"
  }
}
