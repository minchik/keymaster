//
//  TokenExchangerTests.swift
//  keymasterTests
//
//  Unit tests for the Foundation-only token-exchange helpers in
//  TokenExchanger.swift: `buildTokenRequest` (RFC 6749 §6 form-encoded POST —
//  required params always, optional params only when present, percent-encoded
//  values, correct method/headers/URL) and `parseTokenResponse` (2xx decode +
//  non-empty `access_token`, rotation field passthrough, RFC 6749 §5.2 error
//  surfacing incl. the `invalid_grant` re-auth hint, empty/missing token, and
//  non-JSON bodies). Both are pure (no network), so the file is compiled directly
//  into this host-less bundle via a synchronized-group membership exception and a
//  plain `import Foundation` reaches its symbols — no app import.
import Foundation
import Testing

struct TokenExchangerTests {

  // A complete, valid record (https endpoint, secret + scopes present) used as the
  // baseline; helpers below trim it to exercise the optional-omission paths.
  private static let fullRecord = OAuthRecord(
    tokenEndpoint: "https://example.com/oauth/token",
    clientID: "abc123",
    clientSecret: "shhh",
    refreshToken: "r3fr3sh",
    scopes: "read write"
  )

  // Decode the form-encoded body back into [name: value], URL-decoding each value,
  // so assertions read against logical params rather than a brittle exact string.
  private func formParams(_ request: URLRequest) -> [String: String] {
    let body = String(data: request.httpBody ?? Data(), encoding: .utf8) ?? ""
    var params: [String: String] = [:]
    for pair in body.split(separator: "&") {
      let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
      let name = String(parts[0]).removingPercentEncoding ?? String(parts[0])
      let value = parts.count > 1 ? (String(parts[1]).removingPercentEncoding ?? String(parts[1])) : ""
      params[name] = value
    }
    return params
  }

  // MARK: buildTokenRequest

  @Test func requestUsesPostToTheEndpointWithFormContentType() {
    let request = buildTokenRequest(Self.fullRecord)
    #expect(request.httpMethod == "POST")
    #expect(request.url?.absoluteString == "https://example.com/oauth/token")
    #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded")
  }

  @Test func requestAlwaysSendsGrantTypeRefreshTokenAndClientID() {
    let params = formParams(buildTokenRequest(Self.fullRecord))
    #expect(params["grant_type"] == "refresh_token")
    #expect(params["refresh_token"] == "r3fr3sh")
    #expect(params["client_id"] == "abc123")
  }

  @Test func requestSendsClientSecretAndScopeWhenPresent() {
    let params = formParams(buildTokenRequest(Self.fullRecord))
    #expect(params["client_secret"] == "shhh")
    #expect(params["scope"] == "read write")
  }

  @Test func requestOmitsClientSecretAndScopeWhenAbsent() {
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    let params = formParams(buildTokenRequest(record))
    #expect(params["client_secret"] == nil)
    #expect(params["scope"] == nil)
    // The required trio is still present.
    #expect(params["grant_type"] == "refresh_token")
    #expect(params["refresh_token"] == "tok")
    #expect(params["client_id"] == "id")
  }

  @Test func requestOmitsEmptyClientSecretAndScope() {
    // Empty (not just absent) optionals are treated as "public client" / "no scope".
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: "",
      refreshToken: "tok",
      scopes: ""
    )
    let params = formParams(buildTokenRequest(record))
    #expect(params["client_secret"] == nil)
    #expect(params["scope"] == nil)
  }

  @Test func requestPercentEncodesReservedCharactersInValues() {
    // A refresh token / secret with reserved characters must not break out of its
    // field: the raw body is escaped, and the decoded values round-trip exactly.
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id&special=1",
      clientSecret: "a b+c/d",
      refreshToken: "tok=en&more",
      scopes: "read write"
    )
    let request = buildTokenRequest(record)
    let rawBody = String(data: request.httpBody ?? Data(), encoding: .utf8) ?? ""
    // The reserved characters are escaped in the wire body...
    #expect(!rawBody.contains("tok=en&more"))
    #expect(rawBody.contains("tok%3Den%26more"))
    #expect(rawBody.contains("a%20b%2Bc%2Fd"))  // space, +, / all escaped
    // ...and decode back to the originals.
    let params = formParams(request)
    #expect(params["refresh_token"] == "tok=en&more")
    #expect(params["client_secret"] == "a b+c/d")
    #expect(params["client_id"] == "id&special=1")
    #expect(params["scope"] == "read write")
  }

  // MARK: parseTokenResponse — success

  @Test func parseDecodesSuccessfulResponse() throws {
    // The extra token_type/expires_in keys are coverage that unknown keys are ignored.
    let json = """
    { "access_token": "at-123", "token_type": "Bearer", "expires_in": 3600 }
    """
    let response = try parseTokenResponse(data: Data(json.utf8), status: 200)
    #expect(response.accessToken == "at-123")
    #expect(response.refreshToken == nil)
  }

  @Test func parseAcceptsNonConformantStringExpiresIn() throws {
    // Regression: a provider returning `expires_in` as a quoted string used to make
    // the whole TokenResponse decode throw, surfacing a misleading "no access_token"
    // even though a valid access_token was present. With expires_in no longer modelled,
    // JSONDecoder drops the unknown key and minting succeeds.
    let json = """
    { "access_token": "at", "token_type": "Bearer", "expires_in": "3600" }
    """
    let response = try parseTokenResponse(data: Data(json.utf8), status: 200)
    #expect(response.accessToken == "at")
    #expect(response.refreshToken == nil)
  }

  @Test func parsePassesThroughRotatedRefreshToken() throws {
    // A present `refresh_token` in the reply is surfaced so OAuthManager can detect
    // rotation and write it back.
    let json = """
    { "access_token": "at", "refresh_token": "rotated" }
    """
    let response = try parseTokenResponse(data: Data(json.utf8), status: 200)
    #expect(response.accessToken == "at")
    #expect(response.refreshToken == "rotated")
  }

  @Test func parseAcceptsAny2xxStatus() throws {
    let json = """
    { "access_token": "at" }
    """
    let response = try parseTokenResponse(data: Data(json.utf8), status: 201)
    #expect(response.accessToken == "at")
  }

  // MARK: parseTokenResponse — empty / missing access_token

  @Test func parseRejectsEmptyAccessToken() {
    let json = """
    { "access_token": "" }
    """
    #expect(throws: KeychainError.status("token endpoint returned no access_token")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 200)
    }
  }

  @Test func parseRejectsSuccessBodyWithoutAccessToken() {
    // A 2xx whose JSON lacks the required field is unusable: same "no access_token".
    let json = """
    { "token_type": "Bearer" }
    """
    #expect(throws: KeychainError.status("token endpoint returned no access_token")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 200)
    }
  }

  @Test func parseRejectsNonJSONSuccessBody() {
    // A 2xx with a non-JSON body carried no usable token either.
    let body = "<html>not json</html>"
    #expect(throws: KeychainError.status("token endpoint returned no access_token")) {
      _ = try parseTokenResponse(data: Data(body.utf8), status: 200)
    }
  }

  @Test func parseRejectsAccessTokenContainingNul() {
    // A NUL in the access token is non-conformant (RFC 6749 access tokens are visible
    // ASCII) and would abort Process.run() uncatchably if `run` injected it into a
    // child's environment; reject it at parse — the single choke point every minted
    // token passes through — so both `get` and `run` surface a clean error. The escape
    // is built from a backslash code point so this source carries no raw NUL; the JSON
    // text shows the escape as backslash-u-0000, which JSONDecoder turns into a NUL.
    let backslash = String(UnicodeScalar(UInt8(92)))
    let json = "{ \"access_token\": \"a\(backslash)u0000b\" }"
    #expect(throws: KeychainError.status("token endpoint returned an access_token containing a NUL byte")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 200)
    }
  }

  // MARK: parseTokenResponse — error bodies

  @Test func parseSpecialCasesInvalidGrant() {
    let json = """
    { "error": "invalid_grant", "error_description": "Token has been expired or revoked." }
    """
    #expect(throws: KeychainError.status("refresh token expired or revoked; re-run oauth set")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 400)
    }
  }

  @Test func parseSurfacesGenericProviderErrorWithDescription() {
    let json = """
    { "error": "invalid_client", "error_description": "client authentication failed" }
    """
    #expect(throws: KeychainError.status("invalid_client: client authentication failed")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 401)
    }
  }

  @Test func parseSurfacesGenericProviderErrorWithoutDescription() {
    let json = """
    { "error": "invalid_request" }
    """
    #expect(throws: KeychainError.status("invalid_request")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 400)
    }
  }

  @Test func parseFallsBackForNonJSONErrorBody() {
    // A non-2xx whose body is not a recognizable RFC error → a clear status fallback.
    let body = "Internal Server Error"
    #expect(throws: KeychainError.status("token request failed: HTTP 500")) {
      _ = try parseTokenResponse(data: Data(body.utf8), status: 500)
    }
  }

  @Test func parseFallsBackForErrorBodyMissingErrorField() {
    // Valid JSON but without the required `error` field is not an RFC error reply.
    let json = """
    { "message": "something went wrong" }
    """
    #expect(throws: KeychainError.status("token request failed: HTTP 503")) {
      _ = try parseTokenResponse(data: Data(json.utf8), status: 503)
    }
  }
}
