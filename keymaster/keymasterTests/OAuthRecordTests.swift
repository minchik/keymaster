//
//  OAuthRecordTests.swift
//  keymasterTests
//
//  Unit tests for the Foundation-only OAuth data model in OAuthRecord.swift: the
//  tolerant `Codable` decode (unknown keys ignored, optionals absent, required
//  fields enforced), `validate()` (non-empty required fields + https-only
//  endpoint), and the encode→decode round-trip. The model file is compiled
//  directly into this host-less bundle via a synchronized-group membership
//  exception, so a plain `import Foundation` reaches its symbols — no app import.
import Foundation
import Testing

struct OAuthRecordTests {

  // A complete, valid record JSON used as the baseline for the decode/validate
  // tests. Helpers below mutate or trim it.
  private static let fullJSON = """
  {
    "token_endpoint": "https://example.com/oauth/token",
    "client_id": "abc123",
    "client_secret": "shhh",
    "refresh_token": "r3fr3sh",
    "scopes": "read write"
  }
  """

  private func decode(_ json: String) throws -> OAuthRecord {
    try JSONDecoder().decode(OAuthRecord.self, from: Data(json.utf8))
  }

  // MARK: OAuthRecord decode

  @Test func decodesAllFields() throws {
    let record = try decode(Self.fullJSON)
    #expect(record.tokenEndpoint == "https://example.com/oauth/token")
    #expect(record.clientID == "abc123")
    #expect(record.clientSecret == "shhh")
    #expect(record.refreshToken == "r3fr3sh")
    #expect(record.scopes == "read write")
  }

  @Test func decodeIgnoresUnknownKeys() throws {
    // Tolerant decode: a provider may add fields we don't model; they must not
    // break decoding (leaves a clean door for a future `oauth login` record shape).
    let json = """
    {
      "token_endpoint": "https://example.com/token",
      "client_id": "id",
      "refresh_token": "tok",
      "issued_at": 1700000000,
      "extra": { "nested": true }
    }
    """
    let record = try decode(json)
    #expect(record.tokenEndpoint == "https://example.com/token")
    #expect(record.clientID == "id")
    #expect(record.refreshToken == "tok")
  }

  @Test func decodeAllowsAbsentOptionals() throws {
    // client_secret (public client) and scopes are optional and may be omitted.
    let json = """
    {
      "token_endpoint": "https://example.com/token",
      "client_id": "id",
      "refresh_token": "tok"
    }
    """
    let record = try decode(json)
    #expect(record.clientSecret == nil)
    #expect(record.scopes == nil)
  }

  @Test func decodeThrowsOnMissingTokenEndpoint() {
    let json = """
    { "client_id": "id", "refresh_token": "tok" }
    """
    #expect(throws: (any Error).self) {
      _ = try self.decode(json)
    }
  }

  @Test func decodeThrowsOnMissingClientID() {
    let json = """
    { "token_endpoint": "https://example.com/token", "refresh_token": "tok" }
    """
    #expect(throws: (any Error).self) {
      _ = try self.decode(json)
    }
  }

  @Test func decodeThrowsOnMissingRefreshToken() {
    let json = """
    { "token_endpoint": "https://example.com/token", "client_id": "id" }
    """
    #expect(throws: (any Error).self) {
      _ = try self.decode(json)
    }
  }

  @Test func decodeThrowsOnNonJSON() {
    #expect(throws: (any Error).self) {
      _ = try self.decode("not json at all")
    }
  }

  // MARK: validate

  @Test func validateAcceptsHttpsEndpoint() throws {
    let record = try decode(Self.fullJSON)
    try record.validate()  // does not throw
  }

  @Test func validateAcceptsRecordWithoutOptionals() throws {
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    try record.validate()  // optionals are not required
  }

  @Test func validateRejectsHttpEndpoint() {
    // An http endpoint would POST the refresh token in the clear — refused.
    let record = OAuthRecord(
      tokenEndpoint: "http://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("token_endpoint must be an https URL")) {
      try record.validate()
    }
  }

  @Test func validateRejectsGarbageEndpoint() {
    let record = OAuthRecord(
      tokenEndpoint: "not a url",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("token_endpoint must be an https URL")) {
      try record.validate()
    }
  }

  @Test func validateRejectsSchemelessEndpoint() {
    let record = OAuthRecord(
      tokenEndpoint: "example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("token_endpoint must be an https URL")) {
      try record.validate()
    }
  }

  @Test func validateRejectsEmptyTokenEndpoint() {
    let record = OAuthRecord(
      tokenEndpoint: "",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("token_endpoint is required")) {
      try record.validate()
    }
  }

  @Test func validateRejectsEmptyClientID() {
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("client_id is required")) {
      try record.validate()
    }
  }

  @Test func validateRejectsEmptyRefreshToken() {
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "",
      scopes: nil
    )
    #expect(throws: KeychainError.status("refresh_token is required")) {
      try record.validate()
    }
  }

  // MARK: validate — embedded-NUL rejection (the escaped-NUL bypass)

  @Test func validateRejectsNulInRefreshToken() {
    // THE headline case: a NUL in refresh_token survives a JSON round-trip (JSONEncoder
    // re-escapes U+0000 to backslash-u-0000, so storeSecret's byte-level contains(0)
    // guard misses it). validate() must reject it before storage. The NUL is built from
    // a code point so this source carries no raw NUL byte.
    let nul = String(UnicodeScalar(UInt8(0)))
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "r" + nul + "t",
      scopes: nil
    )
    #expect(throws: KeychainError.status("refresh_token must not contain a NUL byte")) {
      try record.validate()
    }
  }

  @Test func validateRejectsNulInTokenEndpoint() {
    // A NUL in token_endpoint is caught by the NUL check (a clearer message than the
    // generic https-URL rejection that would otherwise fire).
    let nul = String(UnicodeScalar(UInt8(0)))
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/" + nul + "token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("token_endpoint must not contain a NUL byte")) {
      try record.validate()
    }
  }

  @Test func validateRejectsNulInClientID() {
    let nul = String(UnicodeScalar(UInt8(0)))
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "i" + nul + "d",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("client_id must not contain a NUL byte")) {
      try record.validate()
    }
  }

  @Test func validateRejectsNulInOptionalClientSecret() {
    // Optional fields are checked too: a present-but-NUL client_secret is rejected.
    let nul = String(UnicodeScalar(UInt8(0)))
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: "s" + nul + "s",
      refreshToken: "tok",
      scopes: nil
    )
    #expect(throws: KeychainError.status("client_secret must not contain a NUL byte")) {
      try record.validate()
    }
  }

  @Test func validateRejectsNulInOptionalScopes() {
    let nul = String(UnicodeScalar(UInt8(0)))
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: "read" + nul + "write"
    )
    #expect(throws: KeychainError.status("scopes must not contain a NUL byte")) {
      try record.validate()
    }
  }

  @Test func validateRejectsNulDecodedFromJsonEscape() throws {
    // End-to-end realistic path: the value arrives as the JSON backslash-u-0000 escape
    // (exactly what a piped `oauth set` record could carry), JSONDecoder turns it into a
    // string with U+0000, and validate() rejects it — proving the creation-path bypass is
    // closed for real input, not just literal-NUL Swift strings. The escape is built from
    // a backslash code point so this source carries no raw NUL.
    let backslash = String(UnicodeScalar(UInt8(92)))
    let json = """
    { "token_endpoint": "https://example.com/token", "client_id": "id", "refresh_token": "r\(backslash)u0000t" }
    """
    let record = try decode(json)
    #expect(record.refreshToken == "r" + String(UnicodeScalar(UInt8(0))) + "t")
    #expect(throws: KeychainError.status("refresh_token must not contain a NUL byte")) {
      try record.validate()
    }
  }

  // MARK: encoded round-trip

  @Test func encodeDecodeRoundTrips() throws {
    let original = try decode(Self.fullJSON)
    let data = try original.encoded()
    let restored = try JSONDecoder().decode(OAuthRecord.self, from: data)
    #expect(restored == original)
  }

  @Test func encodeRoundTripsRecordWithoutOptionals() throws {
    let original = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    let data = try original.encoded()
    let restored = try JSONDecoder().decode(OAuthRecord.self, from: data)
    #expect(restored == original)
  }

  @Test func encodedUsesSnakeCaseKeysAndUnescapedSlashes() throws {
    let record = OAuthRecord(
      tokenEndpoint: "https://example.com/token",
      clientID: "id",
      clientSecret: nil,
      refreshToken: "tok",
      scopes: nil
    )
    let json = String(data: try record.encoded(), encoding: .utf8)!
    // snake_case storage keys, canonical (sorted) order, and the URL left readable.
    #expect(json.contains("\"token_endpoint\":\"https://example.com/token\""))
    #expect(json.contains("\"client_id\":\"id\""))
    #expect(json.contains("\"refresh_token\":\"tok\""))
    #expect(!json.contains("\\/"))
  }

  // MARK: TokenResponse decode

  @Test func tokenResponseDecodesRequiredAndOptionalFields() throws {
    let json = """
    {
      "access_token": "at",
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": "newr"
    }
    """
    let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
    #expect(response.accessToken == "at")
    #expect(response.refreshToken == "newr")
  }

  @Test func tokenResponseAllowsAbsentOptionals() throws {
    let json = """
    { "access_token": "at" }
    """
    let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
    #expect(response.accessToken == "at")
    #expect(response.refreshToken == nil)
  }

  @Test func tokenResponseThrowsOnMissingAccessToken() {
    let json = """
    { "token_type": "Bearer" }
    """
    #expect(throws: (any Error).self) {
      _ = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
    }
  }

  @Test func tokenResponseIgnoresUnknownAndNonConformantKeys() throws {
    // Unknown/extra keys (and a non-conformant string `expires_in`) must be
    // dropped by JSONDecoder rather than failing the decode; only
    // access_token/refresh_token are modelled.
    let json = """
    {
      "access_token": "at",
      "token_type": "Bearer",
      "expires_in": "3600",
      "error_uri": "https://example.com/err",
      "refresh_token": "newr"
    }
    """
    let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
    #expect(response.accessToken == "at")
    #expect(response.refreshToken == "newr")
  }
}
