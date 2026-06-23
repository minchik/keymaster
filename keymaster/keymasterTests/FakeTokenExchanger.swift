//
//  FakeTokenExchanger.swift
//  keymasterTests
//
//  A programmable TokenExchanger test double. The real URLSession send can never
//  run in automated tests (it would hit the network), so OAuthManager's mint flow
//  is exercised against this fake instead: it returns a programmed TokenResponse
//  or throws a programmed KeychainError, and records the OAuthRecord it was handed
//  so tests can assert the decoded record was passed through to the exchange.
//
//  Like the other test sources this reaches TokenExchanger/OAuthRecord/TokenResponse
//  through a plain `import Foundation`: TokenExchanger.swift and OAuthRecord.swift
//  are compiled directly into this host-less bundle via synchronized-group
//  membership exceptions, not imported.
import Foundation

final class FakeTokenExchanger: TokenExchanger {
  // When `error` is set, `exchange` throws it; otherwise it returns `response`.
  // A test that sets neither is misconfigured and the call fails loudly.
  var response: TokenResponse?
  var error: KeychainError?

  // The record handed to the most recent `exchange`, so tests can prove the bytes
  // read from the keychain decoded to the expected record before exchange.
  private(set) var receivedRecord: OAuthRecord?

  init(response: TokenResponse? = nil, error: KeychainError? = nil) {
    self.response = response
    self.error = error
  }

  func exchange(_ record: OAuthRecord) throws -> TokenResponse {
    receivedRecord = record
    if let error { throw error }
    guard let response else {
      throw KeychainError.status("FakeTokenExchanger: no response or error programmed")
    }
    return response
  }
}
