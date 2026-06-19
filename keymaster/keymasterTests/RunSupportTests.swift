//
//  RunSupportTests.swift
//  keymasterTests
//
//  Unit tests for the pure, biometric-free helpers in RunSupport.swift.
//
//  The keymasterTests bundle is HOST-LESS and does not `@testable import` the app
//  (the `@main` CLI exit()s before an app-hosted runner can attach). RunSupport.swift
//  is compiled directly into this bundle via a synchronized-group membership
//  exception, so a plain `import Foundation` reaches it — no app module import.
import Foundation
import Testing

struct RunSupportTests {

  // MARK: parseKeyMapping

  @Test func parseBareNameMapsEnvAndKeyToItself() throws {
    #expect(try parseKeyMapping("NAME") == KeyMapping(env: "NAME", key: "NAME"))
  }

  @Test func parseEnvEqualsKeySplitsIntoBoth() throws {
    #expect(try parseKeyMapping("ENV=key") == KeyMapping(env: "ENV", key: "key"))
  }

  @Test func parseSplitsOnFirstEqualsOnly() throws {
    // Keychain keys may contain "=", so only the first "=" separates env from key.
    #expect(try parseKeyMapping("ENV=a=b") == KeyMapping(env: "ENV", key: "a=b"))
  }

  @Test func parseRejectsEmptyEnvName() {
    #expect(throws: KeyMappingError.self) {
      _ = try parseKeyMapping("=key")
    }
  }

  @Test func parseRejectsEmptyKey() {
    #expect(throws: KeyMappingError.self) {
      _ = try parseKeyMapping("NAME=")
    }
  }

  // MARK: mergedEnvironment

  @Test func mergeOverrideReplacesBaseValue() {
    let merged = mergedEnvironment(base: ["A": "1"], overrides: ["A": "2"])
    #expect(merged["A"] == "2")
  }

  @Test func mergeAddsNewKey() {
    let merged = mergedEnvironment(base: ["A": "1"], overrides: ["B": "2"])
    #expect(merged["A"] == "1")
    #expect(merged["B"] == "2")
  }

  @Test func mergePreservesUntouchedBaseKey() {
    let merged = mergedEnvironment(base: ["A": "1", "B": "2"], overrides: ["B": "9"])
    #expect(merged["A"] == "1")
    #expect(merged["B"] == "9")
  }

}
