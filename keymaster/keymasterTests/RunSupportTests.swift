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
    #expect(throws: KeyMappingError.emptyName("=key")) {
      _ = try parseKeyMapping("=key")
    }
  }

  @Test func parseRejectsEmptyKey() {
    #expect(throws: KeyMappingError.emptyKey("NAME=")) {
      _ = try parseKeyMapping("NAME=")
    }
  }

  @Test func parseRejectsBareEmptyString() {
    // No "=" present, so the empty-input guard (not the split branch) rejects it
    // as an empty env name — otherwise it would map "" to env "" / key "".
    #expect(throws: KeyMappingError.emptyName("")) {
      _ = try parseKeyMapping("")
    }
  }

  @Test func errorDescriptionNamesTheOffendingArgument() {
    #expect(KeyMappingError.emptyName("=key").description
      == "invalid --key \"=key\": environment variable name is empty")
    #expect(KeyMappingError.emptyKey("NAME=").description
      == "invalid --key \"NAME=\": keychain key is empty")
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

  // MARK: runProcess

  @Test func runForwardsExitCode() {
    #expect(runProcess(command: ["/bin/sh", "-c", "exit 7"], extraEnv: [:]) == 7)
  }

  @Test func runReportsSignalDeathAs128PlusSigno() {
    // SIGTERM is signal 15, so a SIGTERM death is reported as 128 + 15 = 143.
    #expect(runProcess(command: ["/bin/sh", "-c", "kill -TERM $$"], extraEnv: [:]) == 143)
  }

  // A var name that won't exist in a developer/CI shell, so the no-injection case
  // below truly tests the unset fallback rather than inheriting an ambient value
  // (runProcess deliberately preserves ProcessInfo.processInfo.environment).
  @Test func runInjectsExtraEnvIntoChild() {
    // The child exits with the var when set, so a forwarded 7 proves it reached it.
    #expect(runProcess(
      command: ["/bin/sh", "-c", "exit ${KEYMASTER_TEST_VAR:-99}"],
      extraEnv: ["KEYMASTER_TEST_VAR": "7"]
    ) == 7)
  }

  @Test func runWithoutInjectionLeavesVarUnset() {
    // Same child without the override falls back to 99, confirming no leakage.
    #expect(runProcess(
      command: ["/bin/sh", "-c", "exit ${KEYMASTER_TEST_VAR:-99}"],
      extraEnv: [:]
    ) == 99)
  }

  @Test func runResolvesBareProgramNameViaPath() {
    // /usr/bin/env resolves a bare name against PATH, so "true"/"false" run directly.
    #expect(runProcess(command: ["true"], extraEnv: [:]) == 0)
    #expect(runProcess(command: ["false"], extraEnv: [:]) == 1)
  }

}
