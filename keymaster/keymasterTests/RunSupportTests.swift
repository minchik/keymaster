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

  // MARK: runProcess

  @Test func runForwardsExitCode() {
    #expect(runProcess(command: ["/bin/sh", "-c", "exit 7"], extraEnv: [:]) == 7)
  }

  @Test func runReportsSignalDeathAs128PlusSigno() {
    // SIGTERM is signal 15, so a SIGTERM death is reported as 128 + 15 = 143.
    #expect(runProcess(command: ["/bin/sh", "-c", "kill -TERM $$"], extraEnv: [:]) == 143)
  }

  @Test func runInjectsExtraEnvIntoChild() {
    // The child exits with FOO when set, so a forwarded 7 proves the var reached it.
    #expect(runProcess(command: ["/bin/sh", "-c", "exit ${FOO:-99}"], extraEnv: ["FOO": "7"]) == 7)
  }

  @Test func runWithoutInjectionLeavesVarUnset() {
    // Same child without the override falls back to 99, confirming no leakage.
    #expect(runProcess(command: ["/bin/sh", "-c", "exit ${FOO:-99}"], extraEnv: [:]) == 99)
  }

  @Test func runResolvesBareProgramNameViaPath() {
    // /usr/bin/env resolves a bare name against PATH, so "true"/"false" run directly.
    #expect(runProcess(command: ["true"], extraEnv: [:]) == 0)
    #expect(runProcess(command: ["false"], extraEnv: [:]) == 1)
  }

}
