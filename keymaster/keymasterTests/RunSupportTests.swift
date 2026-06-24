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

  // MARK: execArgv

  @Test func execArgvWrapsBareNameWithEnvAndDashDash() {
    // A bare program name is prefixed with /usr/bin/env and "--" so it resolves
    // against PATH after env stops parsing its own options.
    #expect(execArgv(command: ["ls"]) == ["/usr/bin/env", "--", "ls"])
  }

  @Test func execArgvKeepsDashLeadingProgramAfterDashDash() {
    // The "--" guard means a dash-leading program name is passed through as the
    // command rather than mistaken for an env option.
    #expect(execArgv(command: ["-foo"]) == ["/usr/bin/env", "--", "-foo"])
  }

  @Test func execArgvPreservesProgramArgumentsInOrder() {
    #expect(execArgv(command: ["echo", "-n", "hi"])
      == ["/usr/bin/env", "--", "echo", "-n", "hi"])
  }

  // MARK: execEnvironmentBlock

  @Test func execEnvironmentBlockSortsKeyValueStrings() {
    #expect(execEnvironmentBlock(["B": "2", "A": "1"]) == ["A=1", "B=2"])
  }

  @Test func execEnvironmentBlockKeepsEqualsInValue() {
    // Only the KEY=VALUE join matters; a value containing "=" is left intact
    // (execve splits the env entry on the first "=" itself).
    #expect(execEnvironmentBlock(["A": "x=y"]) == ["A=x=y"])
  }

  @Test func execEnvironmentBlockKeepsEmptyValue() {
    // An empty secret injects a legal `KEY=` entry; the formatter must keep the
    // bare trailing "=" rather than drop the key or the separator.
    #expect(execEnvironmentBlock(["A": ""]) == ["A="])
  }

  @Test func execEnvironmentBlockEmptyDictYieldsEmptyArray() {
    #expect(execEnvironmentBlock([:]) == [])
  }

}
