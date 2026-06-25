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

  // MARK: parseNamespacedKey

  @Test func parseNamespacedSecretPrefix() throws {
    let result = try parseNamespacedKey("secret.Foo")
    #expect(result.namespace == .secret)
    #expect(result.key == "Foo")
  }

  @Test func parseNamespacedOauthPrefix() throws {
    let result = try parseNamespacedKey("oauth.Foo")
    #expect(result.namespace == .oauth)
    #expect(result.key == "Foo")
  }

  @Test func parseNamespacedSplitsOnFirstDotOnly() throws {
    // First-"." split, so a plain key literally named "oauth.Foo" is reachable as
    // secret.oauth.Foo — namespace `.secret`, key "oauth.Foo".
    let result = try parseNamespacedKey("secret.oauth.Foo")
    #expect(result.namespace == .secret)
    #expect(result.key == "oauth.Foo")
  }

  @Test func parseNamespacedRejectsMissingNamespace() {
    // No ".", so there is no namespace prefix at all.
    #expect(throws: NamespacedKeyError.missingNamespace("Foo")) {
      _ = try parseNamespacedKey("Foo")
    }
  }

  @Test func parseNamespacedRejectsEmptyKey() {
    // A valid prefix but nothing after the ".".
    #expect(throws: NamespacedKeyError.emptyKey("secret.")) {
      _ = try parseNamespacedKey("secret.")
    }
  }

  @Test func parseNamespacedRejectsUnknownNamespace() {
    #expect(throws: NamespacedKeyError.unknownNamespace("bogus.Foo", prefix: "bogus")) {
      _ = try parseNamespacedKey("bogus.Foo")
    }
  }

  @Test func parseNamespacedRejectsEmptyPrefixAsUnknownNamespace() {
    // A leading "." means an empty prefix, which is an unknown namespace (not a
    // missing one — the "." is present).
    #expect(throws: NamespacedKeyError.unknownNamespace(".Foo", prefix: "")) {
      _ = try parseNamespacedKey(".Foo")
    }
  }

  @Test func namespacedKeyErrorDescriptionsNameTheOffendingInput() {
    #expect(NamespacedKeyError.missingNamespace("Foo").description
      == "invalid key \"Foo\": missing namespace prefix — use secret.NAME or oauth.NAME")
    #expect(NamespacedKeyError.unknownNamespace("bogus.Foo", prefix: "bogus").description
      == "invalid key \"bogus.Foo\": unknown namespace \"bogus\" — use secret.NAME or oauth.NAME")
    #expect(NamespacedKeyError.emptyKey("secret.").description
      == "invalid key \"secret.\": key name is empty — use secret.NAME or oauth.NAME")
  }

  // MARK: parseKeyMapping

  @Test func parseBareNamespacedNameMapsEnvToDePrefixedKey() throws {
    // Regression-prone: with no "=", the env name is the DE-PREFIXED key ("API_TOKEN"),
    // not the full "secret.API_TOKEN" spec.
    #expect(try parseKeyMapping("secret.API_TOKEN")
      == KeyMapping(env: "API_TOKEN", key: "API_TOKEN", namespace: .secret))
  }

  @Test func parseBareOauthNameMapsEnvToDePrefixedKey() throws {
    #expect(try parseKeyMapping("oauth.GitHub")
      == KeyMapping(env: "GitHub", key: "GitHub", namespace: .oauth))
  }

  @Test func parseEnvEqualsNamespacedKeySplitsIntoBoth() throws {
    #expect(try parseKeyMapping("ENV=oauth.key")
      == KeyMapping(env: "ENV", key: "key", namespace: .oauth))
  }

  @Test func parseSplitsOnFirstEqualsOnly() throws {
    // Keychain keys may contain "=", so only the first "=" separates env from spec;
    // the namespace prefix is then stripped from the remaining spec.
    #expect(try parseKeyMapping("ENV=secret.a=b")
      == KeyMapping(env: "ENV", key: "a=b", namespace: .secret))
  }

  @Test func parseRejectsEmptyEnvName() {
    // The env name is checked before the spec is parsed, so an empty env wins.
    #expect(throws: KeyMappingError.emptyName("=secret.key")) {
      _ = try parseKeyMapping("=secret.key")
    }
  }

  @Test func parseRejectsEmptyKeyViaNamespacedParser() {
    // A valid prefix but empty key in the spec surfaces the namespaced parser's error.
    #expect(throws: NamespacedKeyError.emptyKey("secret.")) {
      _ = try parseKeyMapping("ENV=secret.")
    }
  }

  @Test func parseRejectsMissingNamespaceOnBareName() {
    // A bare name with no namespace prefix is rejected by the namespaced parser.
    #expect(throws: NamespacedKeyError.missingNamespace("NAME")) {
      _ = try parseKeyMapping("NAME")
    }
  }

  @Test func parseRejectsBareEmptyString() {
    // No "=" present, so the whole (empty) argument is parsed as a namespaced key,
    // which has no prefix at all.
    #expect(throws: NamespacedKeyError.missingNamespace("")) {
      _ = try parseKeyMapping("")
    }
  }

  @Test func errorDescriptionNamesTheOffendingArgument() {
    #expect(KeyMappingError.emptyName("=secret.key").description
      == "invalid --key \"=secret.key\": environment variable name is empty")
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
