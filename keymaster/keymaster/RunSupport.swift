// Pure, biometric-free helpers for the `run` subcommand (and the namespaced-key
// parsing shared with top-level `get`).
//
// This file is intentionally Foundation-only — no `@main`, ArgumentParser, or
// keychain symbols — so it can be compiled into BOTH the app target (via the
// synchronized folder group) and the HOST-LESS `keymasterTests` bundle (via a
// synchronized-group membership exception) without a duplicate-symbol clash or a
// dependency the test bundle cannot satisfy. The keychain/biometric/exec glue
// lives in `keymasterApp.swift` and is verified manually.
//
// `parseNamespacedKey` is the single owner of the `secret.NAME`/`oauth.NAME`
// syntax: both `get` (one key) and `run --key` (many, via `parseKeyMapping`)
// resolve a name's namespace by parsing its prefix here, so the namespace is
// explicit in the argument rather than probed for at read time. (`KeychainNamespace`
// is defined in `SecretManager.swift`; it is in scope here without an `import`
// because both files share the app target and the test bundle.)
import Foundation

// A resolved `--key` argument: read keychain key `key` from namespace `namespace`,
// inject it as env var `env`.
struct KeyMapping: Equatable {
  let env: String
  let key: String
  let namespace: KeychainNamespace

  // `namespace` defaults to `.secret` only so a caller may omit it; every real caller
  // (`parseKeyMapping` / `OAuthManager.resolveSecret`) supplies it explicitly.
  init(env: String, key: String, namespace: KeychainNamespace = .secret) {
    self.env = env
    self.key = key
    self.namespace = namespace
  }
}

// Raised when a `secret.NAME`/`oauth.NAME` key is malformed, so it is rejected
// (before any prompt/exec) by `get`/`run`. CustomStringConvertible so the CLI
// surfaces the message verbatim.
enum NamespacedKeyError: Error, Equatable, CustomStringConvertible {
  case missingNamespace(String)
  case unknownNamespace(String, prefix: String)
  case emptyKey(String)

  var description: String {
    switch self {
    case .missingNamespace(let raw):
      return "invalid key \"\(raw)\": missing namespace prefix — use secret.NAME or oauth.NAME"
    case .unknownNamespace(let raw, let prefix):
      return "invalid key \"\(raw)\": unknown namespace \"\(prefix)\" — use secret.NAME or oauth.NAME"
    case .emptyKey(let raw):
      return "invalid key \"\(raw)\": key name is empty — use secret.NAME or oauth.NAME"
    }
  }
}

// Parse a namespaced key into its (namespace, bare key) parts.
//
//   "secret.Foo"       -> (.secret, "Foo")
//   "oauth.Foo"        -> (.oauth,  "Foo")
//   "secret.oauth.Foo" -> (.secret, "oauth.Foo")   (FIRST "." splits, so a plain key
//                                                    literally named "oauth.Foo" is
//                                                    still reachable as secret.oauth.Foo)
//
// The prefix must be exactly `secret` or `oauth` and the key must be non-empty;
// otherwise a `NamespacedKeyError` is thrown so the malformed argument is rejected
// before any biometric prompt.
func parseNamespacedKey(_ raw: String) throws -> (namespace: KeychainNamespace, key: String) {
  guard let dot = raw.firstIndex(of: ".") else {
    throw NamespacedKeyError.missingNamespace(raw)
  }
  let prefix = String(raw[raw.startIndex..<dot])
  let key = String(raw[raw.index(after: dot)...])
  let namespace: KeychainNamespace
  switch prefix {
  case "secret": namespace = .secret
  case "oauth": namespace = .oauth
  default: throw NamespacedKeyError.unknownNamespace(raw, prefix: prefix)
  }
  guard !key.isEmpty else { throw NamespacedKeyError.emptyKey(raw) }
  return (namespace, key)
}

// Raised when the env-name side of a `--key ENV=spec` argument is empty, so it is
// rejected before any exec. (Key-side problems — missing/unknown namespace, empty
// key — surface as `NamespacedKeyError` from `parseNamespacedKey`.)
enum KeyMappingError: Error, Equatable, CustomStringConvertible {
  case emptyName(String)

  var description: String {
    switch self {
    case .emptyName(let raw):
      return "invalid --key \"\(raw)\": environment variable name is empty"
    }
  }
}

// Parse a `--key` argument into an (env var, namespace, keychain key) mapping.
//
//   "secret.NAME"        -> env "NAME" from `.secret` key "NAME"  (env = de-prefixed key)
//   "oauth.NAME"         -> env "NAME" from `.oauth`  key "NAME"
//   "ENVNAME=secret.key" -> env "ENVNAME" from `.secret` key "key"
//
// Split on the FIRST "=" only, so keychain keys may themselves contain "=". The
// key-spec (the whole argument when there is no "=", or the right side of the
// first "=") is parsed by `parseNamespacedKey`, so the namespace prefix is required.
// Throws (before exec) when the env name is empty (`KeyMappingError`) or the key-spec
// is malformed (`NamespacedKeyError`).
func parseKeyMapping(_ raw: String) throws -> KeyMapping {
  guard let equals = raw.firstIndex(of: "=") else {
    let (namespace, key) = try parseNamespacedKey(raw)
    return KeyMapping(env: key, key: key, namespace: namespace)
  }
  let env = String(raw[raw.startIndex..<equals])
  guard !env.isEmpty else { throw KeyMappingError.emptyName(raw) }
  let spec = String(raw[raw.index(after: equals)...])
  let (namespace, key) = try parseNamespacedKey(spec)
  return KeyMapping(env: env, key: key, namespace: namespace)
}

// Merge `overrides` over `base`, with overrides winning on key collisions. Pure,
// so the env-injection logic can be unit-tested without spawning a process.
func mergedEnvironment(
  base: [String: String],
  overrides: [String: String]
) -> [String: String] {
  base.merging(overrides) { _, override in override }
}

// Build the argv for the exec target. The command is launched through
// /usr/bin/env, so a bare name like "ls" resolves against PATH, and a "--" is
// inserted before the command so env stops parsing its own options first.
// Without it, a command whose first token starts with "-" (a program literally
// named like "-foo", or one passed that way) is mistaken for an env option and
// the launch fails with "illegal option" instead of running. Pure, so the argv
// shape can be unit-tested without exec'ing.
func execArgv(command: [String]) -> [String] {
  ["/usr/bin/env", "--"] + command
}

// Format an environment map as the `KEY=VALUE` strings execve's envp expects.
// The output is `.sorted()` ONLY for deterministic test assertions — execve's
// envp is an unordered map and the child does not depend on the order. Pure, so
// the env-block formatting can be unit-tested without exec'ing.
func execEnvironmentBlock(_ env: [String: String]) -> [String] {
  env.map { "\($0.key)=\($0.value)" }.sorted()
}
