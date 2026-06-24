// Pure, biometric-free helpers for the `run` subcommand.
//
// This file is intentionally Foundation-only — no `@main`, ArgumentParser, or
// keychain symbols — so it can be compiled into BOTH the app target (via the
// synchronized folder group) and the HOST-LESS `keymasterTests` bundle (via a
// synchronized-group membership exception) without a duplicate-symbol clash or a
// dependency the test bundle cannot satisfy. The keychain/biometric/exec glue
// lives in `keymasterApp.swift` and is verified manually.
import Foundation

// A resolved `--key` argument: read keychain key `key`, inject it as env var `env`.
struct KeyMapping: Equatable {
  let env: String
  let key: String
}

// Raised when a `--key` argument is malformed, so it is rejected before any exec.
enum KeyMappingError: Error, Equatable, CustomStringConvertible {
  case emptyName(String)
  case emptyKey(String)

  var description: String {
    switch self {
    case .emptyName(let raw):
      return "invalid --key \"\(raw)\": environment variable name is empty"
    case .emptyKey(let raw):
      return "invalid --key \"\(raw)\": keychain key is empty"
    }
  }
}

// Parse a `--key` argument into an (env var, keychain key) mapping.
//
//   "NAME"        -> env "NAME"    from keychain key "NAME"
//   "ENVNAME=key" -> env "ENVNAME" from keychain key "key"
//
// Split on the FIRST "=" only, so keychain keys may themselves contain "=".
// Throws when either side is empty so a malformed --key is rejected before exec.
func parseKeyMapping(_ raw: String) throws -> KeyMapping {
  guard let equals = raw.firstIndex(of: "=") else {
    guard !raw.isEmpty else { throw KeyMappingError.emptyName(raw) }
    return KeyMapping(env: raw, key: raw)
  }
  let env = String(raw[raw.startIndex..<equals])
  let key = String(raw[raw.index(after: equals)...])
  guard !env.isEmpty else { throw KeyMappingError.emptyName(raw) }
  guard !key.isEmpty else { throw KeyMappingError.emptyKey(raw) }
  return KeyMapping(env: env, key: key)
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
