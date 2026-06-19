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
enum KeyMappingError: Error, CustomStringConvertible {
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
