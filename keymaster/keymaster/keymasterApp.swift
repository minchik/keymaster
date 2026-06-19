// Keymaster, access Keychain secrets guarded by Touch ID.
//
// This is an .app target only so the binary can carry the
// `keychain-access-groups` entitlement (a restricted entitlement that AMFI
// rejects on an unsigned/unprovisioned binary). At runtime it behaves as a
// CLI: `keymaster.app/Contents/MacOS/keymaster <set|get|delete> <key>` does
// its Keychain work and exits before any AppKit run loop starts, so no window
// is shown.
import Foundation
import LocalAuthentication
import Security

let servicePrefix = "dev.mnck."
let account = "keymaster"

// Build a biometric access-control object so the Keychain itself challenges
// for Touch ID on every read/modify/delete. Returns nil if creation fails.
func makeAccessControl() -> SecAccessControl? {
  // Success is indicated by a non-nil return value, per the Security API
  // contract; a nil return (with the error populated) means creation failed.
  var error: Unmanaged<CFError>?
  return SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryAny,
    &error
  )
}

// Produce an LAContext whose prompt names the requested key, so a caller
// asking for the wrong secret is visible at approval time.
func authContext(verb: String, key: String) -> LAContext {
  let context = LAContext()
  context.localizedReason = "\(verb) keychain secret: \"\(key)\""
  return context
}

// The fields every Keychain query shares: the item class plus the namespaced
// service and fixed account that together identify one stored secret. Each
// operation extends this with the keys specific to add/read/delete.
//
// kSecUseDataProtectionKeychain pins every operation to the modern
// data-protection keychain. The biometric access control and the
// keychain-access-groups entitlement are only honored there; without this the
// items would target the legacy file keychain. The single access group from
// the entitlement is applied by default, so kSecAttrAccessGroup is not set.
func baseQuery(for key: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: servicePrefix + key,
    kSecAttrAccount as String: account,
    kSecUseDataProtectionKeychain as String: true
  ]
}

// Upsert a biometric-protected secret. The added item carries an access-control
// object so the Keychain challenges for Touch ID on every later read/modify/delete.
// On a duplicate, the existing item is deleted and re-added so the stored secret
// always carries our biometric ACL — never the access control of a pre-existing
// item. Returns the raw OSStatus so the caller can report real failures.
func setPassword(key: String, secret: Data) -> OSStatus {
  guard let accessControl = makeAccessControl() else { return errSecParam }

  var addQuery = baseQuery(for: key)
  addQuery[kSecValueData as String] = secret
  addQuery[kSecAttrAccessControl as String] = accessControl

  let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
  guard addStatus == errSecDuplicateItem else { return addStatus }

  // An item already exists under this service/account. Its access control can't
  // be trusted: another binary entitled to this access group could have created
  // it with a weaker ACL, and SecItemUpdate would preserve that ACL while
  // storing the new secret. Instead force a Touch ID prompt (an authenticated
  // read naming the key), then delete the existing item and re-add it so the
  // stored secret always carries our biometric ACL. SecItemDelete does not
  // decrypt, so the read is what gates this overwrite behind Touch ID.
  let (auth, _) = readItem(verb: "Update", key: key)
  guard auth == errSecSuccess else { return auth }
  let deleteStatus = SecItemDelete(baseQuery(for: key) as CFDictionary)
  guard deleteStatus == errSecSuccess else { return deleteStatus }
  return SecItemAdd(addQuery as CFDictionary, nil)
}

// Delete a biometric-protected secret. SecItemDelete does not decrypt the item,
// so the biometric ACL would not challenge it on its own; we first force a Touch
// ID prompt with an authenticated read and delete only when the user approves.
// Returns the raw OSStatus so the caller can report real failures.
func deletePassword(key: String) -> OSStatus {
  let (auth, _) = readItem(verb: "Delete", key: key)
  guard auth == errSecSuccess else { return auth }
  return SecItemDelete(baseQuery(for: key) as CFDictionary)
}

// Read the item, forcing a Touch ID challenge whose prompt names the key and
// uses `verb` (e.g. "Read", "Delete", "Update"). The biometric ACL only
// challenges on decryption, so this read is also what gates delete/overwrite:
// those callers run it first and proceed only when it returns errSecSuccess.
// Returns the raw OSStatus alongside the secret data (nil unless success).
func readItem(verb: String, key: String) -> (OSStatus, Data?) {
  var query = baseQuery(for: key)
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = true
  query[kSecUseAuthenticationContext as String] = authContext(verb: verb, key: key)
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  return (status, item as? Data)
}

func usage() {
  print("Usage:")
  print("  keymaster set <key>      # store a secret read from stdin, gated by Touch ID")
  print("  keymaster get <key>      # retrieve a secret, gated by Touch ID")
  print("  keymaster delete <key>   # remove a secret, gated by Touch ID")
}

// Read one secret from stdin. When stdin is a TTY, prompt and disable terminal
// echo so the typed secret never appears on screen, then read a single typed
// line. Otherwise read all piped input so multi-line secrets are preserved,
// trimming a single trailing newline. Returns nil if nothing valid is read.
func readSecret(for key: String) -> String? {
  guard isatty(STDIN_FILENO) != 0 else {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard var secret = String(data: data, encoding: .utf8) else { return nil }
    if secret.hasSuffix("\n") { secret.removeLast() }
    return secret
  }
  FileHandle.standardError.write(Data("Secret for \"\(key)\": ".utf8))
  var original = termios()
  guard tcgetattr(STDIN_FILENO, &original) == 0 else {
    fail("could not read terminal settings")
  }
  var noEcho = original
  noEcho.c_lflag &= ~tcflag_t(ECHO)
  // Abort rather than fall through with echo on, which would print the secret.
  guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &noEcho) == 0 else {
    fail("could not disable terminal echo")
  }
  defer {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
    FileHandle.standardError.write(Data("\n".utf8))
  }
  return readLine(strippingNewline: true)
}

// Print a human-readable Keychain error and exit non-zero.
func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data("Error: \(message)\n".utf8))
  exit(EXIT_FAILURE)
}

// Translate an OSStatus into a message via SecCopyErrorMessageString and exit.
func failKeychain(_ status: OSStatus) -> Never {
  let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
  fail(message)
}

// Decode a getPassword result into the secret string, exiting on any failure.
func secretString(status: OSStatus, data: Data?) -> String {
  guard status == errSecSuccess else { failKeychain(status) }
  guard let data = data else { fail("keychain returned no data") }
  guard let password = String(data: data, encoding: .utf8) else {
    fail("stored secret is not valid UTF-8")
  }
  return password
}

@main
struct KeymasterCLI {
  static func main() {
    let inputArgs = Array(CommandLine.arguments.dropFirst())
    guard inputArgs.count == 2 else {
      usage()
      exit(EXIT_FAILURE)
    }
    let action = inputArgs[0]
    let key = inputArgs[1]

    switch action {
    case "set":
      guard let secret = readSecret(for: key), !secret.isEmpty else {
        fail("no secret provided")
      }
      let status = setPassword(key: key, secret: Data(secret.utf8))
      guard status == errSecSuccess else { failKeychain(status) }
      print("Key \"\(key)\" has been set in the keychain")
    case "get":
      let (status, data) = readItem(verb: "Read", key: key)
      print(secretString(status: status, data: data))
    case "delete":
      let status = deletePassword(key: key)
      guard status == errSecSuccess else { failKeychain(status) }
      print("Key \"\(key)\" has been deleted from the keychain")
    default:
      usage()
      exit(EXIT_FAILURE)
    }
  }
}
