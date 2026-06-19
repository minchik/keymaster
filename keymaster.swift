// Keymaster, access Keychain secrets guarded by TouchID
//
import Foundation
import LocalAuthentication
import Security

let servicePrefix = "dev.mnck."
let account = "keymaster"

// Build a biometric access-control object so the Keychain itself challenges
// for Touch ID on every read/modify/delete. Returns nil if creation fails.
func makeAccessControl() -> SecAccessControl? {
  var error: Unmanaged<CFError>?
  let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryAny,
    &error
  )
  guard error == nil else { return nil }
  return accessControl
}

// Produce an LAContext whose prompt names the requested key, so a caller
// asking for the wrong secret is visible at approval time.
func authContext(verb: String, key: String) -> LAContext {
  let context = LAContext()
  context.localizedReason = "\(verb) keychain secret: \"\(key)\""
  return context
}

// Upsert a biometric-protected secret. The added item carries an access-control
// object so the Keychain challenges for Touch ID on every later read/modify/delete.
// On a duplicate, the existing item is updated (which prompts, naming the key).
// Returns the raw OSStatus so the caller can report real failures.
func setPassword(key: String, secret: Data) -> OSStatus {
  guard let accessControl = makeAccessControl() else { return errSecParam }

  let addQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: servicePrefix + key,
    kSecAttrAccount as String: account,
    kSecValueData as String: secret,
    kSecAttrAccessControl as String: accessControl
  ]

  let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
  guard addStatus == errSecDuplicateItem else { return addStatus }

  let matchQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: servicePrefix + key,
    kSecAttrAccount as String: account,
    kSecUseAuthenticationContext as String: authContext(verb: "Update", key: key)
  ]
  let attributes: [String: Any] = [kSecValueData as String: secret]
  return SecItemUpdate(matchQuery as CFDictionary, attributes as CFDictionary)
}

// Delete a biometric-protected secret. The bound LAContext makes the Keychain
// present a Touch ID prompt naming the requested key. Returns the raw OSStatus
// so the caller can report real failures.
func deletePassword(key: String) -> OSStatus {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: servicePrefix + key,
    kSecAttrAccount as String: account,
    kSecUseAuthenticationContext as String: authContext(verb: "Delete", key: key)
  ]
  return SecItemDelete(query as CFDictionary)
}

// Read a biometric-protected secret. The bound LAContext makes the Keychain
// present a Touch ID prompt naming the requested key. Returns the raw OSStatus
// alongside the secret data (nil unless the status is success).
func getPassword(key: String) -> (OSStatus, Data?) {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: servicePrefix + key,
    kSecAttrAccount as String: account,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true,
    kSecUseAuthenticationContext as String: authContext(verb: "Read", key: key)
  ]
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
// echo so the typed secret never appears on screen; otherwise read a single
// piped line. The trailing newline is stripped. Returns nil if nothing is read.
func readSecret(for key: String) -> String? {
  guard isatty(STDIN_FILENO) != 0 else {
    return readLine(strippingNewline: true)
  }
  FileHandle.standardError.write(Data("Secret for \"\(key)\": ".utf8))
  var original = termios()
  tcgetattr(STDIN_FILENO, &original)
  var noEcho = original
  noEcho.c_lflag &= ~tcflag_t(ECHO)
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &noEcho)
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

func main() {
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
    let (status, data) = getPassword(key: key)
    guard status == errSecSuccess else { failKeychain(status) }
    guard let data = data, let password = String(data: data, encoding: .utf8) else {
      fail("stored secret is not valid UTF-8")
    }
    print(password)
  case "delete":
    let status = deletePassword(key: key)
    guard status == errSecSuccess else { failKeychain(status) }
    print("Key \"\(key)\" has been deleted from the keychain")
  default:
    usage()
    exit(EXIT_FAILURE)
  }
}

main()
