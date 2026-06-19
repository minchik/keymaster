// Keymaster, access Keychain secrets guarded by Touch ID.
//
// This is an .app target only so the binary can carry the
// `keychain-access-groups` entitlement (a restricted entitlement that AMFI
// rejects on an unsigned/unprovisioned binary). At runtime it behaves as a
// CLI: `Keymaster.app/Contents/MacOS/keymaster <set|get|rm> <key>` does
// its Keychain work and exits before any AppKit run loop starts, so no window
// is shown.
import ArgumentParser
import Dispatch
import Foundation
import LocalAuthentication
import Security

let servicePrefix = "dev.mnck."
let account = "keymaster"

// Build a biometric access-control object so the Keychain itself challenges
// for Touch ID on every read/modify/remove. Returns nil if creation fails.
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

// Pre-authenticate ONE LAContext so a whole batch of secrets (the `run`
// subcommand) can be read with a SINGLE Touch ID prompt.
// evaluateAccessControl(.useItem) forces one fresh biometric challenge; the
// returned context is then handed to each readItem via
// kSecUseAuthenticationContext, and the Keychain reuses that authentication for
// every item instead of re-prompting. Returns nil if the user cancels or auth
// fails, so the caller aborts before launching the command.
//
// Security: touchIDAuthenticationAllowableReuseDuration is left at its default
// (0). The single prompt comes solely from sharing one already-authenticated
// context, NOT from a reuse time window in which a recent device unlock could
// satisfy a read — so keymaster's guarantee that every secret access forces a
// fresh Touch ID is preserved.
//
// Concurrency: evaluateAccessControl(...:reply:) is async, so this bridges it to a
// synchronous flow with a DispatchSemaphore. The app builds with
// SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor, so this runs on the main actor and
// semaphore.wait() blocks that thread; that is safe because LocalAuthentication
// delivers the reply on a background queue (which signals the semaphore) and the
// CLI has no AppKit run loop to starve.
func authenticatedContext(reason: String) -> LAContext? {
  guard let accessControl = makeAccessControl() else { return nil }
  let context = LAContext()
  let semaphore = DispatchSemaphore(value: 0)
  var granted = false
  context.evaluateAccessControl(
    accessControl,
    operation: .useItem,
    localizedReason: reason
  ) { success, _ in
    granted = success
    semaphore.signal()
  }
  semaphore.wait()
  return granted ? context : nil
}

// The fields every Keychain query shares: the item class plus the namespaced
// service and fixed account that together identify one stored secret. Each
// operation extends this with the keys specific to add/read/remove.
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
// object so the Keychain challenges for Touch ID on every later read/modify/remove.
// On a duplicate, the existing item is removed and re-added so the stored secret
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
  // read naming the key), then remove the existing item and re-add it so the
  // stored secret always carries our biometric ACL. SecItemDelete does not
  // decrypt, so the read is what gates this overwrite behind Touch ID.
  let (auth, _) = readItem(verb: "Update", key: key)
  guard auth == errSecSuccess else { return auth }
  let removeStatus = SecItemDelete(baseQuery(for: key) as CFDictionary)
  guard removeStatus == errSecSuccess else { return removeStatus }
  return SecItemAdd(addQuery as CFDictionary, nil)
}

// Remove a biometric-protected secret. SecItemDelete does not decrypt the item,
// so the biometric ACL would not challenge it on its own; we first force a Touch
// ID prompt with an authenticated read and remove only when the user approves.
// Returns the raw OSStatus so the caller can report real failures.
func removePassword(key: String) -> OSStatus {
  let (auth, _) = readItem(verb: "Remove", key: key)
  guard auth == errSecSuccess else { return auth }
  return SecItemDelete(baseQuery(for: key) as CFDictionary)
}

// Read the item, forcing a Touch ID challenge whose prompt names the key and
// uses `verb` (e.g. "Read", "Remove", "Update"). The biometric ACL only
// challenges on decryption, so this read is also what gates remove/overwrite:
// those callers run it first and proceed only when it returns errSecSuccess.
// Returns the raw OSStatus alongside the secret data (nil unless success).
//
// Delegates to the context-based overload with a fresh per-key context, so
// set/get/rm keep prompting exactly as before.
func readItem(verb: String, key: String) -> (OSStatus, Data?) {
  readItem(key: key, context: authContext(verb: verb, key: key))
}

// Read one item through a caller-supplied LAContext. `run` passes a single
// pre-authenticated context (see authenticatedContext) so a batch of reads share
// one Touch ID prompt; the per-key callers above pass a fresh context each time.
// Returns the raw OSStatus alongside the secret data (nil unless success).
func readItem(key: String, context: LAContext) -> (OSStatus, Data?) {
  var query = baseQuery(for: key)
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = true
  query[kSecUseAuthenticationContext as String] = context
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  return (status, item as? Data)
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

// Decode a secret read for `run` into an environment-variable value. Like
// secretString, but the error message names the failing key (a batch reads many,
// so an unqualified message would not say which one failed) and the abort happens
// before exec so the command never runs with a silently-missing secret. Non-UTF-8
// is rejected because environment values must be text.
func envSecret(forKey key: String, status: OSStatus, data: Data?) -> String {
  guard status == errSecSuccess else {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
    fail("\(key): \(message)")
  }
  guard let data = data else { fail("\(key): keychain returned no data") }
  guard let secret = String(data: data, encoding: .utf8) else {
    fail("\(key): stored secret is not valid UTF-8")
  }
  return secret
}

@main
struct Keymaster: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "keymaster",
    abstract: "Store and retrieve Keychain secrets guarded by Touch ID.",
    subcommands: [Set.self, Get.self, Remove.self]
  )
}

extension Keymaster {
  // Store a secret read from stdin. No Touch ID prompt on first create (the ACL
  // is evaluated on access, not creation); an overwrite prompts via setPassword.
  struct Set: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Store a secret read from stdin; prompts on overwrite."
    )

    @Argument(help: "The key to store the secret under.")
    var key: String

    func run() {
      guard let secret = readSecret(for: key), !secret.isEmpty else {
        fail("no secret provided")
      }
      let status = setPassword(key: key, secret: Data(secret.utf8))
      guard status == errSecSuccess else { failKeychain(status) }
      print("Key \"\(key)\" has been set in the keychain")
    }
  }

  // Retrieve a secret; the Keychain challenges Touch ID on the read.
  struct Get: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Retrieve a secret, gated by Touch ID."
    )

    @Argument(help: "The key to retrieve.")
    var key: String

    func run() {
      let (status, data) = readItem(verb: "Read", key: key)
      print(secretString(status: status, data: data))
    }
  }

  // Remove a secret; removePassword forces a Touch ID read before deleting.
  struct Remove: ParsableCommand {
    static let configuration = CommandConfiguration(
      commandName: "rm",
      abstract: "Remove a secret, gated by Touch ID."
    )

    @Argument(help: "The key to remove.")
    var key: String

    func run() {
      let status = removePassword(key: key)
      guard status == errSecSuccess else { failKeychain(status) }
      print("Key \"\(key)\" has been removed from the keychain")
    }
  }
}
