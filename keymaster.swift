// Keymaster, access Keychain secrets guarded by TouchID
//
import Foundation
import LocalAuthentication
import Security

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
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
  print("keymaster [get|set|delete] [key] [secret]")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if inputArgs.count < 2 || inputArgs.count > 3 {
    usage()
    exit(EXIT_FAILURE) 
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  var secret = ""
  if action == "set" && inputArgs.count == 3 {
    secret = inputArgs[2]
  }

  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 0

  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  if action == "set" {
    context.evaluatePolicy(policy, localizedReason: "set to your password") { _, _ in
      guard setPassword(key: key, secret: Data(secret.utf8)) == errSecSuccess else {
        print("Error setting password")
        exit(EXIT_FAILURE)
      }
      print("Key \(key) has been sucessfully set in the keychain")
      exit(EXIT_SUCCESS)
    }
    dispatchMain()
  }

  if action == "get" {
    context.evaluatePolicy(policy, localizedReason: "access to your password") { success, error in
      if success && error == nil {
        let (status, data) = getPassword(key: key)
        guard status == errSecSuccess,
          let data = data,
          let password = String(data: data, encoding: String.Encoding.utf8)
        else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if action == "delete" {
    context.evaluatePolicy(policy, localizedReason: "delete your password") { success, error in
      if success && error == nil {
        guard deletePassword(key: key) == errSecSuccess else {
          print("Error deleting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been sucessfully deleted from the keychain")
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }
}

main()
