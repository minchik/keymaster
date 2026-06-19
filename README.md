# Keymaster

Keymaster is a small binary written in Swift that lets scripts store and read macOS Keychain secrets guarded by Touch ID.

Macs come with the `security` command which can get and set secrets in the Keychain:

```bash
# Save a key/value to the default "login" keychain, with key "MyKeyName", update if exists (-U),
# allow no app to access without a prompt (-T ""), and prompt for secret to store (-w)
security add-generic-password -a login -s "MyKeyName" -T "" -U -w

# Get the secret value from a key
security find-generic-password -s "MyKeyName" -w
```

You can use `security` in a script, but (AFAIK) you can't tell it to guard secrets with biometrics — you have to enter the password each time, or "always allow" the `security` binary to access the secret. "Always allow" is exactly the weakening you don't want: it lets any process running as you read the plaintext with no challenge.

🔑 Keymaster fixes this. Each secret is stored with a biometric access-control object (`.biometryAny`), so the **Keychain itself** challenges for Touch ID on every read, overwrite, and delete. Enforcement is a property of the stored item, not of this program's control flow — there is no "always allow" to grant, and `security find-generic-password -w` cannot return the plaintext without a biometric match.

## Building Keymaster

Compile `keymaster.swift` into a binary:

`swiftc keymaster.swift`

Put the binary somewhere in your path.

## Save a secret to the keychain

The secret is read from **stdin**, never passed as an argument (an argument would leak via `ps` and shell history):

```bash
# Interactive: keymaster prompts and reads the secret without echoing it to the screen
keymaster set MyKeyName

# Piped: feed the secret in from another command
printf %s "$SECRET" | keymaster set MyKeyName
```

Piped input is read in full, so multi-line secrets (e.g. PEM keys) are preserved; a single trailing newline is trimmed. The interactive prompt reads one typed line. Secrets must be text (valid UTF-8), and an empty secret is rejected.

Creating a brand-new key does **not** prompt for Touch ID (the biometric access control is evaluated on access, not on creation). Overwriting an existing key prompts and names the key.

## Retrieve a secret

`keymaster get MyKeyName`

A Touch ID prompt appears that **names the requested key** (e.g. `Read keychain secret: "MyKeyName"`), so a script asking for the wrong secret is visible at approval time. On a match, the secret is printed to stdout. Cancelling the prompt denies access, prints nothing, and exits non-zero.

## Delete a secret

`keymaster delete MyKeyName`

A Touch ID prompt naming the key appears before the item is removed.

## Migration from the previous version (breaking change)

This version stores items under a new namespaced service (`dev.mnck.<key>`) with a fixed account and a biometric access control. Secrets saved by the previous keymaster use the old un-namespaced, unprotected format and will **not** be found by this version. Re-set each secret with the new build. Optionally remove the old entries via `Keychain Access.app` or `security delete-generic-password -s <oldkey>`.

You can use `keymaster` in bash scripts or Automator Workflows, or wherever you need secure access to a secret.
