# Keymaster

Keymaster lets scripts store and read macOS Keychain secrets guarded by Touch ID.

Macs come with the `security` command which can get and set secrets in the Keychain:

```bash
# Save a key/value to the default "login" keychain, with key "MyKeyName", update if exists (-U),
# allow no app to access without a prompt (-T ""), and prompt for secret to store (-w)
security add-generic-password -a login -s "MyKeyName" -T "" -U -w

# Get the secret value from a key
security find-generic-password -s "MyKeyName" -w
```

You can use `security` in a script, but (AFAIK) you can't tell it to guard secrets with biometrics — you have to enter the password each time, or "always allow" the `security` binary to access the secret. "Always allow" is exactly the weakening you don't want: it lets any process running as you read the plaintext with no challenge.

🔑 Keymaster fixes this. Each secret is stored in the **data-protection keychain** with a biometric access-control object (`.biometryAny`) and scoped to keymaster's own keychain access group, so:

- **Reading a secret triggers a Touch ID challenge from the Keychain itself** — there is no "always allow" to grant.
- The items are **isolated by entitlement**: only a binary signed into keymaster's access group can see them at all. Another process running as you can't read them with `security find-generic-password` — it won't even find them.
- **Removing and overwriting are gated by Touch ID too.** The Keychain does not challenge removal on its own (removing doesn't decrypt the secret), so keymaster forces an authenticated read first and only proceeds when you approve.

## Building Keymaster

The biometric guard relies on a **restricted entitlement** (`keychain-access-groups`). macOS kills an unsigned/unprovisioned binary that carries it, so keymaster **cannot** be a plain `swiftc` binary — it must be built as a signed `.app` with your own Apple signing identity:

1. Open `keymaster/keymaster.xcodeproj` in Xcode.
2. Select the **keymaster** target ▸ **Signing & Capabilities** ▸ set your **Team** (automatic signing). The **Keychain Sharing** capability is already configured with the group `dev.mnck.keymaster`.
3. Build (⌘B). The actual CLI lives inside the app bundle at `Keymaster.app/Contents/MacOS/keymaster`.
4. Put it on your `PATH`, e.g. symlink the inner binary:

   ```bash
   ln -sf "/path/to/Keymaster.app/Contents/MacOS/keymaster" /usr/local/bin/keymaster
   ```

Requires a Mac with Touch ID and an Apple signing identity configured in Xcode.

## Save a secret to the keychain

The secret is read from **stdin**, never passed as an argument (an argument would leak via `ps` and shell history):

```bash
# Interactive: keymaster prompts and reads the secret without echoing it to the screen
keymaster set MyKeyName

# Piped: feed the secret in from another command
printf %s "$SECRET" | keymaster set MyKeyName
```

Piped input is read in full, so multi-line secrets (e.g. PEM keys) are preserved; a single trailing newline is trimmed. The interactive prompt reads one typed line. Secrets must be text (valid UTF-8), and an empty secret is rejected.

Creating a brand-new key does **not** prompt for Touch ID (the biometric access control is evaluated on access, not on creation). Overwriting an existing key **does** prompt and names the key.

## Retrieve a secret

`keymaster get MyKeyName`

A Touch ID prompt appears that **names the requested key** (e.g. `Read keychain secret: "MyKeyName"`), so a script asking for the wrong secret is visible at approval time. On a match, the secret is printed to stdout. Cancelling the prompt denies access, prints nothing, and exits non-zero.

## Remove a secret

`keymaster rm MyKeyName`

A Touch ID prompt naming the key (`Remove keychain secret: "MyKeyName"`) appears before the item is removed.

## Storage details

- **Keychain:** the modern data-protection keychain (`kSecUseDataProtectionKeychain`).
- **Item:** service `dev.mnck.<key>`, account `keymaster`, access group `<TeamID>.dev.mnck.keymaster`.
- **Accessibility:** `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` — items never sync to iCloud and never appear in backups, and they are **destroyed if you remove your device passcode**.
- **`.biometryAny`:** any currently-enrolled fingerprint/face can satisfy the prompt, and the item is *not* invalidated if you later add or remove an enrolled biometric.

## Migration from the previous version (breaking change)

The previous keymaster stored items in the **legacy** keychain with **no biometric protection**. This version uses the data-protection keychain, so old secrets are not found and must be re-`set` with the new build.

The old items are still there and are still readable by any process **with no Touch ID prompt**. Removing them is **required** to remove that exposure, not optional:

```bash
security delete-generic-password -s <oldkey>     # repeat per old key (or use Keychain Access.app)
```

You can use `keymaster` in bash scripts or Automator Workflows, or wherever you need biometric-gated access to a secret.
