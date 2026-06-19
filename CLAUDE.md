# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Keymaster is a macOS Swift CLI that stores/retrieves Keychain secrets guarded by Touch ID. It is built as a **signed `.app`**, not a bare `swiftc` binary, because the biometric guard needs the restricted `keychain-access-groups` entitlement (AMFI kills an unsigned/unprovisioned binary that carries it). The program is a CLI: its entry point in `keymaster/keymaster/keymasterApp.swift` does the Keychain work and `exit()`s before any AppKit run loop starts, so no window is shown. All logic lives in that one file.

## Build

Open `keymaster/keymaster.xcodeproj` in Xcode, select the **keymaster** target ▸ **Signing & Capabilities**, set your **Team** (automatic signing; the Keychain Sharing capability + group `dev.mnck.keymaster` are already configured), and build (⌘B). The CLI binary is inside the bundle at `Keymaster.app/Contents/MacOS/keymaster`.

### Dependency

Argument parsing uses [swift-argument-parser](https://github.com/apple/swift-argument-parser) — each subcommand (`set`/`get`/`rm`) is a `ParsableCommand` in `keymasterApp.swift`; the Keychain logic stays in that same file. It is wired in as an SPM package and **resolved automatically**: Xcode fetches it on first build, and the release workflow's `xcodebuild archive` fetches it on a clean runner (no `-disableAutomaticPackageResolution`). The pinned version lives in `keymaster.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`, which is **committed** so CI builds are reproducible rather than re-resolving to the latest `1.x`. The library links statically into the binary, so there is no extra framework to sign or notarize. If you ever re-add the package by hand, link **only** the `ArgumentParser` library product to the **keymaster** target — leave the `generate-manual` and `generate-docc-reference` executable products set to **None**.

A plain `swiftc keymaster*.swift` build will **not** work: the biometric `kSecAttrAccessControl` requires the `keychain-access-groups` entitlement, an unsigned binary that adds without it gets `errSecMissingEntitlement` (-34018), and a binary that carries it without a provisioning profile is SIGKILLed by AMFI. The `.app` target is what supplies the profile.

## Testing

There is no automated test suite — biometric prompts can't run headless or in CI. Build and verify by hand on a Touch ID Mac:

- `set <newkey>`: stores the secret, **no** Touch ID prompt (the ACL is evaluated on access, not on creation).
- `get <key>`: the Keychain challenges Touch ID; the prompt names the key.
- `rm <key>` and overwrite (`set` on an existing key): both prompt. `SecItemDelete` does not decrypt the item, so the biometric ACL would not challenge it on its own — keymaster forces an authenticated read (`readItem`) first and proceeds only on `errSecSuccess`.

Items live in the data-protection keychain (`kSecUseDataProtectionKeychain`), scoped to the access group from the entitlement. The legacy `security` CLI cannot see them, so a `security find-generic-password` "item not found" is expected and is **not** evidence of a bypass; the meaningful check is that `get` requires Touch ID.

## Linting

```bash
swiftlint   # uses .swiftlint.yml; install with: brew install swiftlint
```

Indent with 2 spaces (matches existing code).

## Usage

The secret is read from **stdin**, never passed as an argument (an argument would leak via `ps` and shell history, CWE-214):

```
keymaster set <key>            # store a secret read from stdin; prompts on overwrite, not on first create
keymaster get <key>            # retrieve, gated by Touch ID
keymaster rm <key>             # remove, gated by Touch ID
```

```bash
printf %s "$SECRET" | keymaster set MyKeyName   # piped
keymaster set MyKeyName                          # interactive no-echo prompt
```

## Storage

Items are stored in the data-protection keychain under service `dev.mnck.<key>`, account `keymaster`, access group `<TeamID>.dev.mnck.keymaster`, accessibility `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, and a `.biometryAny` access control.
