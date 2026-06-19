# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Keymaster is a single-file Swift CLI that stores/retrieves macOS Keychain secrets guarded by TouchID. All logic lives in `keymaster.swift`.

## Build

No `Package.swift` — compile the single file directly:

```bash
swiftc keymaster.swift   # produces ./keymaster
```

## Testing

There is no automated test suite. Biometric enforcement is a property of the stored Keychain item: each secret is written with a biometric `kSecAttrAccessControl` (`.biometryAny`), and `get`/`delete`/overwrite bind a fresh `LAContext` via `kSecUseAuthenticationContext`, so the **Keychain itself** shows an **interactive TouchID prompt** on access. (There is no standalone `LAContext.evaluatePolicy`/`dispatchMain` gate anymore — that was cosmetic.) The tool cannot run headless or in CI. Verify changes by building and running `get`/`set`/`delete` by hand on a Mac and approving the prompt. Note: creating a brand-new key via `set` does NOT prompt (the ACL is evaluated on access, not creation); overwrite/get/delete do.

## Linting

```bash
swiftlint   # uses .swiftlint.yml; install with: brew install swiftlint
```

Indent with 2 spaces (matches existing code).

## Usage

The secret is read from **stdin**, never passed as an argument (an argument would leak via `ps` and shell history, CWE-214):

```
keymaster set <key>            # store a secret read from stdin, gated by TouchID
keymaster get <key>            # retrieve, gated by TouchID
keymaster delete <key>         # remove, gated by TouchID
```

```bash
printf %s "$SECRET" | keymaster set MyKeyName   # piped
keymaster set MyKeyName                          # interactive no-echo prompt
```

Items are stored under a namespaced service (`dev.mnck.<key>`) with a fixed account (`keymaster`).
