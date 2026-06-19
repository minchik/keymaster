# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Keymaster is a single-file Swift CLI that stores/retrieves macOS Keychain secrets guarded by TouchID. All logic lives in `keymaster.swift`.

## Build

No `Package.swift` — compile the single file directly:

```bash
swiftc keymaster.swift   # produces ./keymaster
```

## Testing

There is no automated test suite. Every command calls `LAContext.evaluatePolicy`, which shows an **interactive TouchID prompt**, so the tool cannot run headless or in CI. Verify changes by building and running `get`/`set`/`delete` by hand on a Mac and approving the prompt.

## Linting

```bash
swiftlint   # uses .swiftlint.yml; install with: brew install swiftlint
```

Indent with 2 spaces (matches existing code).

## Usage

```
keymaster set <key> <secret>   # store, gated by TouchID
keymaster get <key>            # retrieve, gated by TouchID
keymaster delete <key>         # remove, gated by TouchID
```
