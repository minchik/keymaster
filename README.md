# Keymaster

Keymaster lets scripts store and read macOS Keychain secrets guarded by Touch ID **or a paired Apple Watch**.

Macs come with the `security` command which can get and set secrets in the Keychain:

```bash
# Save a key/value to the default "login" keychain, with key "MyKeyName", update if exists (-U),
# allow no app to access without a prompt (-T ""), and prompt for secret to store (-w)
security add-generic-password -a login -s "MyKeyName" -T "" -U -w

# Get the secret value from a key
security find-generic-password -s "MyKeyName" -w
```

You can use `security` in a script, but (AFAIK) you can't tell it to guard secrets with biometrics — you have to enter the password each time, or "always allow" the `security` binary to access the secret. "Always allow" is exactly the weakening you don't want: it lets any process running as you read the plaintext with no challenge.

🔑 Keymaster fixes this. Each secret is stored in the **data-protection keychain** with a biometric access-control object (`[.biometryAny, .or, .companion]`) and scoped to keymaster's own keychain access group, so:

- **Reading a secret triggers a Touch ID challenge from the Keychain itself** (a nearby unlocked paired Apple Watch can approve it instead, via a side-button double-click) — there is no "always allow" to grant.
- The items are **isolated by entitlement**: only a binary signed into keymaster's access group can see them at all. Another process running as you can't read them with `security find-generic-password` — it won't even find them.
- **Removing and overwriting are gated by Touch ID too.** The Keychain does not challenge removal on its own (removing doesn't decrypt the secret), so keymaster forces an authenticated read first and only proceeds when you approve.

## Installing

The easiest way is Homebrew, via the [`minchik/tap`](https://github.com/minchik/homebrew-tap) cask:

```bash
brew install --cask minchik/tap/keymaster
```

This downloads the signed release `.app` and symlinks the inner `keymaster` CLI onto your `PATH`, so there's nothing to build or sign yourself. Upgrade with `brew upgrade --cask keymaster` and remove with `brew uninstall --cask keymaster`.

Requires a Mac with Touch ID (a paired, unlocked Apple Watch can approve prompts as an alternative).

## Building from source

The biometric guard relies on a **restricted entitlement** (`keychain-access-groups`). macOS kills an unsigned/unprovisioned binary that carries it, so keymaster **cannot** be a plain `swiftc` binary — it must be built as a signed `.app` with your own Apple signing identity:

1. Open `keymaster/keymaster.xcodeproj` in Xcode.
2. Select the **keymaster** target ▸ **Signing & Capabilities** ▸ set your **Team** (automatic signing). The **Keychain Sharing** capability is already configured with the group `dev.mnck.keymaster`.
3. Build (⌘B). The actual CLI lives inside the app bundle at `Keymaster.app/Contents/MacOS/keymaster`.
4. Put it on your `PATH`, e.g. symlink the inner binary:

   ```bash
   ln -sf "/path/to/Keymaster.app/Contents/MacOS/keymaster" /usr/local/bin/keymaster
   ```

Keymaster depends on [swift-argument-parser](https://github.com/apple/swift-argument-parser); Xcode resolves and fetches it automatically on the first build (the exact version is pinned in the project's committed `Package.resolved`), so the only requirement beyond Xcode is an internet connection on that first build.

Requires a Mac with Touch ID (a paired, unlocked Apple Watch can approve prompts as an alternative) and an Apple signing identity configured in Xcode.

## Save a secret to the keychain

The secret is read from **stdin**, never passed as an argument (an argument would leak via `ps` and shell history):

```bash
# Interactive: keymaster prompts and reads the secret without echoing it to the screen
keymaster set MyKeyName

# Piped: feed the secret in from another command
printf %s "$SECRET" | keymaster set MyKeyName
```

Piped input is read in full, so multi-line secrets (e.g. PEM keys) are preserved; a single trailing newline is trimmed. The interactive prompt reads one typed line. Secrets must be text (valid UTF-8) with no embedded NUL byte (one could never be injected as an environment variable, so it is refused at write time rather than stored unretrievably), and an empty secret is rejected.

Creating a brand-new key does **not** prompt for Touch ID (the biometric access control is evaluated on access, not on creation). Overwriting an existing key **does** prompt and names the key.

If the name already holds an [OAuth record](#oauth-refresh-token-records), `set` **refuses** and writes nothing — a name lives in exactly one store (see [OAuth refresh-token records](#oauth-refresh-token-records) below). Remove the OAuth record first with `keymaster oauth rm MyKeyName`, then re-run `set`.

## Retrieve a secret

`keymaster get MyKeyName`

A Touch ID prompt (which a paired Apple Watch can also approve, via a side-button double-click) appears that **names the requested key** (e.g. `Read keychain secret: "MyKeyName"`), so a script asking for the wrong secret is visible at approval time. On a match, the secret is printed to stdout. Cancelling the prompt denies access, prints nothing, and exits non-zero.

If the name is an [OAuth record](#oauth-refresh-token-records) rather than a plain secret, `get` instead mints a fresh access token from it and prints **only** that token — see below. The namespace is classified through that same single approval — by design, so keymaster never discloses whether a name exists without a Touch ID approval first. A name in neither store therefore fails *after* the one prompt, naming the key and doing nothing else; its absence is never leaked before the prompt.

## Remove a secret

`keymaster rm MyKeyName`

A Touch ID prompt (or Apple Watch approval) naming the key (`Remove keychain secret: "MyKeyName"`) appears before the item is removed.

## Run a command with secrets

`keymaster run` injects one or more keychain secrets into a child process as environment variables, unlocking the whole batch with a **single** Touch ID prompt (which a paired Apple Watch can also approve). It's modelled on `op run`:

```bash
keymaster run --key API_TOKEN --key DB_PASS=prod-db-password -- ./deploy.sh --flag
```

Everything after `--` is the command to run. Each `--key` is repeatable and names a secret to inject:

- `--key NAME` — read keychain key `NAME` and inject it as environment variable `NAME`.
- `--key ENVNAME=keychainkey` — read keychain key `keychainkey` and inject it as environment variable `ENVNAME`. The split is on the **first** `=` only, so keychain keys may themselves contain `=`.

A key may name either a plain secret or an [OAuth record](#oauth-refresh-token-records). Every name is classified (plain vs OAuth) *through* the single Touch ID approval itself — the probe rides that one prompt. This is the intended security guarantee, not just a prompt-saving trick: keymaster never discloses whether a name exists without a biometric approval first, so a name in neither store aborts the batch *after* the prompt, naming the key, rather than leaking its absence beforehand; an OAuth key is minted into a fresh access token under that same one prompt.

The injected variables are merged over the current environment (a `--key` that names an existing env var overrides it; a duplicated env name keeps the last one). The command is launched through `/usr/bin/env`, so a bare program name like `node` is resolved against `PATH`, and stdio is inherited so the child talks to your terminal directly.

**One prompt for the whole batch.** A single Touch ID prompt appears whose text names every requested key and the program, e.g. `Run "./deploy.sh" with keychain secrets: "API_TOKEN", "prod-db-password"` (the prompt names the keychain keys being unlocked, so a renamed `ENV=key` shows the key side). Approving it once reads all the secrets; you are not challenged per secret. (This reuses one pre-authenticated authentication context, not a time-based reuse window, so each `run` still forces a fresh Touch ID.)

**Abort before exec on any failure.** If any requested key is missing or unreadable, `keymaster run` prints a message naming that key and exits non-zero **without** launching the command — it never runs with a silently-missing secret. Cancelling the Touch ID prompt likewise exits non-zero and runs nothing.

The secret never appears on a command line: it is handed to the child through its environment, not as an argument, so it stays out of keymaster's (and the child's) argv and out of your shell history — the classic argv leak (CWE-214) doesn't apply. It does, though, live in the child's environment for the child's lifetime: it is inherited by anything the child spawns, is readable by `root`, and may be surfaced by tools that read process environments (`ps -E` is documented to print them, though current macOS restricts what it returns) — visibility depends on your OS version, tooling, and permissions. So **once injected the secret is no longer behind the biometric guard** — it is only as private as the process tree you hand it to. The child's exit code is forwarded as keymaster's own (a child killed by a signal is reported as `128 + signal number`, mirroring shell convention).

A handy pattern is a small wrapper script that runs a tool with its secrets injected. For example, to give [Taskwarrior](https://taskwarrior.org) its sync credentials behind a single Touch ID prompt:

```sh
#!/bin/sh

keymaster run \
  --key TASKWARRIOR_SYNC_URL \
  --key TASKWARRIOR_CLIENT_ID \
  --key TASKWARRIOR_ENCRYPTION_SECRET \
  -- task sync
```

## OAuth refresh-token records

Some APIs don't take a static secret — they hand out a long-lived **refresh token** that you exchange for a short-lived **access token** whenever you need one. Keymaster can store the refresh-token credential behind Touch ID and do that exchange for you on demand (the RFC 6749 §6 refresh-token grant), so scripts never hold an expiring access token and you never copy one by hand.

Store a record under a name:

```bash
# Interactive: keymaster prompts for each field (client_secret and refresh_token are read without echo)
keymaster oauth set GitHub

# Non-interactive: pipe the whole record as JSON
printf '%s' '{"token_endpoint":"https://example.com/token","client_id":"abc","refresh_token":"r0","scopes":"repo"}' \
  | keymaster oauth set GitHub
```

A record has three required fields — `token_endpoint` (must be `https`), `client_id`, and `refresh_token` — plus optional `client_secret` (omit it for a public client) and `scopes`. Creating a record does **not** prompt for Touch ID; overwriting one does.

If the name already holds a plain secret, `oauth set` **refuses** and writes nothing — a name lives in exactly one store (see **One name, one store** below). Remove the plain secret first with `keymaster rm GitHub`, then re-run `oauth set`.

Mint an access token from a stored record:

```bash
keymaster get GitHub                           # Touch ID → prints ONLY the access token to stdout
keymaster run --key TOKEN=GitHub -- ./deploy   # injects a freshly-minted TOKEN under one prompt
```

`keymaster get <name>` unlocks the record with one Touch ID prompt (or Apple Watch approval), exchanges the refresh token, and prints **only** the access token to stdout — so `$(keymaster get GitHub)` captures a clean token — while any warning goes to stderr. `keymaster run` treats an OAuth key like a plain one: it is classified through the single prompt and minted into a fresh access token under it. Keymaster never caches a token; it mints a fresh one each time.

Inspect or delete a record (both gated by Touch ID or Apple Watch):

```bash
keymaster oauth get GitHub    # print the stored record as JSON
keymaster oauth rm GitHub     # remove the record
```

**No redirects.** The token exchange never follows HTTP redirects — to avoid resending the refresh token (and any `client_secret`) to another host, a token endpoint that responds with a 3xx **fails** the request rather than minting.

**Rotation.** If the provider returns a new `refresh_token` (token rotation), keymaster updates the stored record in place, atomically, with no extra prompt, preserving any extra keys the stored JSON happened to carry (the write-back edits the `refresh_token` field in the stored object rather than rewriting it from scratch). If that write-back ever fails, the access token it just minted is still used and a warning is printed to **stderr** telling you to re-run `keymaster oauth set` — it does not abort. An expired or revoked refresh token surfaces a clear `invalid_grant` → "re-run oauth set" message.

**One name, one store.** A name is either a plain secret or an OAuth record, never both. If you `set` a plain secret over an existing OAuth record (or `oauth set` over an existing plain secret), keymaster **refuses** and writes nothing — the existing item is left untouched. A no-prompt `exists` probe of the other namespace runs before any write, so the refusal costs no Touch ID prompt and names the exact `rm` command to remove the old item. The probe is fail-closed: if the keychain can't determine presence (a transient error), the write refuses rather than silently skipping the cross-namespace check. To replace the credential, remove the old item first (`keymaster oauth rm <name>` or `keymaster rm <name>`), then create the new one.

## Storage details

- **Keychain:** the modern data-protection keychain (`kSecUseDataProtectionKeychain`).
- **Item:** service `dev.mnck.<key>`, account `keymaster`, access group `<TeamID>.dev.mnck.keymaster`.
- **OAuth records:** the same keychain, access group, accessibility, and access control, but under a separate service prefix `dev.mnck.oauth.<name>` **and** a distinct account `keymaster.oauth`, holding the whole credential as JSON (written canonically at `oauth set` time; a rotation write-back stays decode-equivalent but not byte-canonical). (The distinct account keeps the prefix-overlapping namespaces from ever aliasing — a plain key `oauth.<name>` would otherwise share the OAuth record `<name>`'s service string.)
- **Accessibility:** `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` — items never sync to iCloud and never appear in backups, and they are **destroyed if you remove your device passcode**.
- **`[.biometryAny, .or, .companion]`:** Touch ID (any currently-enrolled fingerprint/face) **or** a paired Apple Watch (side-button double-click) can satisfy the prompt; the item is *not* invalidated if you later add or remove an enrolled biometric. There is **no passcode fallback** (`.userPresence`/`.devicePasscode` are deliberately unused).

## Migration from the previous version (breaking change)

The previous keymaster stored items in the **legacy** keychain with **no biometric protection**. This version uses the data-protection keychain, so old secrets are not found and must be re-`set` with the new build.

The old items are still there and are still readable by any process **with no Touch ID prompt**. Removing them is **required** to remove that exposure, not optional:

```bash
security delete-generic-password -s <oldkey>     # repeat per old key (or use Keychain Access.app)
```

You can use `keymaster` in bash scripts or Automator Workflows, or wherever you need biometric-gated access to a secret.
