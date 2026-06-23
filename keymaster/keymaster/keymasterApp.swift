// Keymaster, access Keychain secrets guarded by Touch ID.
//
// This is an .app target only so the binary can carry the
// `keychain-access-groups` entitlement (a restricted entitlement that AMFI
// rejects on an unsigned/unprovisioned binary). At runtime it behaves as a
// CLI: `Keymaster.app/Contents/MacOS/keymaster <set|get|rm> <key>` does
// its Keychain work and exits before any AppKit run loop starts, so no window
// is shown.
//
// This file is now just the CLI surface: argument parsing plus stdin/version/IO
// glue. The secret-management logic lives in `SecretManager.swift` (Foundation
// only, unit-tested via a fake) behind the `KeychainBackend` protocol, whose real
// SecItem*/LAContext adapter is `SystemKeychain.swift`. Each command builds a
// `SecretManager(backend: SystemKeychain())` and turns a thrown `KeychainError`
// into the same stderr text the old code printed.
import ArgumentParser
import Foundation

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
  return readLineWithEchoOff()
}

// Read one line from a TTY with terminal echo disabled, so a typed secret never
// appears on screen. Reads in NON-canonical mode: the terminal's canonical
// (line-buffered) discipline caps one input line at `MAX_CANON` = 1024 bytes, so a
// longer pasted `refresh_token`/`client_secret` rings the bell and the overflow is
// silently discarded (and truncated if Enter is pressed). Clearing `ICANON`
// alongside `ECHO` lifts that cap; the cost is that the line editing the tty used to
// do for us (append / backspace / line terminators) must now be done by hand, so we
// read one byte at a time through the pure `noEchoLineEvent(after:into:)` reducer and
// decode the assembled bytes as UTF-8 once at the end. `VMIN`=1/`VTIME`=0 make each
// `read()` block for at least one byte with no inter-byte timer. A signal-interrupted
// `read()` (`EINTR`) is retried rather than treated as fatal, restoring the resilience
// the canonical `readLine()` had: its `getline` wrapper loops on EINTR, so a Ctrl-Z
// suspend / `fg` resume (or any signal delivered mid-read) resumes the prompt instead
// of aborting a half-typed secret. `ISIG` is left set, so Ctrl-C still interrupts. The
// caller writes any prompt to stderr first; this restores the original terminal
// settings and emits the suppressed newline on the way out. Aborts rather than falling
// through with echo on, which would print the secret.
func readLineWithEchoOff() -> String? {
  var original = termios()
  guard tcgetattr(STDIN_FILENO, &original) == 0 else {
    fail("could not read terminal settings")
  }
  var raw = original
  raw.c_lflag &= ~tcflag_t(ECHO | ICANON)
  withUnsafeMutableBytes(of: &raw.c_cc) { controls in
    controls[Int(VMIN)] = 1
    controls[Int(VTIME)] = 0
  }
  guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0 else {
    fail("could not disable terminal echo")
  }
  // Restoring the terminal must run on EVERY exit from raw mode, including the fatal
  // read-error path below — and `fail` calls exit(), which bypasses Swift's `defer`, so
  // that path calls this directly before failing while every normal exit goes through the
  // `defer`. (The two `fail`s above run before raw mode is entered, so they need no
  // restore.) Without it a non-EINTR `read()` error would leave the shell with
  // echo/canonical mode off.
  func restoreTerminal() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
    FileHandle.standardError.write(Data("\n".utf8))
  }
  defer { restoreTerminal() }
  var buffer: [UInt8] = []
  var byte: UInt8 = 0
  while true {
    let count = read(STDIN_FILENO, &byte, 1)
    if count < 0 {
      // A signal-interrupted read (`EINTR`) is not a real error — retry it, matching
      // the `readLine()` we replaced. Its `getline` wrapper loops on EINTR
      // (`do { … } while (result < 0 && errno == EINTR)`), so without this a Ctrl-Z
      // suspend / `fg` resume (or any signal delivered mid-read) would otherwise abort
      // a half-typed secret. Only a non-EINTR error is fatal.
      if errno == EINTR { continue }
      // A non-EINTR read error is fatal. `fail` exits the process, bypassing the
      // termios-restoring `defer`, so restore the terminal here first.
      restoreTerminal()
      fail("could not read terminal input")
    }
    if count == 0 {
      // Stream EOF: end like Ctrl-D — submit a typed line, else return nil. The
      // decode is intentionally lossy (matches the old `readLine`, which never
      // returned nil mid-line on invalid UTF-8), so silence the failable-init rule.
      // swiftlint:disable:next optional_data_string_conversion
      return buffer.isEmpty ? nil : String(decoding: buffer, as: UTF8.self)
    }
    switch noEchoLineEvent(after: byte, into: &buffer) {
    case .continue:
      continue
    case .endLine:
      // swiftlint:disable:next optional_data_string_conversion
      return String(decoding: buffer, as: UTF8.self)
    case .endInput:
      return nil
    }
  }
}

// Print a human-readable error and exit non-zero. Kept out of the testable
// SecretManager layer because it calls exit().
func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data("Error: \(message)\n".utf8))
  exit(EXIT_FAILURE)
}

// Read CFBundleShortVersionString (= MARKETING_VERSION) from the bundle. keymaster
// ships as a signed .app and is usually run through a symlink (Homebrew puts one in
// its bin); launched that way, Bundle.main resolves to the symlink's directory, not
// the .app, so its Info.plist is missing. Resolve the real executable path and load
// the bundle that actually contains it, falling back to Bundle.main when run in place.
func marketingVersion() -> String {
  let info: [String: Any]?
  if let executable = Bundle.main.executableURL?.resolvingSymlinksInPath() {
    // <app>/Contents/MacOS/keymaster -> <app>
    let appURL = executable
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    info = Bundle(url: appURL)?.infoDictionary ?? Bundle.main.infoDictionary
  } else {
    info = Bundle.main.infoDictionary
  }
  return info?["CFBundleShortVersionString"] as? String ?? "unknown"
}

@main
struct Keymaster: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "keymaster",
    abstract: "Store and retrieve Keychain secrets guarded by Touch ID.",
    subcommands: [Set.self, Get.self, Remove.self, Run.self, OAuth.self, Version.self]
  )
}

extension Keymaster {
  // Store a secret read from stdin. No Touch ID prompt on first create (the ACL
  // is evaluated on access, not creation); an overwrite prompts via the upsert's
  // authenticated read inside SecretManager.set.
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
      let keychain = SystemKeychain()
      do {
        // Symmetric cross-namespace guard: a name lives in exactly one store, so if this
        // name already holds an OAuth record, refuse rather than overwrite it. `storeSecret`
        // runs a no-prompt `exists` probe of the OAuth namespace FIRST and throws
        // `.crossNamespaceConflict` (naming the `oauth rm` command) without writing anything;
        // otherwise it upserts the plain secret as today.
        try storeSecret(Data(secret.utf8), name: key, in: .secret, conflictingWith: .oauth, backend: keychain)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
      print("Key \"\(key)\" has been set in the keychain")
    }
  }

  // Retrieve a secret, OR mint a fresh access token for an OAuth record, under a
  // SINGLE Touch ID prompt. The resolver authenticates ONCE, then classifies the
  // name's namespace THROUGH that session (no separate probe prompt): a plain secret
  // is read and printed as-is; an OAuth record is exchanged for a fresh access token
  // (printed to stdout, with any rotated-but-unsaved warning on stderr — so
  // `$(keymaster get X)` stays clean). Classifying under the one approval is the
  // intended security property: keymaster never reveals whether a name exists without
  // a biometric approval first. So a name in neither store aborts AFTER the one prompt
  // with a deliberate, key-prefixed "not found" — the absence is not leaked before the
  // prompt. The resolver already prefixes its errors with the key, so this surfaces
  // them verbatim.
  struct Get: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Retrieve a secret or mint an OAuth access token, gated by Touch ID."
    )

    @Argument(help: "The key to retrieve.")
    var key: String

    func run() {
      let keychain = SystemKeychain()
      let oauth = OAuthManager(backend: keychain, exchanger: URLSessionTokenExchanger())
      do {
        let result = try oauth.resolveSecret(name: key, reason: "Read keychain secret: \"\(key)\"")
        if result.refreshTokenStale { warnStaleRefreshToken(key) }
        print(result.value)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
    }
  }

  // Print keymaster's version, read from the bundle by marketingVersion() (see
  // there for why Bundle.main alone is not enough). The release workflow sets the
  // bundle's marketing version from the git tag, so a released build reports its
  // real version and a local build the project default.
  struct Version: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Print the version."
    )

    func run() {
      print("keymaster \(marketingVersion())")
    }
  }

  // Remove a secret; SecretManager.remove forces a Touch ID read before deleting.
  struct Remove: ParsableCommand {
    static let configuration = CommandConfiguration(
      commandName: "rm",
      abstract: "Remove a secret, gated by Touch ID."
    )

    @Argument(help: "The key to remove.")
    var key: String

    func run() {
      let manager = SecretManager(backend: SystemKeychain())
      do {
        try manager.remove(key: key)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
      print("Key \"\(key)\" has been removed from the keychain")
    }
  }

  // Run a command with keychain secrets injected as environment variables, all
  // unlocked by a SINGLE Touch ID prompt. Each `--key` names a value to inject and
  // the env var to inject it as (see parseKeyMapping); a plain-secret key is read
  // as-is, an OAuth-record key is exchanged for a fresh access token. The resolver
  // authenticates ONCE, then classifies every name's namespace THROUGH that session.
  // Classifying under the one approval is the intended security property: a name's
  // existence is never disclosed without a biometric approval first. So a name in
  // neither store aborts AFTER the one prompt (but still before exec) — it never
  // launches with a silently-missing secret, and never leaks the name's absence
  // before the prompt. The trailing command after `--` is exec'd with those vars
  // merged over the current environment.
  struct Run: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Run a command with keychain secrets injected as env vars (one Touch ID prompt)."
    )

    @Option(
      name: .customLong("key"),
      help: ArgumentHelp(
        "Secret to inject. \"NAME\" sets env NAME from key NAME; \"ENV=key\" sets env ENV from key 'key'. Repeatable.",
        valueName: "NAME|ENV=key"
      )
    )
    var keys: [String]

    @Argument(
      parsing: .postTerminator,
      help: ArgumentHelp(
        "The command to run, after `--`, e.g. -- ./deploy.sh --flag.",
        valueName: "-- command [args...]"
      )
    )
    var command: [String]

    // Rules that don't touch the keychain live here (and in parseKeyMapping) so a
    // malformed invocation is rejected before any Touch ID prompt or exec.
    func validate() throws {
      guard !keys.isEmpty else {
        throw ValidationError("provide at least one --key")
      }
      guard !command.isEmpty else {
        throw ValidationError("provide a command after --")
      }
      for raw in keys { _ = try parseKeyMapping(raw) }
    }

    func run() {
      // validate() already proved every --key parses, so this cannot throw.
      let mappings = keys.compactMap { try? parseKeyMapping($0) }
      let program = command.first ?? ""
      let names = mappings.map { "\"\($0.key)\"" }.joined(separator: ", ")
      let reason = "Run \"\(program)\" with keychain secrets: \(names)"
      let keychain = SystemKeychain()
      let oauth = OAuthManager(backend: keychain, exchanger: URLSessionTokenExchanger())
      // resolveRunEnvironment authenticates once (the single prompt) and resolves
      // every mapping THROUGH that session — classifying each name's namespace,
      // reading+decoding `.secret` keys, and minting `.oauth` keys into a fresh access
      // token — aborting before exec if any classify/read/mint/decode fails or a name
      // is in neither store (its error names the offending key). The classify now rides
      // the single approval, so a missing key aborts after the prompt rather than before
      // it. Last write wins for a duplicated env name. A key whose rotated refresh token
      // failed to persist is reported in staleKeys (non-fatal): warn on stderr and
      // proceed with the still-valid token.
      let injected: [String: String]
      let staleKeys: [String]
      do {
        (injected, staleKeys) = try oauth.resolveRunEnvironment(mappings: mappings, reason: reason)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
      for key in staleKeys { warnStaleRefreshToken(key) }
      // Qualify exit so it resolves to libc's, not ParsableCommand.exit(withError:).
      Foundation.exit(runProcess(command: command, extraEnv: injected))
    }
  }
}

// Warn loudly on stderr that the provider rotated the refresh token but persisting
// the new one failed (the in-place keychain update did not stick). The just-minted
// access token is still valid for this use, so this is a NON-fatal heads-up, not an
// abort — the caller still emits the token. Shared by `get` and `run`.
func warnStaleRefreshToken(_ key: String) {
  let message = "Warning: \"\(key)\" rotated its refresh token but the new one could not be saved; "
    + "re-run `keymaster oauth set \(key)` to store it.\n"
  FileHandle.standardError.write(Data(message.utf8))
}

// Map "" (and nil) to nil so an empty answer for an optional OAuth field
// (client_secret, scopes) is stored as absent rather than an empty string.
func emptyToNil(_ value: String?) -> String? {
  guard let value = value, !value.isEmpty else { return nil }
  return value
}

// Prompt on stderr for one OAuth-record field and read it from the TTY. Secret
// fields (client_secret, refresh_token) are read with echo disabled — reusing
// readSecret's no-echo handling — so they never appear on screen; the rest echo
// normally. Returns the typed line (empty allowed; validate() rejects empty
// required fields), or nil only on EOF.
func promptField(_ label: String, secret: Bool) -> String? {
  FileHandle.standardError.write(Data("\(label): ".utf8))
  return secret ? readLineWithEchoOff() : readLine(strippingNewline: true)
}

// Build an OAuthRecord by prompting for each field on a TTY. Required fields default
// to "" on EOF so validate() surfaces the proper "<field> is required" message;
// empty optional fields collapse to nil. Field content is not checked here — the
// caller runs record.validate() before storing.
func readOAuthRecordInteractively() -> OAuthRecord {
  let tokenEndpoint = promptField("token_endpoint (https URL)", secret: false) ?? ""
  let clientID = promptField("client_id", secret: false) ?? ""
  let clientSecret = promptField("client_secret (optional, hidden)", secret: true)
  let refreshToken = promptField("refresh_token (hidden)", secret: true) ?? ""
  let scopes = promptField("scopes (optional, space-separated)", secret: false)
  return OAuthRecord(
    tokenEndpoint: tokenEndpoint,
    clientID: clientID,
    clientSecret: emptyToNil(clientSecret),
    refreshToken: refreshToken,
    scopes: emptyToNil(scopes)
  )
}

// Decode an OAuthRecord from JSON piped on stdin (the non-TTY `oauth set` path), so
// records can be provisioned non-interactively. A malformed body or a missing
// required field aborts before anything is stored. Content validity is the caller's
// record.validate() responsibility.
func decodeOAuthRecordFromStdin() -> OAuthRecord {
  let data = FileHandle.standardInput.readDataToEndOfFile()
  do {
    return try JSONDecoder().decode(OAuthRecord.self, from: data)
  } catch {
    fail("stdin did not contain a valid OAuth record JSON (need token_endpoint, client_id, refresh_token)")
  }
}

extension Keymaster {
  // Manage OAuth refresh-token credential records (the dev.mnck.oauth.* namespace),
  // the credentials `keymaster get`/`run` mint a fresh access token from. `set`
  // stores a record, `get` prints the stored record JSON (Touch ID), and `rm`
  // removes it (Touch ID) — mirroring the plain set/get/rm but on the OAuth store.
  struct OAuth: ParsableCommand {
    static let configuration = CommandConfiguration(
      commandName: "oauth",
      abstract: "Manage OAuth refresh-token records used to mint access tokens.",
      subcommands: [Set.self, Get.self, Remove.self]
    )
  }
}

extension Keymaster.OAuth {
  // Store an OAuth record. On a TTY each field is prompted in turn (client_secret
  // and refresh_token with echo off); otherwise the record is read as JSON from
  // stdin. The record is validated, then upserted as canonical JSON via
  // SecretManager on the .oauth store — a first create does not prompt, an overwrite
  // prompts via the upsert's authenticated read. If the name already exists as a
  // plain secret, `storeSecret` refuses (a name lives in exactly one store) and tells
  // you to `keymaster rm` it first, writing nothing.
  struct Set: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Store an OAuth record read from prompts (TTY) or JSON on stdin."
    )

    @Argument(help: "The name to store the OAuth record under.")
    var name: String

    func run() {
      let record = isatty(STDIN_FILENO) != 0
        ? readOAuthRecordInteractively()
        : decodeOAuthRecordFromStdin()
      let keychain = SystemKeychain()
      do {
        try record.validate()
        let encoded = try record.encoded()
        // A name lives in exactly one store, so if this name already holds a plain secret,
        // refuse rather than overwrite it. `storeSecret` runs a no-prompt `exists` probe of
        // the plain namespace FIRST and throws `.crossNamespaceConflict` (naming the `rm`
        // command) without writing anything; otherwise it upserts the OAuth record as today.
        try storeSecret(encoded, name: name, in: .oauth, conflictingWith: .secret, backend: keychain)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
      print("OAuth record \"\(name)\" has been set in the keychain")
    }
  }

  // Print a stored OAuth record's JSON; the Keychain challenges Touch ID on the read.
  struct Get: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Print a stored OAuth record's JSON, gated by Touch ID."
    )

    @Argument(help: "The name of the OAuth record to print.")
    var name: String

    func run() {
      let manager = SecretManager(backend: SystemKeychain(), namespace: .oauth)
      do {
        print(try manager.get(key: name))
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
    }
  }

  // Remove a stored OAuth record; SecretManager.remove forces a Touch ID read before
  // deleting (read-before-delete), so a cancelled prompt leaves the record intact.
  struct Remove: ParsableCommand {
    static let configuration = CommandConfiguration(
      commandName: "rm",
      abstract: "Remove a stored OAuth record, gated by Touch ID."
    )

    @Argument(help: "The name of the OAuth record to remove.")
    var name: String

    func run() {
      let manager = SecretManager(backend: SystemKeychain(), namespace: .oauth)
      do {
        try manager.remove(key: name)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
      print("OAuth record \"\(name)\" has been removed from the keychain")
    }
  }
}
