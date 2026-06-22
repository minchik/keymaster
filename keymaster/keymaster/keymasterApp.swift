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
    subcommands: [Set.self, Get.self, Remove.self, Run.self, Version.self]
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
      let manager = SecretManager(backend: SystemKeychain())
      do {
        try manager.set(key: key, secret: Data(secret.utf8))
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
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
      let manager = SecretManager(backend: SystemKeychain())
      do {
        print(try manager.get(key: key))
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
  // unlocked by a SINGLE Touch ID prompt. Each `--key` names a secret to read and
  // the env var to inject it as (see parseKeyMapping); the trailing command after
  // `--` is exec'd with those vars merged over the current environment. Any
  // unreadable key aborts before the command runs, so it never launches with a
  // silently-missing secret.
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
      // resolveEnvironment authenticates once (the single prompt) and reads every
      // secret through it, aborting before exec if any read/decode fails — its
      // error names the offending key. Last write wins for a duplicated env name.
      let manager = SecretManager(backend: SystemKeychain())
      let injected: [String: String]
      do {
        injected = try manager.resolveEnvironment(mappings: mappings, reason: reason)
      } catch let error as KeychainError {
        fail(error.message)
      } catch {
        fail(error.localizedDescription)
      }
      // Qualify exit so it resolves to libc's, not ParsableCommand.exit(withError:).
      Foundation.exit(runProcess(command: command, extraEnv: injected))
    }
  }
}
