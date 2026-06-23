//
//  DecodeTests.swift
//  keymasterTests
//
//  Unit tests for the Foundation-only decode helpers in SecretManager.swift and
//  the KeychainError display text. The shared file is compiled directly into this
//  host-less bundle via a synchronized-group membership exception, so a plain
//  `import Foundation` reaches its symbols — no app module import.
import Foundation
import Testing

struct DecodeTests {

  // MARK: decodeSecret

  @Test func decodeSecretReturnsUtf8String() throws {
    #expect(try decodeSecret(Data("hunter2".utf8)) == "hunter2")
  }

  @Test func decodeSecretRejectsNonUtf8() {
    // 0xFF is never a valid UTF-8 lead byte, so the decode fails as .invalidData.
    #expect(throws: KeychainError.invalidData) {
      _ = try decodeSecret(Data([0xFF]))
    }
  }

  @Test func decodeSecretAllowsEmbeddedNul() throws {
    // decodeSecret has no NUL restriction (only env values forbid one), so a NUL
    // round-trips as U+0000 — get/set store and surface secrets verbatim.
    #expect(try decodeSecret(Data("a\0b".utf8)) == "a\0b")
  }

  // MARK: decodeEnvValue

  @Test func decodeEnvValueReturnsUtf8String() throws {
    #expect(try decodeEnvValue(Data("value".utf8)) == "value")
  }

  @Test func decodeEnvValueRejectsNonUtf8() {
    #expect(throws: KeychainError.invalidData) {
      _ = try decodeEnvValue(Data([0xFF]))
    }
  }

  @Test func decodeEnvValueRejectsEmbeddedNul() {
    // A POSIX environment value cannot contain a NUL; reject it so the run batch
    // aborts before exec rather than crashing in Process.run().
    #expect(throws: KeychainError.containsNul) {
      _ = try decodeEnvValue(Data("a\0b".utf8))
    }
  }

  // MARK: KeychainError.message

  // The display text must stay byte-identical to the pre-refactor stderr strings
  // (the old secretString/envSecret/failKeychain output) so the CLI's observable
  // error output is unchanged.
  @Test func errorMessagesMatchPreRefactorText() {
    #expect(KeychainError.noData.message == "keychain returned no data")
    #expect(KeychainError.invalidData.message == "stored secret is not valid UTF-8")
    #expect(KeychainError.containsNul.message
      == "secret contains a NUL byte and cannot be used as an environment variable")
    #expect(KeychainError.status("a message").message == "a message")
    // `.duplicate` can surface only on the upsert re-add race; its text must equal
    // SecCopyErrorMessageString(errSecDuplicateItem), which the pre-refactor
    // failKeychain printed on that path.
    #expect(KeychainError.duplicate.message == "The specified item already exists in the keychain.")
  }

}
