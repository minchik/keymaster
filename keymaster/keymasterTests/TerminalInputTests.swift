//
//  TerminalInputTests.swift
//  keymasterTests
//
//  Unit tests for the Foundation-only no-echo line-editing reducer in
//  TerminalInput.swift (`noEchoLineEvent(after:into:)`). This is the pure logic
//  extracted from the `readLineWithEchoOff` TTY wrapper so the per-byte editing
//  decisions — append, backspace-erase, CR/LF/Ctrl-D terminators — can be tested
//  headlessly; the termios setup and the `read()` loop stay manual (TTY syscalls).
//  The key regression is that a >1024-byte line assembles losslessly: the old
//  canonical-mode prompt capped a line at `MAX_CANON` = 1024 bytes, and this
//  reducer is what replaces that line discipline without the cap.
//
//  The file under test is compiled directly into this host-less bundle via a
//  synchronized-group membership exception, so a plain `import Foundation` reaches
//  its symbols — no app import.
import Foundation
import Testing

struct TerminalInputTests {

  // Drive the reducer over a byte sequence exactly as the real `read()` loop
  // would: feed bytes one at a time until the reducer reports a terminator.
  // Returns the assembled bytes on `endLine`, or nil on `endInput`/exhaustion
  // (a stream that ends with no terminator behaves like the old `readLine` EOF).
  private func run(_ bytes: [UInt8]) -> [UInt8]? {
    var buffer: [UInt8] = []
    for byte in bytes {
      switch noEchoLineEvent(after: byte, into: &buffer) {
      case .continue:
        continue
      case .endLine:
        return buffer
      case .endInput:
        return nil
      }
    }
    return nil
  }

  // Decode an assembled line the way the wrapper does: UTF-8 over the raw bytes.
  private func runString(_ text: String, terminator: UInt8 = 0x0A) -> String? {
    let bytes = Array(text.utf8) + [terminator]
    guard let out = run(bytes) else { return nil }
    return String(decoding: out, as: UTF8.self)
  }

  // MARK: append ordering

  @Test func plainBytesAppendInOrder() {
    let assembled = run(Array("hunter2".utf8) + [0x0A])
    #expect(assembled == Array("hunter2".utf8))
  }

  @Test func emptyLineAssemblesToEmptyNotNil() {
    // A bare Enter on an empty buffer is a real (empty) line, not EOF.
    #expect(run([0x0A]) == [])
  }

  // MARK: backspace editing

  @Test func delErasesLastByte() {
    // "ab" + DEL -> "a"
    let assembled = run([0x61, 0x62, 0x7F, 0x0A])
    #expect(assembled == [0x61])
  }

  @Test func bsErasesLastByte() {
    // "ab" + BS (0x08) -> "a"
    let assembled = run([0x61, 0x62, 0x08, 0x0A])
    #expect(assembled == [0x61])
  }

  @Test func backspaceOnEmptyBufferIsNoOp() {
    // Leading DEL/BS must not underflow; the line is still empty afterwards.
    var buffer: [UInt8] = []
    #expect(noEchoLineEvent(after: 0x7F, into: &buffer) == .continue)
    #expect(noEchoLineEvent(after: 0x08, into: &buffer) == .continue)
    #expect(buffer.isEmpty)
    // ...and a following byte still appends normally.
    #expect(noEchoLineEvent(after: 0x61, into: &buffer) == .continue)
    #expect(buffer == [0x61])
  }

  @Test func multipleBackspacesThenRetype() {
    // "abc" + DEL + DEL + "X" -> "aX"
    let assembled = run([0x61, 0x62, 0x63, 0x7F, 0x7F, 0x58, 0x0A])
    #expect(assembled == [0x61, 0x58])
  }

  // MARK: scalar-aware backspace (multi-byte UTF-8)

  @Test func backspaceErasesWholeTwoByteScalar() {
    // "é" (U+00E9 = 0xC3 0xA9) + DEL must remove BOTH bytes, leaving nothing —
    // not a dangling lead byte that would decode to U+FFFD.
    let assembled = run(Array("é".utf8) + [0x7F, 0x0A])
    #expect(assembled == [])
  }

  @Test func backspaceErasesWholeFourByteScalar() {
    // A 4-byte emoji (U+1F510 = 0xF0 0x9F 0x94 0x90) + DEL removes all 4 bytes.
    let assembled = run(Array("🔐".utf8) + [0x7F, 0x0A])
    #expect(assembled == [])
  }

  @Test func backspaceAfterMixedAsciiAndScalarLeavesAscii() {
    // "a" + "é" + DEL -> "a": the backspace erases the whole multi-byte scalar
    // and leaves the preceding ASCII byte untouched.
    let assembled = run(Array("aé".utf8) + [0x7F, 0x0A])
    #expect(assembled == Array("a".utf8))
    #expect(assembled.map { String(decoding: $0, as: UTF8.self) } == "a")
  }

  @Test func backspaceErasesFourByteScalarAfterAsciiLeavesAscii() {
    // "a" + 4-byte emoji (U+1F510) + DEL -> "a": the backspace removes exactly the
    // 4-byte scalar and STOPS at the preceding ASCII byte. Unlike the empty-buffer
    // emoji case, this distinguishes a correct scalar-boundary stop (break on the lead
    // byte) from merely "removed 4 bytes and happened to empty the buffer".
    let assembled = run(Array("a🔐".utf8) + [0x7F, 0x0A])
    #expect(assembled == Array("a".utf8))
  }

  @Test func backspaceOnMalformedTailRemovesAtMostFourBytes() {
    // A malformed all-continuation tail: 5 trailing 0x80 bytes. One backspace must
    // remove exactly 4 (the max-scalar cap), never walking back unboundedly, and
    // never crash — leaving 1 continuation byte behind.
    var buffer: [UInt8] = [0x80, 0x80, 0x80, 0x80, 0x80]
    #expect(noEchoLineEvent(after: 0x7F, into: &buffer) == .continue)
    #expect(buffer == [0x80])
  }

  @Test func multiByteScalarRoundTripsThroughBackspaceRetype() {
    // Type "café", backspace the "é", retype "e" -> "cafe": the edited line decodes
    // cleanly with no U+FFFD remnant from the erased multi-byte scalar.
    let bytes = Array("café".utf8) + [0x7F] + Array("e".utf8) + [0x0A]
    let assembled = run(bytes)
    #expect(String(decoding: assembled!, as: UTF8.self) == "cafe")
  }

  // MARK: terminators

  @Test func lfYieldsEndLine() {
    var buffer: [UInt8] = [0x61]
    #expect(noEchoLineEvent(after: 0x0A, into: &buffer) == .endLine)
  }

  @Test func crYieldsEndLine() {
    var buffer: [UInt8] = [0x61]
    #expect(noEchoLineEvent(after: 0x0D, into: &buffer) == .endLine)
  }

  @Test func crAndLfBothTerminateWithSameContent() {
    #expect(runString("secret", terminator: 0x0A) == "secret")
    #expect(runString("secret", terminator: 0x0D) == "secret")
  }

  @Test func crThenLfEndsLineAtCrLeavingLfForNextRead() {
    // A terminal/paste sending CRLF: the CR ends the line with the bytes typed before
    // it ("ab"), and the trailing LF is NOT consumed by this line — it would itself be
    // an (empty) terminator on the next read. Pins this benign CRLF interaction so a
    // future change to CR handling (e.g. swallowing a following LF) is caught.
    var buffer: [UInt8] = []
    #expect(noEchoLineEvent(after: 0x61, into: &buffer) == .continue)
    #expect(noEchoLineEvent(after: 0x62, into: &buffer) == .continue)
    #expect(noEchoLineEvent(after: 0x0D, into: &buffer) == .endLine)
    #expect(buffer == [0x61, 0x62])
    var next: [UInt8] = []
    #expect(noEchoLineEvent(after: 0x0A, into: &next) == .endLine)
    #expect(next.isEmpty)
  }

  @Test func ctrlDOnEmptyBufferYieldsEndInput() {
    var buffer: [UInt8] = []
    #expect(noEchoLineEvent(after: 0x04, into: &buffer) == .endInput)
    // The whole-stream view: a lone Ctrl-D returns nil (EOF, nothing typed).
    #expect(run([0x04]) == nil)
  }

  @Test func ctrlDOnNonEmptyBufferYieldsEndLine() {
    var buffer: [UInt8] = [0x61, 0x62]
    #expect(noEchoLineEvent(after: 0x04, into: &buffer) == .endLine)
    // The whole-stream view: typed bytes then Ctrl-D submits that line.
    #expect(run([0x61, 0x62, 0x04]) == [0x61, 0x62])
  }

  // MARK: the MAX_CANON regression — long lines must not be capped or lost

  @Test func longLineAssemblesLosslessly() {
    // A line well over the old 1024-byte canonical-mode limit must survive intact;
    // this is the regression that proves the MAX_CANON cap is gone.
    let long = String(repeating: "A", count: 4096)
    #expect(runString(long) == long)
    #expect(runString(long)?.count == 4096)
  }

  @Test func longTokenWithMixedBytesRoundTrips() {
    // A realistic long credential: 2000 chars of mixed alphanumerics/punctuation.
    let token = String(
      repeating: "aZ9-_.+/=", count: 250
    ) // 9 * 250 = 2250 bytes, > MAX_CANON
    #expect(runString(token) == token)
  }

  // MARK: multi-byte UTF-8 content

  @Test func multiByteUTF8RoundTrips() {
    // Multi-byte scalars (emoji, accents, CJK) must round-trip when the whole line
    // is decoded as UTF-8 on endLine — the bytes are accumulated raw in between.
    let text = "café — 日本語 — 🔐🗝️"
    #expect(runString(text) == text)
  }

  @Test func longMultiByteUTF8RoundTrips() {
    // Multi-byte content that also exceeds MAX_CANON, combining both invariants.
    let unit = "🔐é"
    let text = String(repeating: unit, count: 300) // far over 1024 bytes
    #expect(runString(text) == text)
    #expect(Array(text.utf8).count > 1024)
  }
}
