// Pure, syscall-free line-editing logic for the no-echo TTY prompt.
//
// This file is intentionally Foundation-only — no `@main`, ArgumentParser, or
// termios/`read()` syscalls in any signature — so it can be compiled into BOTH
// the app target (via the synchronized folder group) and the HOST-LESS
// `keymasterTests` bundle (via a synchronized-group membership exception). The
// termios setup and the `read()` one-byte loop that drives this reducer live in
// `keymasterApp.swift` (`readLineWithEchoOff`) and are verified manually, per the
// project's documented testability boundary; the per-byte editing *decisions*
// extracted here are unit-tested headlessly.
//
// Why this exists: the old prompt read in the terminal's CANONICAL (line-buffered)
// mode, where macOS caps one input line at `MAX_CANON` = 1024 bytes — pasting a
// longer `refresh_token`/`client_secret` rings the bell and silently discards the
// overflow. Reading one byte at a time in NON-canonical mode removes that limit,
// which means the line editing (append / backspace / terminators) the tty used to
// do for us now has to be done by hand. This reducer is that hand-rolled editor.
//
// `nonisolated` keeps these types compiling identically in the app target (which
// defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`) and the test target
// (which has no such default), matching the rest of the Foundation-only layer.
import Foundation

// The decision a single input byte produces while assembling a no-echo line.
//
// - `continue`: the byte was consumed (appended, or it erased the last byte, or it
//   was an ignored edit on an empty buffer); keep reading.
// - `endLine`:  the line is complete; return the accumulated bytes as the secret.
// - `endInput`: end-of-input with nothing typed; the caller returns `nil`
//   (equivalent to the old `readLine` returning `nil` at EOF).
nonisolated enum NoEchoLineEvent: Equatable {
  case `continue`
  case endLine
  case endInput
}

// Apply one input byte to the accumulating line buffer and report what it means.
//
// Mirrors the canonical-mode line discipline the terminal used to perform for us,
// minus the 1024-byte `MAX_CANON` cap:
//   - LF (`0x0A`) / CR (`0x0D`)  → `endLine` (Enter on either terminator).
//   - EOT / Ctrl-D (`0x04`)      → `endInput` if the buffer is empty (EOF with
//                                  nothing typed), else `endLine` (submit a typed
//                                  line, matching a canonical-mode Ctrl-D).
//   - DEL (`0x7F`) / BS (`0x08`) → erase the last UTF-8 scalar; a no-op on an empty
//                                  buffer.
//   - any other byte             → append it; `continue`.
//
// The erase removes one whole UTF-8 *scalar*, not a single raw byte: pop the last
// byte, then keep popping while the byte just removed was a continuation byte
// (`b & 0xC0 == 0x80`), the buffer is non-empty, and fewer than 4 bytes (the max
// UTF-8 scalar length) have been popped. For well-formed input this removes exactly
// one scalar, so a backspace inside a multi-byte character can never leave a dangling
// partial sequence that would decode to U+FFFD and silently corrupt the secret. The
// 4-byte cap bounds a malformed all-continuation tail: a single backspace removes at
// most 4 bytes, never walking back across what should be several characters. A
// grapheme cluster made of several scalars (e.g. an emoji + variation selector)
// erases one scalar per press — an accepted ergonomic caveat, distinct from the
// corruption bug this fixes. The buffer holds raw bytes; the caller decodes the
// whole line as UTF-8 once on `endLine`.
nonisolated func noEchoLineEvent(after byte: UInt8, into buffer: inout [UInt8]) -> NoEchoLineEvent {
  switch byte {
  case 0x0A, 0x0D:
    return .endLine
  case 0x04:
    return buffer.isEmpty ? .endInput : .endLine
  case 0x7F, 0x08:
    guard !buffer.isEmpty else { return .continue }
    var removed = 0
    while !buffer.isEmpty && removed < 4 {
      let last = buffer.removeLast()
      removed += 1
      // Stop once we've removed a lead/ASCII byte; only continuation bytes
      // (0b10xxxxxx) keep the scalar open.
      if last & 0xC0 != 0x80 { break }
    }
    return .continue
  default:
    buffer.append(byte)
    return .continue
  }
}
