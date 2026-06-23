// The real, networked TokenExchanger: the one URLSession syscall behind the seam.
//
// This is the un-runnable half of the token-exchange seam, mirroring
// `SystemKeychain.swift`'s role for the Keychain seam. It performs a live HTTPS
// POST, so it cannot run in the host-less `keymasterTests` bundle (network access,
// nondeterministic, depends on a real provider) and is therefore kept OUT of the
// pbxproj `membershipExceptions`. The security-relevant request-building and
// response-parsing logic it relies on (`buildTokenRequest`/`parseTokenResponse`)
// lives in the Foundation-only `TokenExchanger.swift` and IS unit-tested; this file
// only adds the actual send and is covered by the live-provider smoke test in
// CLAUDE.md.
//
// Everything here is `nonisolated`: `TokenExchanger` is `nonisolated`, so the
// conforming method is too, and `semaphore.wait()` may then block whatever thread
// calls it (the app target defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`,
// which would otherwise isolate this to the main actor).
import Dispatch
import Foundation

// Refuses every HTTP redirect on the token POST. A 307/308 (and many servers'
// 301/302 on a POST) re-sends the original request body to the new location —
// and that body carries the `refresh_token` and possibly the `client_secret`.
// Following such a redirect would leak the long-lived credential to whatever host
// the endpoint points us at, so we never follow: returning `nil` from
// `completionHandler` cancels the redirect and lets the task complete with the
// 3xx response itself, which `parseTokenResponse` then maps to a request error.
private final class NoRedirectTaskDelegate: NSObject, URLSessionTaskDelegate {
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}

// The networked `TokenExchanger`. Builds the refresh-token POST with the shared
// pure `buildTokenRequest`, sends it synchronously, and hands the HTTP
// `(body, statusCode)` to the shared pure `parseTokenResponse` — so all of the
// RFC 6749 §6 request shape and §5 reply handling stays in the tested layer and
// this conformer is the thinnest possible wrapper over `URLSession`.
nonisolated struct URLSessionTokenExchanger: TokenExchanger {
  // How long to wait for the token endpoint before giving up. Applied to the
  // request itself (so a hung connection fails rather than blocking the CLI
  // forever); a timeout surfaces through the transport-error path below.
  let timeout: TimeInterval

  init(timeout: TimeInterval = 30) {
    self.timeout = timeout
  }

  // Exchange the stored record for a fresh token. Sends the form-encoded POST
  // synchronously (the CLI has no run loop, so the async data task is bridged to a
  // blocking call with a DispatchSemaphore, exactly as `authenticatedContext` does
  // for LocalAuthentication), then:
  //   - a transport failure (network/timeout/TLS) or a non-HTTP/nil response maps
  //     to `KeychainError.status("token request failed: <reason>")` — un-prefixed,
  //     so `get`/`run` prepend `"<key>: "` as today;
  //   - otherwise the `(data, statusCode)` is parsed by the shared
  //     `parseTokenResponse`, which decodes the token or throws the mapped
  //     RFC error (including the `invalid_grant` re-auth hint).
  func exchange(_ record: OAuthRecord) throws -> TokenResponse {
    var request = buildTokenRequest(record)
    request.timeoutInterval = timeout

    let semaphore = DispatchSemaphore(value: 0)
    var responseData: Data?
    var httpResponse: HTTPURLResponse?
    var transportError: Error?

    // A dedicated per-exchange session (not `URLSession.shared`) so it can carry a
    // delegate: `NoRedirectTaskDelegate` refuses every 3xx redirect, ensuring the
    // credential-bearing POST body is never re-sent to a redirect target. The
    // `.ephemeral` configuration keeps no on-disk cache/cookies for this
    // credential exchange. The session delivers the completion on a background
    // queue, which signals the semaphore; `wait()` then blocks the calling thread
    // until the reply (or failure) arrives. Safe because there is no AppKit run
    // loop to starve and nothing else runs on this thread meanwhile. The session
    // is invalidated right after `wait()` to release its retained delegate.
    let session = URLSession(
      configuration: .ephemeral,
      delegate: NoRedirectTaskDelegate(),
      delegateQueue: nil
    )
    let task = session.dataTask(with: request) { data, response, error in
      responseData = data
      httpResponse = response as? HTTPURLResponse
      transportError = error
      semaphore.signal()
    }
    task.resume()
    semaphore.wait()
    session.finishTasksAndInvalidate()

    if let transportError = transportError {
      throw KeychainError.status("token request failed: \(transportError.localizedDescription)")
    }
    guard let httpResponse = httpResponse else {
      throw KeychainError.status("token request failed: no HTTP response")
    }

    return try parseTokenResponse(data: responseData ?? Data(), status: httpResponse.statusCode)
  }
}
