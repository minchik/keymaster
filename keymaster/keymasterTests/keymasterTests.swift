//
//  keymasterTests.swift
//  keymasterTests
//
//  Created by Aliaksandr Minets on 19/06/2026.
//

import Testing

// The keymasterTests bundle is HOST-LESS: it has no TEST_HOST/BUNDLE_LOADER and does
// not `@testable import` the app. The app is a `@main` CLI that exit()s on launch, so
// an app-hosted bundle never finishes bootstrapping (the runner exits with code 64
// before establishing a connection). Pure logic under test is compiled directly into
// this bundle via a synchronized-group membership exception (see RunSupport.swift).
struct keymasterTests {

    @Test func testTargetRuns() async throws {
        // Smoke test: confirms the host-less keymasterTests target actually executes.
        #expect(1 + 1 == 2)
    }

}
