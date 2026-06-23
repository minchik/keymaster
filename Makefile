# Makefile — build a locally-signed Keymaster.app for Touch ID testing.
#
# Keymaster must run as a signed .app: the biometric guard needs the restricted
# keychain-access-groups entitlement, which requires a provisioning profile
# (AMFI SIGKILLs an unsigned/unprovisioned binary that carries it). This builds
# the app with Xcode automatic signing using your "Apple Development" identity,
# which mints/embeds a development provisioning profile — no Developer ID or
# notarization needed for local testing. See `make help`.

PROJECT := keymaster/keymaster.xcodeproj
SCHEME  := keymaster
CONFIG  := Debug

# Automatic-signing team (matches the project's DEVELOPMENT_TEAM).
TEAM := 57ACZ9RAXL
# Local DerivedData (kept under the git-ignored build/ dir).
DERIVED := build/local

# Where xcodebuild drops the product, and the CLI binary inside the bundle.
APP := $(DERIVED)/Build/Products/$(CONFIG)/Keymaster.app
BIN := $(APP)/Contents/MacOS/keymaster

# Symlink target for `make install` (no sudo by default; must be on your PATH).
PREFIX := $(HOME)/.local/bin

XCODEBUILD := xcodebuild
COMMON := -project $(PROJECT) -scheme $(SCHEME) -destination 'platform=macOS'

.DEFAULT_GOAL := build
.PHONY: build test lint install uninstall path clean help

## build: compile + development-sign Keymaster.app into ./$(DERIVED)
build:
	$(XCODEBUILD) build $(COMMON) \
	  -configuration $(CONFIG) \
	  -derivedDataPath $(DERIVED) \
	  DEVELOPMENT_TEAM=$(TEAM) \
	  CODE_SIGN_STYLE=Automatic \
	  -allowProvisioningUpdates
	@echo
	@echo "Built + signed: $(APP)"
	@codesign -dvv "$(APP)" 2>&1 | grep -E 'Authority=Apple Development|TeamIdentifier' || true
	@echo
	@echo "Run the CLI with:"
	@echo "  $(BIN) version"
	@echo "  printf %s \"\$$SECRET\" | $(BIN) set MyKey   # then: $(BIN) get MyKey"

## test: run the host-less unit tests (Foundation-only logic, no signing/Touch ID)
test:
	$(XCODEBUILD) test $(COMMON) -only-testing:keymasterTests CODE_SIGNING_ALLOWED=NO

## lint: run SwiftLint over the sources
lint:
	swiftlint

## install: symlink the built binary into $(PREFIX) (put $(PREFIX) on your PATH)
install: build
	@mkdir -p "$(PREFIX)"
	@ln -sf "$(CURDIR)/$(BIN)" "$(PREFIX)/keymaster"
	@echo "Linked $(PREFIX)/keymaster -> $(BIN)"
	@echo "Ensure $(PREFIX) is on your PATH, then run: keymaster version"

## uninstall: remove the symlink created by `make install`
uninstall:
	@rm -f "$(PREFIX)/keymaster" && echo "Removed $(PREFIX)/keymaster"

## path: print the absolute path to the built CLI binary
path:
	@echo "$(CURDIR)/$(BIN)"

## clean: delete the local build output
clean:
	@rm -rf "$(DERIVED)" && echo "Removed $(DERIVED)"

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
