# Makefile for the Oxigate workspace
# Run from the workspace root (the directory containing this file).
#
# Usage:
#   make                  → print help (default)
#
#   Workspace-wide:
#   make build            → build all crates (debug)
#   make release          → build all crates (release)
#   make check            → compile-check all crates
#   make test             → run all tests
#   make lint             → clippy + format check
#   make fmt              → auto-format all sources
#   make clean            → remove build artifacts
#
#   Library (oxigate):
#   make lib-build        → build the library (debug)
#   make lib-release      → build the library (release)
#   make lib-check        → compile-check the library
#   make lib-test         → run library tests
#   make lib-clippy       → clippy on the library
#   make lib-doc          → generate library rustdoc
#   make lib-doc-open     → generate and open library rustdoc
#
#   Application crate (oxigate-app → binary: oxigate):
#   make app-build        → build the application (debug)
#   make app-release      → build the application (release)
#   make app-check        → compile-check the application
#   make app-test         → run application tests
#   make app-clippy       → clippy on the application
#   make app-doc          → generate application rustdoc
#   make app-doc-open     → generate and open application rustdoc
#   make app-install          → install oxigate to ~/.cargo/bin (release)
#   make app-init             → write example configs to DEST (default: ./config/)
#   make app-init DEST=/path  → write example configs to a custom path
#
#   make help             → print this message

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CARGO        := cargo
LIB          := oxigate
APP_CRATE    := oxigate-app
BIN          := oxigate
WORKSPACE    := --workspace
RELEASE_FLAG := --release
DEST         ?= ./config

# Resolve the Cargo target directory.
# `cargo metadata` always returns the correct workspace target path regardless
# of where make is invoked. Falls back to ./target if metadata is unavailable.
# Uses only grep + sed — no Python or jq required.
TARGET_DIR := $(if $(CARGO_TARGET_DIR),\
                $(CARGO_TARGET_DIR),\
                $(shell cargo metadata --no-deps --format-version 1 2>/dev/null \
                  | grep -o '"target_directory":"[^"]*"' \
                  | sed 's/"target_directory":"//;s/"//'))
TARGET_DIR := $(if $(TARGET_DIR),$(TARGET_DIR),$(CURDIR)/target)

# Colour helpers (degrade gracefully when the terminal has no colour support).
BOLD  := $(shell tput bold    2>/dev/null || true)
GREEN := $(shell tput setaf 2 2>/dev/null || true)
CYAN  := $(shell tput setaf 6 2>/dev/null || true)
RESET := $(shell tput sgr0    2>/dev/null || true)

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: \
  all build release check test lint fmt fmt-check clean \
  lib-build lib-release lib-check lib-test lib-clippy lib-doc lib-doc-open \
  app-build app-release app-check app-test app-clippy app-doc app-doc-open \
  app-install app-init \
  help

# ---------------------------------------------------------------------------
# Workspace-wide targets
# ---------------------------------------------------------------------------

## all: Build all workspace crates in debug mode.
all: build

## build: Build all workspace crates in debug mode.
build:
	@echo "$(CYAN)$(BOLD)» Building workspace (debug)…$(RESET)"
	$(CARGO) build $(WORKSPACE)

## release: Build all workspace crates in release mode.
release:
	@echo "$(CYAN)$(BOLD)» Building workspace (release)…$(RESET)"
	$(CARGO) build $(WORKSPACE) $(RELEASE_FLAG)

## check: Compile-check all workspace crates without producing binaries.
check:
	@echo "$(CYAN)$(BOLD)» Checking workspace…$(RESET)"
	$(CARGO) check $(WORKSPACE)

## test: Run all tests across the workspace.
test:
	@echo "$(CYAN)$(BOLD)» Running workspace tests…$(RESET)"
	$(CARGO) test $(WORKSPACE)

## lint: Run clippy and verify formatting across the workspace (no changes written).
lint: lib-clippy app-clippy fmt-check
	@echo "$(GREEN)$(BOLD)» Lint OK.$(RESET)"

## fmt: Auto-format all Rust sources in the workspace.
fmt:
	@echo "$(CYAN)$(BOLD)» Formatting sources…$(RESET)"
	$(CARGO) fmt --all

## fmt-check: Check formatting across the workspace without writing changes (CI-friendly).
fmt-check:
	@echo "$(CYAN)$(BOLD)» Checking formatting…$(RESET)"
	$(CARGO) fmt --all -- --check

## clean: Remove all build artifacts.
clean:
	@echo "$(CYAN)$(BOLD)» Cleaning build artifacts…$(RESET)"
	$(CARGO) clean

# ---------------------------------------------------------------------------
# Library targets  (lib-*)
# ---------------------------------------------------------------------------

## lib-build: Build the oxigate library in debug mode.
lib-build:
	@echo "$(CYAN)$(BOLD)» Building $(LIB) (debug)…$(RESET)"
	$(CARGO) build -p $(LIB)

## lib-release: Build the oxigate library in release mode.
lib-release:
	@echo "$(CYAN)$(BOLD)» Building $(LIB) (release)…$(RESET)"
	$(CARGO) build -p $(LIB) $(RELEASE_FLAG)

## lib-check: Compile-check the oxigate library without producing artifacts.
lib-check:
	@echo "$(CYAN)$(BOLD)» Checking $(LIB)…$(RESET)"
	$(CARGO) check -p $(LIB)

## lib-test: Run tests for the oxigate library.
lib-test:
	@echo "$(CYAN)$(BOLD)» Testing $(LIB)…$(RESET)"
	$(CARGO) test -p $(LIB)

## lib-clippy: Run clippy on the oxigate library.
lib-clippy:
	@echo "$(CYAN)$(BOLD)» Clippy $(LIB)…$(RESET)"
	$(CARGO) clippy -p $(LIB) -- -D warnings

## lib-doc: Generate rustdoc for the oxigate library.
lib-doc:
	@echo "$(CYAN)$(BOLD)» Documenting $(LIB)…$(RESET)"
	$(CARGO) doc -p $(LIB) --no-deps

## lib-doc-open: Generate rustdoc for the oxigate library and open it in the browser.
lib-doc-open:
	@echo "$(CYAN)$(BOLD)» Documenting $(LIB) (open)…$(RESET)"
	$(CARGO) doc -p $(LIB) --no-deps --open

# ---------------------------------------------------------------------------
# Application crate targets  (app-*)
# Crate: oxigate-app  |  Binary: oxigate
# ---------------------------------------------------------------------------

## app-build: Build the oxigate binary in debug mode.
app-build:
	@echo "$(CYAN)$(BOLD)» Building $(BIN) (debug)…$(RESET)"
	$(CARGO) build -p $(APP_CRATE)

## app-release: Build the oxigate binary in release mode.
app-release:
	@echo "$(CYAN)$(BOLD)» Building $(BIN) (release)…$(RESET)"
	$(CARGO) build -p $(APP_CRATE) $(RELEASE_FLAG)

## app-check: Compile-check the oxigate-app crate without producing artifacts.
app-check:
	@echo "$(CYAN)$(BOLD)» Checking $(APP_CRATE)…$(RESET)"
	$(CARGO) check -p $(APP_CRATE)

## app-test: Run tests for the oxigate-app crate.
app-test:
	@echo "$(CYAN)$(BOLD)» Testing $(APP_CRATE)…$(RESET)"
	$(CARGO) test -p $(APP_CRATE)

## app-clippy: Run clippy on the oxigate-app crate.
app-clippy:
	@echo "$(CYAN)$(BOLD)» Clippy $(APP_CRATE)…$(RESET)"
	$(CARGO) clippy -p $(APP_CRATE) -- -D warnings

## app-doc: Generate rustdoc for the oxigate-app crate.
app-doc:
	@echo "$(CYAN)$(BOLD)» Documenting $(APP_CRATE)…$(RESET)"
	$(CARGO) doc -p $(APP_CRATE) --no-deps

## app-doc-open: Generate rustdoc for the oxigate-app crate and open it in the browser.
app-doc-open:
	@echo "$(CYAN)$(BOLD)» Documenting $(APP_CRATE) (open)…$(RESET)"
	$(CARGO) doc -p $(APP_CRATE) --no-deps --open

## app-install: Install the oxigate binary to ~/.cargo/bin (release build).
app-install:
	@echo "$(CYAN)$(BOLD)» Installing $(BIN) to ~/.cargo/bin…$(RESET)"
	$(CARGO) install --path oxigate-app --bin $(BIN)

## app-init: Write example YAML config files to DEST (default: ./config/). Override with DEST=/path.
app-init: app-build
	@echo "$(CYAN)$(BOLD)» Writing example configs to $(DEST)…$(RESET)"
	$(TARGET_DIR)/debug/$(BIN) --init $(DEST)
	@echo "$(GREEN)$(BOLD)Done.$(RESET) Edit the files in $(DEST)/ then start the gateway with:"
	@echo "  $(BIN) --config $(DEST)/gateway.yaml"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

## help: Print this help message.
help:
	@echo ""
	@echo "$(BOLD)Oxigate — available make targets$(RESET)"
	@echo ""
	@echo "$(BOLD)Workspace$(RESET)"
	@grep -E '^## [^a-z]*(build|release|check|test|lint|fmt|fmt-check|clean|all):' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-20s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Library crate — oxigate (lib-*)$(RESET)"
	@grep -E '^## lib-' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-20s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Application crate — oxigate-app / binary: oxigate (app-*)$(RESET)"
	@grep -E '^## app-' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-20s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Variables$(RESET)"
	@echo "  $(CYAN)DEST$(RESET)             Destination directory for 'make app-init' (default: ./config)"
	@echo "  $(CYAN)CARGO_TARGET_DIR$(RESET) Override the Cargo build output directory"
	@echo ""
