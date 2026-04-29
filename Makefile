# Wattcloud — Makefile.
#
# Targets here support ONE install path: clone + local build, for
# contributors, maintainers, and self-builders who want to audit or
# modify the code. They are NOT used by operators running a production
# install.
#
#   Path 1 (repo clone — this Makefile)     — contributors, maintainers,
#                                              self-builders
#   Path 2 (release tarball download)        — production operators. They
#                                              use `install.sh` once, then
#                                              `wattcloud-update`,
#                                              `wattcloud oauth-setup`, etc.
#                                              Operators do not need Make.
#
# Canonical CI is GitHub Actions; scripts/ci.sh mirrors it locally.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

CYAN   := $(shell tput setaf 6 2>/dev/null || echo "")
YELLOW := $(shell tput setaf 3 2>/dev/null || echo "")
RESET  := $(shell tput sgr0   2>/dev/null || echo "")

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
HOST_ARCH := $(shell uname -m | sed -e 's/x86_64/x86_64-linux/' -e 's/aarch64/aarch64-linux/' -e 's/arm64/aarch64-linux/')
DIST_DIR  := dist

# ---- help ------------------------------------------------------------------

help:
	@echo "$(CYAN)Wattcloud — Makefile targets (Path 1: repo clone)$(RESET)"
	@echo
	@echo "$(YELLOW)dev$(RESET)"
	@echo "  dev               Full-stack dev: byo-relay (:8443) + Vite (:5173), foreground"
	@echo "  dev-stop          Stop a running stack (from another shell)"
	@echo "  dev-frontend      Vite only — use when a relay is already running"
	@echo "  dev-relay         byo-relay only — uses .env.dev (auto-generated on first run)"
	@echo "  claim-token       Print + consume .dev-state/bootstrap.txt (parity with prod 'sudo wattcloud claim-token')"
	@echo "  regenerate-claim-token  Mint a fresh dev bootstrap token (parity with prod 'sudo wattcloud regenerate-claim-token')"
	@echo "  build-sdk-wasm    wasm-pack build → frontend/src/pkg/"
	@echo "  build-frontend    Vite build of the SPA → byo-relay/dist/"
	@echo "  build             build-sdk-wasm + build-frontend"
	@echo "  test              cargo + npm tests across the repo"
	@echo "  test-sdk          cargo test sdk-core (crypto + byo + providers)"
	@echo "  test-byo-relay    cargo test byo-relay"
	@echo "  test-frontend     npm test in frontend/ (incl. src/lib/sdk tests)"
	@echo "  lint              cargo clippy + eslint"
	@echo "  fmt               cargo fmt across both workspaces"
	@echo "  ci                Full local CI (scripts/ci.sh)"
	@echo
	@echo "$(YELLOW)release artifacts (local — for testing packaging)$(RESET)"
	@echo "  tarball           Build a release tarball for the host arch"
	@echo "  tarball-all       Cross-compile + package both x86_64 and aarch64"
	@echo "  smoke-tarball     scripts/byo-smoke.sh against locally-built binary"
	@echo "  verify-tarball    cosign verify a downloaded tarball (TARBALL=, SIG=, CERT=)"
	@echo "  docker-image      Self-builder-only Docker image (not a release artifact)"
	@echo "  release-help      Reminder on how tagged releases flow through Actions"
	@echo
	@echo "$(YELLOW)cleanup$(RESET)"
	@echo "  clean             cargo clean + rm node_modules/dist/pkg/target"
	@echo "  clean-docker      Prune dangling Docker images + builder cache > 7d"
	@echo "  clean-all         clean + clean-docker"

# ---- dev -------------------------------------------------------------------

dev:
	bash scripts/dev.sh

# SIGTERM the running `make dev` via its PID file (.dev-state/dev.pid). Use
# when the stack is running in another shell / tmux pane and Ctrl-C isn't
# reachable. Running tmux/screen sessions themselves are yours to manage.
dev-stop:
	DEV_STOP=1 bash scripts/dev.sh

# Vite only (frontend). Use when you already have a relay running separately
# — e.g. `make dev-relay` in one terminal, `make dev-frontend` in another.
dev-frontend:
	cd frontend && npm run dev

# byo-relay only. Bootstraps .env.dev on first run (same as `make dev`) and
# then cargo-runs the relay in the foreground on 127.0.0.1:8443.
dev-relay:
	DEV_RELAY_ONLY=1 bash scripts/dev.sh

# Dev parity with prod's `sudo wattcloud claim-token`. The relay mints the
# bootstrap token on first restricted-mode startup and drops it at
# .dev-state/bootstrap.txt. Print + unlink here so subsequent `make
# claim-token` invocations fail fast — same single-use hygiene as the
# prod wrapper. (The relay enforces single-use + short TTL regardless;
# unlinking just removes the plaintext copy from disk.)
claim-token:
	@if [ ! -f .dev-state/bootstrap.txt ]; then \
	  echo "No bootstrap token at .dev-state/bootstrap.txt." >&2; \
	  echo "The token has already been consumed, or the dev relay isn't running." >&2; \
	  echo "To mint a fresh one (dev relay must be running):" >&2; \
	  echo "  make regenerate-claim-token" >&2; \
	  exit 1; \
	fi
	@printf '%s\n' "$$(cat .dev-state/bootstrap.txt)"
	@rm -f .dev-state/bootstrap.txt

# Dev parity with prod's `sudo wattcloud regenerate-claim-token`. Sources
# .env.dev so byo-admin picks up ENROLLMENT_DB_PATH / BOOTSTRAP_TOKEN_PATH
# / RELAY_SIGNING_KEY via clap's `env = "…"` fallbacks — no flags needed.
regenerate-claim-token:
	@[ -f .env.dev ] || { echo "No .env.dev — run 'make dev' first to bootstrap it." >&2; exit 1; }
	@set -a && . ./.env.dev && set +a && \
	 cargo run --manifest-path byo-relay/Cargo.toml --bin byo-admin -- \
	   regenerate-bootstrap-token

build-sdk-wasm:
	cd sdk/sdk-wasm && wasm-pack build --release --target web \
	  --out-dir ../../frontend/src/pkg --out-name wattcloud_sdk_wasm

build-frontend:
	cd frontend && npm ci --silent && npm run build

build: build-sdk-wasm build-frontend

test-sdk:
	cargo test --manifest-path sdk/sdk-core/Cargo.toml \
	  --no-default-features --features "crypto byo providers"

test-byo-relay:
	cargo test --manifest-path byo-relay/Cargo.toml

test-frontend:
	cd frontend && npm ci --silent && npm test

test: test-sdk test-byo-relay test-frontend

lint:
	cargo clippy --manifest-path sdk/sdk-core/Cargo.toml \
	  --no-default-features --features "crypto byo providers" \
	  --all-targets -- -D warnings
	cargo clippy --manifest-path byo-relay/Cargo.toml --all-targets -- -D warnings
	cd frontend && npm run lint

fmt:
	cargo fmt --manifest-path Cargo.toml
	cargo fmt --manifest-path byo-relay/Cargo.toml

ci:
	bash scripts/ci.sh

# ---- release artifacts (local build) --------------------------------------

tarball: build
	@mkdir -p "$(DIST_DIR)"
	@cargo build --manifest-path byo-relay/Cargo.toml --release --bin byo-relay --bin byo-admin
	@PAYLOAD="wattcloud-$(VERSION)-$(HOST_ARCH)"; \
	 OUT="$(DIST_DIR)/$$PAYLOAD"; \
	 rm -rf "$$OUT"; \
	 mkdir -p "$$OUT"/{bin,web,scripts,packaging}; \
	 install -m 0755 byo-relay/target/release/byo-relay "$$OUT/bin/byo-relay"; \
	 install -m 0755 byo-relay/target/release/byo-admin "$$OUT/bin/byo-admin"; \
	 cp -r byo-relay/dist/. "$$OUT/web/"; \
	 install -m 0755 scripts/deploy-vps.sh  "$$OUT/scripts/"; \
	 install -m 0755 scripts/harden-vps.sh  "$$OUT/scripts/"; \
	 install -m 0755 scripts/update.sh      "$$OUT/scripts/"; \
	 install -m 0755 scripts/uninstall.sh   "$$OUT/scripts/"; \
	 install -m 0755 scripts/oauth-setup.sh "$$OUT/scripts/"; \
	 install -m 0755 scripts/lib.sh         "$$OUT/scripts/"; \
	 install -m 0644 packaging/wattcloud.service "$$OUT/packaging/"; \
	 install -m 0644 packaging/Caddyfile.tmpl    "$$OUT/packaging/"; \
	 install -m 0644 packaging/config.json.tmpl  "$$OUT/packaging/"; \
	 install -m 0644 .env.example "$$OUT/"; \
	 printf '%s\n' "$(VERSION)" > "$$OUT/VERSION"; \
	 tar -czf "$(DIST_DIR)/$$PAYLOAD.tar.gz" -C "$(DIST_DIR)" "$$PAYLOAD"; \
	 sha256sum "$(DIST_DIR)/$$PAYLOAD.tar.gz" | tee "$(DIST_DIR)/$$PAYLOAD.tar.gz.sha256"
	@echo "Tarball → $(DIST_DIR)/wattcloud-$(VERSION)-$(HOST_ARCH).tar.gz"
	@echo "(not cosign-signed — that happens in the Actions release.yml only)"

tarball-all: build
	@command -v cross >/dev/null 2>&1 || { echo "cross not installed: cargo install cross --locked"; exit 1; }
	@for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do \
	  echo "━━ $$target ━━"; \
	  (cd byo-relay && cross build --release --bin byo-relay --bin byo-admin --target $$target); \
	done
	@echo "Cross-compile done. Individual per-arch tarballs are assembled by release.yml in CI."

smoke-tarball:
	bash scripts/byo-smoke.sh

verify-tarball:
	@[ -n "$$TARBALL" ] || { echo "usage: make verify-tarball TARBALL=<path> SIG=<path> CERT=<path> [SIGNER=<regex>]"; exit 1; }
	@[ -n "$$SIG" ]     || { echo "SIG= required"; exit 1; }
	@[ -n "$$CERT" ]    || { echo "CERT= required"; exit 1; }
	cosign verify-blob \
	  --certificate "$$CERT" \
	  --signature   "$$SIG" \
	  --certificate-identity-regexp "$${SIGNER:-^https://github\\.com/thewattlabs/wattcloud/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+.*$$}" \
	  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
	  "$$TARBALL"
	@echo "Signature verified ✓"

docker-image: build
	docker build -t wattcloud:ci -f byo-relay/Dockerfile byo-relay

release-help:
	@echo "Production releases flow through GitHub Actions — do NOT build + push locally:"
	@echo "  1. git tag -s v0.1.0   # sign with your SSH/GPG key"
	@echo "  2. git push origin v0.1.0"
	@echo "  3. .github/workflows/release.yml:"
	@echo "       - cross-compiles byo-relay (x86_64 + aarch64 glibc)"
	@echo "       - assembles per-arch tarballs in the install layout"
	@echo "       - cosign sign-blob each tarball + install.sh + CHECKSUMS.txt"
	@echo "       - publishes GitHub Release with all assets"
	@echo "  4. Operators install/upgrade via install.sh + wattcloud-update,"
	@echo "     which cosign-verify the tarball before extraction."
	@echo
	@echo "Prereleases (tags with '-') are flagged so /releases/latest/download"
	@echo "stays on the last stable version."

# ---- cleanup ---------------------------------------------------------------

clean:
	@echo "Removing build artifacts..."
	cargo clean --manifest-path Cargo.toml || true
	cargo clean --manifest-path byo-relay/Cargo.toml || true
	rm -rf target byo-relay/target sdk/*/target
	rm -rf node_modules frontend/node_modules
	rm -rf frontend/dist byo-relay/dist
	rm -rf frontend/src/pkg sdk/sdk-wasm/pkg
	rm -rf $(DIST_DIR) .dev-state
	@echo "Done. (.env.dev kept — delete manually if you want fresh dev keys.)"

clean-docker:
	@echo "Pruning dangling Docker images + builder cache older than 7 days..."
	docker image prune -f
	docker builder prune -f --filter 'until=168h'
	@echo "Skipped: docker volume prune."

clean-all: clean clean-docker

.PHONY: help dev dev-stop dev-frontend dev-relay claim-token regenerate-claim-token \
        build-sdk-wasm build-frontend build \
        test test-sdk test-byo-relay test-frontend lint fmt ci \
        tarball tarball-all smoke-tarball verify-tarball docker-image release-help \
        clean clean-docker clean-all
