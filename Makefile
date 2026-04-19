# Thin wrapper around the pnpm + cargo + docker commands that already live
# in package.json, scripts/ci.sh, and the Dockerfile. Nothing here implements
# build logic — it's all delegation. Canonical CI is GitHub Actions.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

CYAN   := $(shell tput setaf 6 2>/dev/null || echo "")
YELLOW := $(shell tput setaf 3 2>/dev/null || echo "")
RESET  := $(shell tput sgr0   2>/dev/null || echo "")

# ---- help ------------------------------------------------------------------

help:
	@echo "$(CYAN)Wattcloud — Makefile targets$(RESET)"
	@echo
	@echo "$(YELLOW)dev$(RESET)"
	@echo "  dev               Start the Vite dev server (frontend on :5173)"
	@echo "  build-sdk-wasm    wasm-pack build → frontend/src/pkg/"
	@echo "  build-byo         Build the @wattcloud/sdk TS package"
	@echo "  build-frontend    Vite build of the SPA → byo-server/dist/"
	@echo "  build             build-sdk-wasm + build-byo + build-frontend"
	@echo "  test              cargo + npm tests across the repo"
	@echo "  test-sdk          cargo test sdk-core (crypto + byo + providers)"
	@echo "  test-byo-server   cargo test byo-server"
	@echo "  test-byo          npm test in byo/"
	@echo "  test-frontend     npm test in frontend/"
	@echo "  lint              cargo clippy + eslint on frontend/byo"
	@echo "  fmt               cargo fmt across both workspaces"
	@echo "  ci                Full local CI (scripts/ci.sh)"
	@echo
	@echo "$(YELLOW)prod$(RESET)"
	@echo "  image             Build the byo-server Docker image as wattcloud:ci"
	@echo "  smoke             Run scripts/byo-smoke.sh against the image"
	@echo "  release-help      Reminder on how tagged releases flow through GH Actions"
	@echo
	@echo "$(YELLOW)cleanup$(RESET)"
	@echo "  clean             cargo clean + rm node_modules/dist/pkg/target"
	@echo "  clean-docker      Prune dangling Docker images + builder cache > 7d"
	@echo "  clean-all         clean + clean-docker"

# ---- dev -------------------------------------------------------------------

dev:
	cd frontend && npm run dev

build-sdk-wasm:
	cd sdk/sdk-wasm && wasm-pack build --release --target web \
	  --out-dir ../../frontend/src/pkg --out-name wattcloud_sdk_wasm

build-byo:
	cd byo && npm ci --silent && npm run build

build-frontend:
	cd frontend && npm ci --silent && npm run build

build: build-sdk-wasm build-byo build-frontend

test-sdk:
	cargo test --manifest-path sdk/sdk-core/Cargo.toml \
	  --no-default-features --features "crypto byo providers"

test-byo-server:
	cargo test --manifest-path byo-server/Cargo.toml

test-byo:
	cd byo && npm ci --silent && npm test

test-frontend:
	cd frontend && npm ci --silent && npm test

test: test-sdk test-byo-server test-byo test-frontend

lint:
	cargo clippy --manifest-path sdk/sdk-core/Cargo.toml \
	  --no-default-features --features "crypto byo providers" \
	  --all-targets -- -D warnings
	cargo clippy --manifest-path byo-server/Cargo.toml --all-targets -- -D warnings
	cd frontend && npm run lint

fmt:
	cargo fmt --manifest-path Cargo.toml
	cargo fmt --manifest-path byo-server/Cargo.toml

ci:
	bash scripts/ci.sh

# ---- prod ------------------------------------------------------------------

image: build
	docker build -t wattcloud:ci -f byo-server/Dockerfile byo-server

smoke:
	bash scripts/byo-smoke.sh

release-help:
	@echo "Tagged releases flow through GitHub Actions — do NOT build + push locally:"
	@echo "  1. git tag -s v0.1.0   # sign the tag with your SSH/GPG key"
	@echo "  2. git push origin v0.1.0"
	@echo "  3. Actions runs .github/workflows/release.yml →"
	@echo "     builds + pushes to ghcr.io/wattzupbyte/wattcloud, cosign-signs,"
	@echo "     writes the @sha256:... digest into the GitHub Release body."
	@echo "  4. On the VPS:  ./scripts/update.sh ghcr.io/wattzupbyte/wattcloud@sha256:<digest>"
	@echo
	@echo "For emergency unsigned roll-outs only:  bash scripts/release.sh v0.1.0-manual"

# ---- cleanup ---------------------------------------------------------------

clean:
	@echo "Removing build artifacts..."
	cargo clean --manifest-path Cargo.toml || true
	cargo clean --manifest-path byo-server/Cargo.toml || true
	rm -rf target byo-server/target sdk/*/target
	rm -rf node_modules byo/node_modules frontend/node_modules
	rm -rf byo/dist frontend/dist byo-server/dist
	rm -rf frontend/src/pkg sdk/sdk-wasm/pkg
	@echo "Done."

clean-docker:
	@echo "Pruning dangling Docker images + builder cache older than 7 days..."
	docker image prune -f
	docker builder prune -f --filter 'until=168h'
	@echo "Skipped: docker volume prune (would eat stats-data volumes)."
	@echo "Run 'docker volume prune' manually if you know you don't need any volumes."

clean-all: clean clean-docker

.PHONY: help dev build-sdk-wasm build-byo build-frontend build \
        test test-sdk test-byo-server test-byo test-frontend lint fmt ci \
        image smoke release-help \
        clean clean-docker clean-all
