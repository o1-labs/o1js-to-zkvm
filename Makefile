.PHONY: help install deps submodules build-ts build-rust ts-unit-tests rust-unit-tests ts-e2e-tests rust-e2e-tests lint-check lint simple-chain-fixtures

CIRCUIT_FIXTURE := $(CURDIR)/fixtures/circuit.json
FIXTURES_DIR := $(CURDIR)/fixtures

.DEFAULT_GOAL := help

help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: submodules deps ## Install SP1 toolchain, protoc, and npm dependencies
	./install.sh

deps: ## Install npm dependencies
	npm ci

submodules: ## Initialize and update git submodules recursively (e.g. mina/proof-systems)
	git submodule update --init --recursive

simple-chain-fixtures: submodules ## Regenerate Simple_chain fixtures (b0..b3 + shared VI/SRS) from the OCaml executable into $(FIXTURES_DIR). Requires dune; enter the mina nix dev shell first if needed.
	cd $(CURDIR)/mina && \
		SIMPLE_CHAIN_FIXTURES_DIR=$(FIXTURES_DIR) \
		dune exec src/lib/crypto/pickles/simple_chain/simple_chain.exe

build-ts: ## Build the TypeScript CLI (run as `npx o1js-cli ...`)
	npm run build
	chmod +x dist/src/cli.js

build-rust: ## Build the o1zkvm Rust binary (requires CIRCUIT_JSON env var)
	@if [ -z "$$CIRCUIT_JSON" ]; then echo "error: CIRCUIT_JSON must be set" >&2; exit 1; fi
	cargo build --release -p o1-verifier-host

ts-unit-tests: build-ts ## Run TypeScript unit tests
	npm test

rust-unit-tests: ## Run native Rust unit and integration tests against the checked-in fixtures
	cargo test --release -p o1-verifier-lib --features std

ts-e2e-tests: build-ts ## Run the TypeScript CLI end-to-end script
	./scripts/ts-e2e-test.sh

rust-e2e-tests: ## Run the full Rust+SP1 end-to-end script
	./scripts/rust-e2e-test.sh

lint-check: ## Run all linters and formatters in check-only mode
	npm run format:check
	npm run lint
	cargo fmt --all -- --check
	# Build the host first so the guest ELF exists for include_elf!
	# (clippy skips build scripts, so we need to build separately)
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo build --release -p o1-verifier-host
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo clippy --all-targets --features std -- -D warnings

lint: ## Run all linters and formatters with auto-fix
	npm run format
	npm run lint
	cargo fmt --all
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo build --release -p o1-verifier-host
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo clippy --all-targets --features std --fix --allow-dirty --allow-staged -- -D warnings
