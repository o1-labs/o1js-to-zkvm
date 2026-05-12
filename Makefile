.PHONY: help install deps build-ts build-rust ts-unit-tests rust-unit-tests ts-e2e-tests rust-e2e-tests rust-e2e-tests-profile prove-cpu prove-cuda lint-check lint

CIRCUIT_FIXTURE := $(CURDIR)/fixtures/circuit.json

# Default to the bundled fixture and resolve to an absolute path: cargo build
# scripts run with a different cwd, so a relative CIRCUIT_JSON fails at build time.
CIRCUIT_JSON ?= $(CIRCUIT_FIXTURE)
export CIRCUIT_JSON := $(abspath $(CIRCUIT_JSON))

.DEFAULT_GOAL := help

help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: deps ## Install SP1 toolchain, protoc, and npm dependencies
	./install.sh

deps: ## Install npm dependencies
	npm ci

build-ts: ## Build the TypeScript CLI (run as `npx o1js-cli ...`)
	npm run build
	chmod +x dist/src/cli.js

build-rust: ## Build the o1zkvm Rust binary (override CIRCUIT_JSON to use a custom circuit)
	cargo build --release -p o1-verifier-host

ts-unit-tests: build-ts ## Run TypeScript unit tests
	npm test

rust-unit-tests: ## Run native Rust unit and integration tests against the checked-in fixtures
	cargo test --release -p o1-verifier-lib --features std

ts-e2e-tests: build-ts ## Run the TypeScript CLI end-to-end script
	./scripts/ts-e2e-test.sh

rust-e2e-tests: ## Run the full Rust+SP1 end-to-end script (mock prover, no GPU)
	./scripts/rust-e2e-test.sh

rust-e2e-tests-profile: ## Run e2e under SP1's sampling profiler (Gecko JSON; view at profiler.firefox.com)
	./scripts/rust-e2e-test-profile.sh

prove-cpu: ## Generate a real SP1 proof on the host CPU (rayon-parallel; tune RAYON_NUM_THREADS)
	SP1_PROVER=cpu ./scripts/rust-prove.sh

prove-cuda: ## Generate a real SP1 proof on a local NVIDIA GPU (downloads sp1-gpu-server on first run)
	SP1_PROVER=cuda ./scripts/rust-prove.sh

lint-check: ## Run all linters and formatters in check-only mode
	npm run format:check
	npm run lint
	cargo fmt --all -- --check
	# Build the host first so the guest ELF exists for include_elf!
	# (clippy skips build scripts, so we need to build separately)
	cargo build --release -p o1-verifier-host
	cargo clippy --all-targets --features std -- -D warnings

lint: ## Run all linters and formatters with auto-fix
	npm run format
	npm run lint
	cargo fmt --all
	cargo build --release -p o1-verifier-host
	cargo clippy --all-targets --features std --fix --allow-dirty --allow-staged -- -D warnings
