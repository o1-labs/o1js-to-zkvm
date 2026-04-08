.PHONY: help install deps build-ts build-rust ts-unit-tests rust-unit-tests ts-e2e-tests rust-e2e-tests lint-check lint

CIRCUIT_FIXTURE := $(CURDIR)/fixtures/circuit.json

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
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo clippy --all-targets --features std -- -D warnings

lint: ## Run all linters and formatters with auto-fix
	npm run format
	npm run lint
	cargo fmt --all
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo clippy --all-targets --features std --fix --allow-dirty --allow-staged -- -D warnings
