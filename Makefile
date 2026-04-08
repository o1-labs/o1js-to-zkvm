.PHONY: help install build-ts lint-check lint

CIRCUIT_FIXTURE := $(CURDIR)/fixtures/circuit.json

.DEFAULT_GOAL := help

help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install SP1 toolchain, protoc, and npm dependencies
	./install.sh
	npm install

build-ts: ## Build the TypeScript CLI (run as `npx o1zkvm ...`)
	npm run build
	chmod +x dist/src/cli.js

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
