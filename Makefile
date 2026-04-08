.PHONY: lint-check lint

CIRCUIT_FIXTURE := $(CURDIR)/fixtures/circuit.json

lint-check:
	npm run format:check
	npm run lint
	cargo fmt --all -- --check
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo clippy --all-targets --features std -- -D warnings

lint:
	npm run format
	npm run lint
	cargo fmt --all
	CIRCUIT_JSON=$(CIRCUIT_FIXTURE) cargo clippy --all-targets --features std --fix --allow-dirty --allow-staged -- -D warnings
