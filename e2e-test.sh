#!/usr/bin/env bash
set -euo pipefail

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Working directory: $WORK_DIR"

# Step 1: Build TypeScript CLI
echo "==> Building TypeScript CLI..."
make build-ts

# Step 2: Compile the circuit
echo "==> Compiling circuit..."
npx o1js-cli compile -o "$WORK_DIR/circuit.json"

# Step 3: Build the o1zkvm host CLI (guest embeds circuit.json at compile time)
echo "==> Building o1zkvm..."
CIRCUIT_JSON="$WORK_DIR/circuit.json" make build-o1zkvm

# Step 4: Generate a proof and verify with TS CLI
echo "==> Generating proof..."
cat > "$WORK_DIR/inputs.json" <<'JSON'
{"publicInput": "8", "privateInput": "2"}
JSON
npx o1js-cli prove -i "$WORK_DIR/inputs.json" -o "$WORK_DIR/proof.json"

echo "==> Verifying with TS CLI..."
npx o1js-cli verify -c "$WORK_DIR/circuit.json" -p "$WORK_DIR/proof.json"

# Step 5: Verify inside SP1 zkVM (mock mode)
echo "==> Verifying inside SP1 zkVM (mock mode)..."
SP1_PROVER=mock target/release/o1zkvm --proof "$WORK_DIR/proof.json"

echo "==> All e2e tests passed!"
