#!/usr/bin/env bash
set -euo pipefail

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Working directory: $WORK_DIR"

# Step 1: Build TypeScript
echo "==> Building TypeScript..."
npm run build

# Step 2: Compile the circuit
echo "==> Compiling circuit..."
npm run cli -- compile -o "$WORK_DIR/circuit.json"

# Step 3: Build the Rust workspace (guest embeds circuit.json at compile time)
echo "==> Building Rust workspace..."
CIRCUIT_JSON="$WORK_DIR/circuit.json" cargo build --release -p o1-verifier-host

# Step 4: Generate a proof and verify with TS CLI
echo "==> Generating proof..."
cat > "$WORK_DIR/inputs.json" <<'JSON'
{"publicInput": "8", "privateInput": "2"}
JSON
npm run cli -- prove -i "$WORK_DIR/inputs.json" -o "$WORK_DIR/proof.json"

echo "==> Verifying with TS CLI..."
npm run cli -- verify -c "$WORK_DIR/circuit.json" -p "$WORK_DIR/proof.json"

# Step 5: Verify inside SP1 zkVM (mock mode)
echo "==> Verifying inside SP1 zkVM (mock mode)..."
SP1_PROVER=mock CIRCUIT_JSON="$WORK_DIR/circuit.json" \
  cargo run --release -p o1-verifier-host -- --proof "$WORK_DIR/proof.json"

echo "==> All e2e tests passed!"
