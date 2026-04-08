#!/usr/bin/env bash
set -euo pipefail

CLI_BIN="dist/src/cli.js"

# (1) Check the TS CLI has been built
if [ ! -x "$CLI_BIN" ]; then
  echo "error: TS CLI not built. Run 'make build-ts' first." >&2
  exit 1
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
echo "==> Working directory: $WORK_DIR"

# (2) Compile the circuit
echo "==> Compiling circuit..."
npx o1js-cli compile -o "$WORK_DIR/circuit.json"

# (3) Generate the input JSON
echo "==> Writing inputs..."
cat > "$WORK_DIR/inputs.json" <<'JSON'
{"publicInput": "8", "privateInput": "2"}
JSON

# (4) Generate the proof
echo "==> Generating proof..."
npx o1js-cli prove -i "$WORK_DIR/inputs.json" -o "$WORK_DIR/proof.json"

# (5) Verify the proof
echo "==> Verifying proof..."
npx o1js-cli verify -c "$WORK_DIR/circuit.json" -p "$WORK_DIR/proof.json"

echo "==> TS e2e test passed!"
