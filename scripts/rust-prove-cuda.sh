#!/usr/bin/env bash
set -euo pipefail

# Full pipeline that generates a real SP1 proof using the local CUDA GPU.
# Requires an NVIDIA GPU and CUDA drivers; sp1-cuda will download
# `~/.sp1/bin/sp1-gpu-server` on first run.

export SP1_PROVER=cuda
# Verbose by default — long Core proofs need this to diagnose silent server
# crashes. Override at the call site if you want quieter output.
export RUST_LOG=${RUST_LOG:-sp1_gpu_server=debug,sp1=debug,info}
CUDA_DEVICE=${CUDA_DEVICE:-0}
SP1_GPU_SOCKET="/tmp/sp1-cuda-${CUDA_DEVICE}.sock"
SP1_GPU_LOG="/tmp/sp1-gpu-server-${CUDA_DEVICE}.log"
GPU_PID=""

WORK_DIR=$(mktemp -d)

cleanup() {
  rm -rf "$WORK_DIR"
  if [ -n "$GPU_PID" ] && kill -0 "$GPU_PID" 2>/dev/null; then
    kill "$GPU_PID" 2>/dev/null || true
    wait "$GPU_PID" 2>/dev/null || true
  fi
  rm -f "$SP1_GPU_SOCKET"
}
trap cleanup EXIT

# sp1-cuda 6.0.2's connect retry budget (~1s) is shorter than this GPU's
# socket-bind time (~1.3s), so the SDK's auto-spawned server gets killed off
# before it's ready. Pre-start the server here; the SDK will still try to spawn
# its own and harmlessly fail with EADDRINUSE, then connect to ours.
#
# The script owns the GPU server for its lifetime; any leftover socket from a
# prior run is removed before spawning. If you need to share an externally
# managed server, run prove-cuda from a shell that already has it set up.
ensure_gpu_server() {
  rm -f "$SP1_GPU_SOCKET"
  echo "==> Starting sp1-gpu-server (device $CUDA_DEVICE)..."
  CUDA_VISIBLE_DEVICES="$CUDA_DEVICE" "$HOME/.sp1/bin/sp1-gpu-server" \
    > "$SP1_GPU_LOG" 2>&1 &
  GPU_PID=$!
  for _ in $(seq 1 50); do
    [ -S "$SP1_GPU_SOCKET" ] && break
    if ! kill -0 "$GPU_PID" 2>/dev/null; then
      echo "sp1-gpu-server exited before binding $SP1_GPU_SOCKET; see $SP1_GPU_LOG"
      exit 1
    fi
    sleep 0.1
  done
  if ! [ -S "$SP1_GPU_SOCKET" ]; then
    echo "sp1-gpu-server failed to bind $SP1_GPU_SOCKET within 5s; see $SP1_GPU_LOG"
    exit 1
  fi
  echo "==> sp1-gpu-server ready (PID $GPU_PID)"
}

echo "==> Working directory: $WORK_DIR"
echo "==> SP1_PROVER=$SP1_PROVER"

# Step 1: Build TypeScript CLI
echo "==> Building TypeScript CLI..."
make build-ts

# Step 2: Compile the circuit
echo "==> Compiling circuit..."
npx o1js-cli compile -o "$WORK_DIR/circuit.json"

# Step 3: Build the o1zkvm host CLI (guest embeds circuit.json at compile time)
echo "==> Building o1zkvm..."
CIRCUIT_JSON="$WORK_DIR/circuit.json" make build-rust

# Step 4: Generate a Kimchi proof and verify with TS CLI
echo "==> Generating Kimchi proof..."
cat > "$WORK_DIR/inputs.json" <<'JSON'
{"publicInput": "8", "privateInput": "2"}
JSON
npx o1js-cli prove -i "$WORK_DIR/inputs.json" -o "$WORK_DIR/proof.json"

echo "==> Verifying Kimchi proof with TS CLI..."
npx o1js-cli verify -c "$WORK_DIR/circuit.json" -p "$WORK_DIR/proof.json"

# Step 5: Generate a real SP1 proof on GPU and verify it
ensure_gpu_server
echo "==> Generating real SP1 proof on CUDA..."
target/release/o1zkvm --proof "$WORK_DIR/proof.json" --prove

echo "==> CUDA proof generation succeeded."
