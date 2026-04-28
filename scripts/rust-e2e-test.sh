#!/usr/bin/env bash
set -euo pipefail

# End-to-end Rust+SP1 test for the Simple_chain wrap-proof flow.
#
# Uses the checked-in `fixtures/simple_chain_*` artifacts (emitted by
# `make simple-chain-fixtures` from the OCaml `simple_chain.exe`):
#   - `simple_chain_wrap_vi.bin` and `simple_chain_wrap_srs.bin`
#     are baked into the guest at build time via build.rs.
#   - `simple_chain_proof_repr_b{N}.json` and
#     `simple_chain_wrap_proof_b{N}.bin` are passed to the host CLI
#     and forwarded to the guest as runtime stdin.
#
# We exercise b0 (descends from a dummy base case) and b1 (descends
# from the real proof b0) under the SP1 mock prover — enough to cover
# both shapes without bloating CI time. The wider chain b0..b3 is
# already exercised by `rust-unit-tests` via `wrap_kimchi_verify`.

FIXTURES_DIR="$(pwd)/fixtures"

echo "==> Building o1zkvm..."
SIMPLE_CHAIN_FIXTURES_DIR="$FIXTURES_DIR" make build-rust

echo "==> Verifying b0 and b1 inside SP1 zkVM (mock mode)..."
for n in 0 1; do
    echo "  -- b${n}"
    SP1_PROVER=mock target/release/o1zkvm \
        --proof-repr "$FIXTURES_DIR/simple_chain_proof_repr_b${n}.json" \
        --wrap-proof "$FIXTURES_DIR/simple_chain_wrap_proof_b${n}.bin"
done

echo "==> All Rust+SP1 e2e iterations passed!"
