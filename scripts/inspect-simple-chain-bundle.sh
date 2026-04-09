#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <simple-chain-bundle.json> [output.json]" >&2
  exit 2
fi

cargo run -p o1-verifier-lib --features std --bin pickles_inspect -- "$@"
