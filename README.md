# o1js-to-zkvm

Take a circuit written in o1js, generate a proof for it, and re-verify
that proof inside the SP1 zkVM. The point is to bridge o1js circuits
into the broader zkVM ecosystem so they can be composed with other
SP1 programs.

## Install

```sh
make install
```

Installs the SP1 toolchain, protoc, and npm dependencies.

## Build

```sh
make build-ts        # TypeScript CLI
make build-rust      # Rust o1zkvm binary (embeds wrap VI/SRS from fixtures/)
```

## End-to-end test

```sh
make rust-e2e-tests
```

Verifies the checked-in `simple_chain` wrap proofs (b0 and b1) inside
the SP1 zkVM (mock mode).
