# Build and run

Targets in this doc are exactly what CI runs. If something here drifts from `.github/workflows/ci.yml`, trust the workflow.

## Prerequisites

- Node — pinned by `.nvmrc` (22.22.2)
- Rust — pinned by `rust-toolchain.toml` (1.92.0). `rustup` installs it on first `cargo` invocation.
- `unzip` on `PATH` (used by `install.sh` to extract protoc)

The `lint` and `rust-e2e-test` jobs in CI also install the SP1 toolchain and protoc; see those steps for the exact paths and cache key.

## Install

```
make install
```

Runs `npm ci` and `./install.sh`. The script fetches the SP1 toolchain into `$HOME/.sp1`, registers the `succinct` rustup toolchain, and unpacks protoc into `$HOME/.local`. Append both to `PATH`:

```
export PATH="$HOME/.sp1/bin:$HOME/.local/bin:$PATH"
```

CI does the equivalent via the "Add SP1 and protoc to PATH" step.

## Build

```
make build-ts                 # TypeScript CLI -> dist/src/cli.js, run as: npx o1js-cli ...
make build-rust               # o1zkvm host + guest ELF -> target/release/o1zkvm
```

`build-rust` embeds the VK and SRS for one specific circuit into the guest at compile time. The circuit JSON is selected by `CIRCUIT_JSON`; the Makefile defaults to `fixtures/circuit.json` and `$(abspath)`s it (cargo build scripts run with a different cwd, so a relative path would fail). Override:

```
CIRCUIT_JSON=/abs/or/rel/path/circuit.json make build-rust
```

## Run

| Target | What it does |
| --- | --- |
| `make ts-unit-tests` | Jest unit tests for the TS CLI |
| `make ts-e2e-tests` | TS CLI compile / prove / verify against the bundled circuit |
| `make rust-unit-tests` | `cargo test` on `o1-verifier-lib`, including the layout canary in `tests/srs_layout.rs` |
| `make rust-e2e-tests` | Compile circuit, generate Kimchi proof via TS CLI, verify it inside SP1 (`SP1_PROVER=mock`) |

All four run in CI. `rust-e2e-tests` is the only one that needs the SP1 toolchain on PATH.

### o1zkvm CLI

```
target/release/o1zkvm --proof <proof.json>
```

`<proof.json>` is the file produced by `npx o1js-cli prove`. The host hands the proof + serialized public inputs to the guest, then asserts the committed `valid` flag.

Backend is selected by `SP1_PROVER` (`mock` / `cpu` / `network`). `make rust-e2e-tests` sets `SP1_PROVER=mock` — no real proof is generated; the guest is executed through the SP1 cycle-counting executor and the verification result is committed as the public output.

For tracing visibility, set `RUST_LOG` (the host does not call `setup_logger()` so default emission is minimal):

```
RUST_LOG=info make rust-e2e-tests
