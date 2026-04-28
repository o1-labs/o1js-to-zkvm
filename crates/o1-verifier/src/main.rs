//! SP1 zkVM guest: verify one Simple_chain wrap proof.
//!
//! Build-time: VK and SRS are embedded from `SIMPLE_CHAIN_FIXTURES_DIR`
//! (see `build.rs`).
//!
//! Runtime stdin (in order):
//!  1. `proof_repr_msgpack: Vec<u8>` — `ProofReprWire` encoded with
//!     rmp-serde. The host JSON-decodes the OCaml fixture and
//!     msgpack-encodes for us so we don't pay JSON-parse cycles
//!     inside the zkVM.
//!  2. `wrap_proof_bytes: Vec<u8>` — kimchi `ProverProof` msgpack as
//!     emitted by `simple_chain.exe`.
//!
//! Commits a single `bool` indicating whether kimchi accepts the
//! Rust-packed wrap proof. Internal decode failures (bad msgpack,
//! etc.) bubble up as `Err`; we treat both `Err` and a kimchi reject
//! as `valid = false`.

#![no_main]
sp1_zkvm::entrypoint!(main);

use o1_pickles_verifier::verify::verify_wrap_proof;

static WRAP_VI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_vi.bin"));
static WRAP_SRS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_srs.bin"));

pub fn main() {
    let proof_repr_msgpack: Vec<u8> = sp1_zkvm::io::read();
    let wrap_proof_bytes: Vec<u8> = sp1_zkvm::io::read();

    let valid =
        verify_wrap_proof(WRAP_VI, WRAP_SRS, &proof_repr_msgpack, &wrap_proof_bytes).is_ok();

    sp1_zkvm::io::commit(&valid);
}
