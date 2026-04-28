//! SP1 zkVM guest: verify one Simple_chain wrap proof.
//!
//! Build-time constants (embedded via `OUT_DIR` / `include_bytes!`,
//! see `build.rs`):
//!  - `simple_chain_wrap_vi.bin` / `simple_chain_wrap_srs.bin`: the
//!    raw msgpack the kimchi verifier consumes.
//!  - `dummy_wrap_sg.bin`: the `Wrap_hack.pad_accumulator` front-pad
//!    Pallas point. Function of the SRS only — bake to avoid a 2^15
//!    MSM on every guest run.
//!  - `vk_commitments.bin`: the 28 single-chunk wrap-VK commitments
//!    in pickles `index_to_field_elements` order. Constant per
//!    circuit; baked to avoid the per-call extraction.
//!
//! Runtime stdin (in order):
//!  1. `proof_repr_msgpack: Vec<u8>` — `ProofReprWire` encoded with
//!     rmp-serde by the host (JSON-decoded from the OCaml fixture and
//!     re-encoded as msgpack so we don't pay JSON-parse cycles).
//!  2. `wrap_proof_bytes: Vec<u8>` — kimchi `ProverProof` msgpack as
//!     emitted by `simple_chain.exe`.
//!
//! Committed public output: a [`CommitOutput`] carrying `(valid,
//! app_state)`. `app_state` is the application circuit's public input
//! — for Simple_chain, the (initial, current) `Vec<Fp>` pair. The
//! Groth16-wrapping end-verifier reads it to learn what the wrap
//! proof attests to. Internal decode failures (bad msgpack, etc.)
//! and kimchi rejection both yield `valid = false` with empty
//! `app_state`.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;

use o1_pickles_verifier::messages::WrapVkCommitments;
use o1_pickles_verifier::verify::{verify_wrap_proof, CommitOutput, WrapVerifySetup};
use o1_pickles_verifier::Pallas;

static WRAP_VI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_vi.bin"));
static WRAP_SRS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_srs.bin"));
static DUMMY_WRAP_SG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dummy_wrap_sg.bin"));
static VK_COMMITMENTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vk_commitments.bin"));

pub fn main() {
    let dummy_sg = Pallas::deserialize_compressed(DUMMY_WRAP_SG)
        .expect("baked dummy_wrap_sg.bin failed to deserialize");
    let vk_commitments = WrapVkCommitments::deserialize_compressed(VK_COMMITMENTS)
        .expect("baked vk_commitments.bin failed to deserialize");
    let setup = WrapVerifySetup {
        dummy_sg,
        vk_commitments: &vk_commitments,
    };

    let proof_repr_msgpack: Vec<u8> = sp1_zkvm::io::read();
    let wrap_proof_bytes: Vec<u8> = sp1_zkvm::io::read();

    let output = match verify_wrap_proof(
        &setup,
        WRAP_VI,
        WRAP_SRS,
        &proof_repr_msgpack,
        &wrap_proof_bytes,
    ) {
        Ok(app_state) => CommitOutput {
            valid: true,
            app_state,
        },
        Err(_) => CommitOutput {
            valid: false,
            app_state: Vec::new(),
        },
    };

    sp1_zkvm::io::commit(&output);
}
