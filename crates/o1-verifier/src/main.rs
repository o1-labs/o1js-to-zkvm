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
//! Committed public output: `(valid: bool, app_state: Vec<Fp>)`. The
//! Groth16-wrapping end-verifier reads `app_state` to learn what the
//! wrap proof attests to (the application circuit's public input
//! plays the proxy role for higher-level statements). When kimchi
//! rejects, `app_state` is committed empty.
//!
//! Internal decode failures (bad msgpack, etc.) bubble up as `Err`;
//! we treat both `Err` and a kimchi reject as `valid = false`.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;

use o1_pickles_verifier::messages::WrapVkCommitments;
use o1_pickles_verifier::verify::{verify_wrap_proof, WrapVerifySetup};
use o1_pickles_verifier::{Fp, Pallas};

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

    let result = verify_wrap_proof(
        &setup,
        WRAP_VI,
        WRAP_SRS,
        &proof_repr_msgpack,
        &wrap_proof_bytes,
    );
    let (valid, app_state) = match result {
        Ok(app_state) => (true, app_state),
        Err(_) => (false, Vec::<Fp>::new()),
    };

    sp1_zkvm::io::commit(&valid);
    sp1_zkvm::io::commit(&app_state);
}
