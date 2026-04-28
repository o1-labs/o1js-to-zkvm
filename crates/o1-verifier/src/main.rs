//! SP1 zkVM guest: slim wrap-proof verifier.
//!
//! Build-time constants (embedded via `OUT_DIR` / `include_bytes!`,
//! see `build.rs`):
//!  - `simple_chain_wrap_vi.bin` / `simple_chain_wrap_srs.bin`: raw
//!    msgpack the kimchi verifier consumes.
//!  - `vk_commitments.bin`: 28 single-chunk wrap-VK commitments.
//!
//! Runtime stdin: a single [`GuestInput`] value.
//!
//! Committed public output: [`CommitOutput`]. End-verifier reads:
//! - `valid`: kimchi accepted.
//! - `app_state`: the wrap proof's application-level public input.
//!   Bound into the kimchi public input via Poseidon, so a kimchi-
//!   accepted run guarantees the committed `app_state` matches what
//!   the wrap circuit was committed against.
//! - `statement_digest`: SHA-256 of `input.proof_repr_msgpack`. Lets a
//!   holder of the same serialized statement verify "this SP1
//!   attestation corresponds to *my* statement" without re-running
//!   the verifier.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;

use o1_pickles_verifier::kimchi_input::WrapVkCommitments;
use o1_pickles_verifier::verify::{
    verify_wrap_proof_precomputed, CommitOutput, GuestInput, WrapVerifySetup,
};

static WRAP_VI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_vi.bin"));
static WRAP_SRS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_srs.bin"));
static VK_COMMITMENTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vk_commitments.bin"));

pub fn main() {
    let vk_commitments = WrapVkCommitments::deserialize_compressed(VK_COMMITMENTS)
        .expect("baked vk_commitments.bin failed to deserialize");
    let setup = WrapVerifySetup {
        vk_commitments: &vk_commitments,
    };

    let input: GuestInput = sp1_zkvm::io::read();

    let output = match verify_wrap_proof_precomputed(&setup, WRAP_VI, WRAP_SRS, input) {
        Ok((app_state, statement_digest)) => CommitOutput {
            valid: true,
            app_state,
            statement_digest,
        },
        Err(_) => CommitOutput {
            valid: false,
            app_state: Vec::new(),
            statement_digest: [0u8; 32],
        },
    };

    sp1_zkvm::io::commit(&output);
}
