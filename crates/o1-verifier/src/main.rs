//! SP1 zkVM guest: slim wrap-proof verifier.
//!
//! Build-time constants (embedded via `OUT_DIR` / `include_bytes!`,
//! see `build.rs`):
//!  - `simple_chain_wrap_vi.bin` / `simple_chain_wrap_srs.bin`: raw
//!    msgpack the kimchi verifier consumes.
//!  - `vk_commitments.bin`: 28 single-chunk wrap-VK commitments.
//!
//! Runtime stdin (in order):
//!  1. `proof_repr_msgpack: Vec<u8>` — canonical proof_repr msgpack.
//!     Hashed via the SHA-256 precompile to produce the
//!     `statement_digest` we commit; the user-side `o1zkvm hash`
//!     subcommand reproduces this from their JSON.
//!  2. `wrap_proof_bytes: Vec<u8>` — kimchi `ProverProof` msgpack.
//!     `prev_challenges` is populated by the host before encoding.
//!  3. `host_precomputed_msgpack: Vec<u8>` — `expand_deferred` outputs
//!     plus `wrap_messages_digest_fq`. The host runs these once in
//!     std-land; the guest skips the heavy Polish-token interpreter.
//!     Wrong values → kimchi rejects (the wrap circuit re-derives
//!     them internally and asserts equality with the public input).
//!
//! Committed public output: [`CommitOutput`]. End-verifier reads:
//! - `valid`: kimchi accepted.
//! - `app_state`: the wrap proof's application-level public input.
//!   Bound into the kimchi public input via Poseidon, so a kimchi-
//!   accepted run guarantees the committed `app_state` matches what
//!   the wrap circuit was committed against.
//! - `statement_digest`: SHA-256 of `proof_repr_msgpack`. Lets a
//!   holder of the same serialized statement verify "this SP1
//!   attestation corresponds to *my* statement" without re-running
//!   the verifier.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;

use o1_pickles_verifier::messages::WrapVkCommitments;
use o1_pickles_verifier::verify::{verify_wrap_proof_precomputed, CommitOutput, WrapVerifySetup};

static WRAP_VI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_vi.bin"));
static WRAP_SRS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/simple_chain_wrap_srs.bin"));
static VK_COMMITMENTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vk_commitments.bin"));

pub fn main() {
    let vk_commitments = WrapVkCommitments::deserialize_compressed(VK_COMMITMENTS)
        .expect("baked vk_commitments.bin failed to deserialize");
    let setup = WrapVerifySetup {
        vk_commitments: &vk_commitments,
    };

    let proof_repr_msgpack: Vec<u8> = sp1_zkvm::io::read_vec();
    let wrap_proof_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let host_precomputed_msgpack: Vec<u8> = sp1_zkvm::io::read_vec();

    let output = match verify_wrap_proof_precomputed(
        &setup,
        WRAP_VI,
        WRAP_SRS,
        &proof_repr_msgpack,
        &wrap_proof_bytes,
        &host_precomputed_msgpack,
    ) {
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
