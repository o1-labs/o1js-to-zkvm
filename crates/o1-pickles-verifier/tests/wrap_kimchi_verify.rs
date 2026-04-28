//! End-to-end verification of the kimchi wrap proof using the same
//! library entry point the SP1 guest calls
//! ([`verify_wrap_proof_precomputed`]). The test runs in std-land
//! against the b0..b3 fixtures, exercising both base-descended (b0)
//! and recursive (b1..b3) cases.

#![cfg(feature = "std")]

use o1_pickles_verifier::messages::{compute_dummy_wrap_sg, WrapVkCommitments};
use o1_pickles_verifier::parse::{canonical_proof_repr_msgpack, parse_proof_repr_json};
use o1_pickles_verifier::verify::{
    host_populate_prev_challenges, host_precompute, verify_wrap_proof_precomputed, WrapVerifySetup,
};
use o1_pickles_verifier::Pallas;
use o1_verifier_lib::{load_pallas_verifier_index, PallasProof};
use poly_commitment::ipa::SRS;

const WRAP_VI: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_vi.bin");
const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");

const PROOF_REPR_B0: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");
const WRAP_PROOF_B0: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b0.bin");
const PROOF_REPR_B1: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b1.json");
const WRAP_PROOF_B1: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b1.bin");
const PROOF_REPR_B2: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b2.json");
const WRAP_PROOF_B2: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b2.bin");
const PROOF_REPR_B3: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b3.json");
const WRAP_PROOF_B3: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b3.bin");

fn run_iteration(label: &str, proof_repr_json: &str, wrap_proof_msgpack: &[u8]) {
    let parsed = parse_proof_repr_json(proof_repr_json).expect("parse_proof_repr_json");
    let stmt = parsed.statement;
    let prev_evals = parsed.prev_evals;
    let proof_repr_msgpack =
        canonical_proof_repr_msgpack(proof_repr_json).expect("canonicalize proof_repr");

    let srs: SRS<Pallas> = rmp_serde::from_slice(WRAP_SRS).expect("parse Pallas SRS");
    let dummy_sg = compute_dummy_wrap_sg(&srs);

    let mut wrap_proof: PallasProof =
        rmp_serde::from_slice(wrap_proof_msgpack).expect("parse wrap proof");
    host_populate_prev_challenges(&mut wrap_proof, &stmt, dummy_sg);
    let wrap_proof_with_prev =
        rmp_serde::to_vec(&wrap_proof).expect("re-encode wrap proof with prev_challenges");

    let precomputed = host_precompute(&stmt, &prev_evals);
    let precomputed_msgpack = rmp_serde::to_vec(&precomputed).expect("rmp-encode HostPrecomputed");

    let vi = load_pallas_verifier_index(WRAP_VI, WRAP_SRS);
    let vk_commitments = WrapVkCommitments::extract(&vi);
    let setup = WrapVerifySetup {
        vk_commitments: &vk_commitments,
    };

    verify_wrap_proof_precomputed(
        &setup,
        WRAP_VI,
        WRAP_SRS,
        &proof_repr_msgpack,
        &wrap_proof_with_prev,
        &precomputed_msgpack,
    )
    .unwrap_or_else(|e| panic!("[{}] verify_wrap_proof_precomputed failed: {:?}", label, e));
}

#[test]
fn b0_wrap_proof_verifies() {
    run_iteration("b0", PROOF_REPR_B0, WRAP_PROOF_B0);
}

#[test]
fn b1_wrap_proof_verifies() {
    run_iteration("b1", PROOF_REPR_B1, WRAP_PROOF_B1);
}

#[test]
fn b2_wrap_proof_verifies() {
    run_iteration("b2", PROOF_REPR_B2, WRAP_PROOF_B2);
}

#[test]
fn b3_wrap_proof_verifies() {
    run_iteration("b3", PROOF_REPR_B3, WRAP_PROOF_B3);
}
