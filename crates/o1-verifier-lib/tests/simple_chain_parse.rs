//! Verifies the Rust side can ingest the msgpack fixtures produced by
//! `mina/src/lib/crypto/pickles/simple_chain/simple_chain.exe`.

use o1_verifier_lib::{load_pallas_verifier_index, PallasProof};

const WRAP_VI: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_vi.bin");
const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");
const WRAP_PROOF: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof.bin");

#[test]
fn parses_simple_chain_wrap_vi_and_srs() {
    let vi = load_pallas_verifier_index(WRAP_VI, WRAP_SRS);

    // Expected shape for a Pickles wrap verifier index (Pallas / Tock):
    // - max_poly_size = 2^15 (Tock SRS size)
    // - public = 40 (pickles-padded wrap statement size)
    // - prev_challenges = 2 (Nat.N2 max_proofs_verified for wrap)
    assert_eq!(vi.max_poly_size, 32768, "wrap max_poly_size");
    assert_eq!(vi.public, 40, "wrap public-input size");
    assert_eq!(vi.prev_challenges, 2, "wrap prev_challenges");
}

#[test]
fn parses_simple_chain_wrap_proof() {
    // The OCaml side extracts the inner wrap Kimchi `ProverProof` from the
    // pickles Proof.t for the recursive-step proof (the `b1` in
    // simple_chain.exe) and serializes it via the new
    // `caml_pasta_fq_plonk_proof_write` stub. Here we assert the Rust side
    // can deserialize those bytes into our `PallasProof` type alias via
    // the same rmp_serde pipeline the VI and SRS already use. Wrap
    // public-input / prev-challenges for a real verify call would still
    // need to come from pickles' prepared-statement packing — a separate
    // step we haven't tackled yet.
    let _proof: PallasProof = rmp_serde::from_slice(WRAP_PROOF)
        .expect("failed to deserialize simple_chain wrap Kimchi proof");
}
