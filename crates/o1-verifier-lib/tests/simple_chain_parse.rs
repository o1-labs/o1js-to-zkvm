//! Verifies the Rust side can ingest the wrap VI + SRS msgpack fixtures
//! produced by `mina/src/lib/crypto/pickles/simple_chain/simple_chain.exe`.

use o1_verifier_lib::load_pallas_verifier_index;

const WRAP_VI: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_vi.bin");
const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");

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
