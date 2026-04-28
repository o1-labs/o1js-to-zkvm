//! Confirm `UncheckedSrs<Pallas>` deserializes the wrap SRS bytes
//! that `Kimchi_bindings.Protocol.SRS.Fq.write` produced (the prod
//! `SRS<G>` shape: `g`, `h`, no `lagrange_bases`). The point of the
//! mirror struct is to dispatch to `deserialize_compressed_unchecked`
//! per generator, skipping `is_on_curve` for a baked, trusted SRS.

#![cfg(feature = "std")]

use o1_pickles_verifier::Pallas;
use o1_verifier_lib::UncheckedSrs;

const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");

#[test]
fn unchecked_srs_deserializes_prod_wrap_srs_bytes() {
    let unchecked: UncheckedSrs<Pallas> =
        rmp_serde::from_slice(WRAP_SRS).expect("UncheckedSrs deserialize");
    // Wrap SRS is 2^15 generators (Tock IPA rounds = 15).
    assert_eq!(unchecked.g.len(), 1 << 15);
}
