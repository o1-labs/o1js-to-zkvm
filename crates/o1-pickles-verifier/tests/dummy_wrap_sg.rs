//! Structural sanity for `compute_dummy_wrap_sg`: deterministic and
//! non-identity. The numeric correctness of the dummy sg is exercised
//! by `wrap_kimchi_verify` — kimchi rejects a wrap proof whose
//! `prev_challenges[0].comm` doesn't match `Wrap_hack.pad_accumulator`'s
//! `Dummy.Ipa.Wrap.sg`, so passing kimchi verification per iteration
//! is a strictly stronger check than equality with a hardcoded
//! constant. The original equality-against-OCaml-fixture check (which
//! confirmed the recipe was right) was retired when we moved to
//! Rust-built `prev_challenges` — the existing b0 fixture's msgpack
//! no longer carries pickles' baked padding.

#![cfg(feature = "std")]

use ark_ec::AffineRepr;
use o1_pickles_verifier::messages::compute_dummy_wrap_sg;
use o1_pickles_verifier::Pallas;
use poly_commitment::ipa::SRS;

const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");

#[test]
fn dummy_wrap_sg_is_deterministic_and_nontrivial() {
    let srs: SRS<Pallas> = rmp_serde::from_slice(WRAP_SRS).expect("parse SRS");
    let a = compute_dummy_wrap_sg(&srs);
    let b = compute_dummy_wrap_sg(&srs);
    assert_eq!(a, b, "compute_dummy_wrap_sg must be deterministic");
    assert!(
        !a.is_zero(),
        "dummy sg must not be the identity / point at infinity"
    );
}
