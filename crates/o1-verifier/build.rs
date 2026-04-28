//! Embed every wrap-circuit constant we can precompute into the SP1
//! guest's read-only memory:
//!
//! * `simple_chain_wrap_vi.bin` and `simple_chain_wrap_srs.bin` —
//!   raw msgpack bytes, still needed at runtime because kimchi's
//!   verifier consumes them (and the Pallas SRS for IPA opening
//!   verification).
//! * `dummy_wrap_sg.bin` — the precomputed `Wrap_hack.pad_accumulator`
//!   front-pad commitment. Without baking, the guest would MSM 2^15
//!   Pallas generators on every run.
//! * `vk_commitments.bin` — the 28 single-chunk wrap-VK commitments
//!   in pickles `index_to_field_elements` order. Constant per
//!   circuit; baking removes the per-call extraction.
//!
//! Both baked constants are computed from the VI and SRS using the
//! exact same library helpers the host-side code uses, so build-time
//! and runtime computation agree on the value.

use std::env;
use std::fs;
use std::path::Path;

use ark_serialize::CanonicalSerialize;
use o1_pickles_verifier::messages::{compute_dummy_wrap_sg, WrapVkCommitments};
use o1_pickles_verifier::Pallas;
use o1_verifier_lib::load_pallas_verifier_index;
use poly_commitment::ipa::SRS;

const VI_NAME: &str = "simple_chain_wrap_vi.bin";
const SRS_NAME: &str = "simple_chain_wrap_srs.bin";

fn main() {
    let dir = env::var("SIMPLE_CHAIN_FIXTURES_DIR").expect(
        "SIMPLE_CHAIN_FIXTURES_DIR env var must point to the directory \
         containing simple_chain_wrap_vi.bin and simple_chain_wrap_srs.bin",
    );
    println!("cargo::rerun-if-env-changed=SIMPLE_CHAIN_FIXTURES_DIR");

    let dir = Path::new(&dir);
    let vi_path = dir.join(VI_NAME);
    let srs_path = dir.join(SRS_NAME);
    println!("cargo::rerun-if-changed={}", vi_path.display());
    println!("cargo::rerun-if-changed={}", srs_path.display());

    let out_dir = env::var("OUT_DIR").unwrap();
    let out = Path::new(&out_dir);

    // Copy the raw msgpack bytes — still needed at runtime by the
    // kimchi verifier.
    fs::copy(&vi_path, out.join(VI_NAME))
        .unwrap_or_else(|e| panic!("failed to copy {}: {e}", vi_path.display()));
    fs::copy(&srs_path, out.join(SRS_NAME))
        .unwrap_or_else(|e| panic!("failed to copy {}: {e}", srs_path.display()));

    // Bake dummy_sg: MSM of `b_poly_coefficients(dummy_chals)` across
    // the SRS's first 2^15 generators. Function only of the SRS.
    let srs_bytes = fs::read(&srs_path).unwrap();
    let srs: SRS<Pallas> = rmp_serde::from_slice(&srs_bytes).expect("parse SRS");
    let dummy_sg = compute_dummy_wrap_sg(&srs);
    let mut dummy_sg_bytes = Vec::new();
    dummy_sg
        .serialize_compressed(&mut dummy_sg_bytes)
        .expect("serialize dummy_sg");
    fs::write(out.join("dummy_wrap_sg.bin"), &dummy_sg_bytes).unwrap();

    // Bake the 28 wrap-VK commitments (single-chunk PolyComm chunks
    // pulled out of the kimchi `VerifierIndex` in
    // `index_to_field_elements` order).
    let vi_bytes = fs::read(&vi_path).unwrap();
    let vi = load_pallas_verifier_index(&vi_bytes, &srs_bytes);
    let vk_commitments = WrapVkCommitments::extract(&vi);
    let mut vk_bytes = Vec::new();
    vk_commitments
        .serialize_compressed(&mut vk_bytes)
        .expect("serialize vk_commitments");
    fs::write(out.join("vk_commitments.bin"), &vk_bytes).unwrap();
}
