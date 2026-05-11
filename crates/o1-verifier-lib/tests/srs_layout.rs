//! Verifies that ark-ec's `Affine<VestaParameters>` and ark-ff's `Fp256`
//! lay out memory the way `o1_verifier_lib::srs_layout::PodVesta` assumes.
//!
//! These upstream types are not `#[repr(C)]`, so Rust does not formally
//! guarantee field order or padding. This test fails the build if upstream
//! ever drifts away from the layout the zero-copy SRS path depends on.

use std::mem::{align_of, size_of};

use ark_ec::AffineRepr;
use ark_ff::BigInt;
use mina_curves::pasta::{Fq, Vesta};
use o1_verifier_lib::parse_circuit_json_structured;
use o1_verifier_lib::srs_layout::{
    load_srs_from_pod_bytes, srs_to_pod_bytes, vesta_to_pod, PodVesta,
};
use poly_commitment::ipa::SRS;

#[test]
fn size_and_align_match() {
    assert_eq!(
        size_of::<Vesta>(),
        size_of::<PodVesta>(),
        "Vesta size = {}, PodVesta size = {}",
        size_of::<Vesta>(),
        size_of::<PodVesta>()
    );
    assert_eq!(
        align_of::<Vesta>(),
        align_of::<PodVesta>(),
        "Vesta align = {}, PodVesta align = {}",
        align_of::<Vesta>(),
        align_of::<PodVesta>()
    );
}

#[test]
fn vesta_to_pod_round_trip() {
    for v in vesta_samples() {
        let expected = vesta_to_pod(&v);

        // Reinterpret a Vesta's bytes as PodVesta. If layouts disagree, the
        // data fields will not match.
        let observed: PodVesta = unsafe { core::ptr::read(&v as *const Vesta as *const PodVesta) };

        assert_eq!(observed.x, expected.x, "x limbs mismatch for {v:?}");
        assert_eq!(observed.y, expected.y, "y limbs mismatch for {v:?}");
        assert_eq!(
            observed.infinity, expected.infinity,
            "infinity flag mismatch for {v:?}"
        );
    }
}

#[test]
fn pod_to_vesta_round_trip() {
    for original in vesta_samples() {
        let pod = vesta_to_pod(&original);

        // Reinterpret PodVesta as Vesta. This is the "unsafe coerce" path the
        // zero-copy SRS relies on.
        let reconstructed: Vesta =
            unsafe { core::ptr::read(&pod as *const PodVesta as *const Vesta) };

        assert_eq!(
            original, reconstructed,
            "Vesta reconstructed from PodVesta does not equal original"
        );
        assert_eq!(original.x, reconstructed.x);
        assert_eq!(original.y, reconstructed.y);
        assert_eq!(original.infinity, reconstructed.infinity);
    }
}

#[test]
fn slice_cast_preserves_points() {
    let originals: Vec<Vesta> = vesta_samples();
    let pods: Vec<PodVesta> = originals.iter().map(vesta_to_pod).collect();

    let recast: &[Vesta] =
        unsafe { core::slice::from_raw_parts(pods.as_ptr() as *const Vesta, pods.len()) };

    assert_eq!(recast, originals.as_slice());
}

#[test]
fn fixture_srs_round_trips_through_pod_bytes() {
    let circuit_json = include_str!("../../../fixtures/circuit.json");
    let (_vi, original) = parse_circuit_json_structured(circuit_json);

    let encoded = srs_to_pod_bytes(&original);

    // Re-align: a `Vec<u8>` is only 1-byte aligned. The production guest gets
    // alignment from a `#[repr(C, align(8))]` wrapper around `include_bytes!`.
    let aligned: Vec<u64> = aligned_to_8(&encoded);
    let aligned_bytes: &[u8] = &bytemuck::cast_slice(&aligned)[..encoded.len()];

    let decoded: SRS<Vesta> = load_srs_from_pod_bytes(aligned_bytes);

    assert_eq!(original.h, decoded.h, "h mismatch");
    assert_eq!(original.g.len(), decoded.g.len(), "g length mismatch");
    assert_eq!(original.g, decoded.g, "g mismatch");
}

/// Re-allocate a byte buffer into 8-byte aligned storage. Simulates the
/// `#[repr(C, align(8))]` wrapper the guest uses around `include_bytes!`.
fn aligned_to_8(bytes: &[u8]) -> Vec<u64> {
    let n_u64 = bytes.len().div_ceil(8);
    let mut buf: Vec<u64> = vec![0u64; n_u64];
    let dst: &mut [u8] = bytemuck::cast_slice_mut(&mut buf);
    dst[..bytes.len()].copy_from_slice(bytes);
    buf
}

fn vesta_samples() -> Vec<Vesta> {
    let g = Vesta::generator();
    let two_g = (g + g).into();
    let inf = Vesta::default();
    assert!(
        inf.infinity,
        "Vesta::default() should be the point at infinity"
    );

    // A point with hand-picked Montgomery-form limbs, to catch any internal
    // repr that disagrees with the BigInt bit pattern. `Fq::new_unchecked`
    // stores the limbs verbatim (no canonical -> Montgomery conversion).
    let x = Fq::new_unchecked(BigInt([
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0xdead_beef_cafe_babe,
        0x1357_9bdf_2468_ace0,
    ]));
    let y = Fq::new_unchecked(BigInt([
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_aaaa_bbbb_cccc,
        0x0,
    ]));
    let synthetic = Vesta::new_unchecked(x, y);

    vec![g, two_g, inf, synthetic]
}
