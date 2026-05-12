//! Flat byte layout for an `SRS<Vesta>` and its precomputed Lagrange basis,
//! designed for zero-parse loading inside the SP1 guest. The build host
//! serializes via [`srs_to_pod_bytes_with_basis`]; the guest reads back via
//! [`load_srs_from_pod_bytes`], which is a pair of slice casts — no
//! deserialization.
//!
//! Blob layout (all little-endian):
//!
//! ```text
//! offset                      field          bytes
//! 0                           srs_len: u64   8
//! 8                           SRS points     72 * srs_len   (h, then g)
//! 8 + 72*srs_len              basis_len: u64 8
//! 16 + 72*srs_len             basis points   72 * basis_len (one Vesta per
//!                                                            single-chunk
//!                                                            PolyComm)
//! ```
//!
//! `basis_len` must equal the verifier index's `domain.size()`. Each Lagrange
//! basis entry is encoded as a single Vesta point (we assert
//! `PolyComm::chunks.len() == 1` at encode time).
//!
//! Soundness of the slice casts depends on `PodVesta` being bit-identical to
//! `Vesta` for the pinned arkworks versions. This is checked by the layout
//! tests in `tests/srs_layout.rs`.

use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::{Pod, Zeroable};
use mina_curves::pasta::Vesta;
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::SRS;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct PodVesta {
    pub x: [u64; 4],
    pub y: [u64; 4],
    pub infinity: u8,
    pub _pad: [u8; 7],
}

pub fn vesta_to_pod(v: &Vesta) -> PodVesta {
    PodVesta {
        x: v.x.0 .0,
        y: v.y.0 .0,
        infinity: u8::from(v.infinity),
        _pad: [0; 7],
    }
}

/// Encode an SRS and a precomputed Lagrange basis. Used by the build script.
///
/// Each `PolyComm` in `basis` must have exactly one chunk (i.e. the SRS is
/// large enough to commit any single Lagrange polynomial unchunked). This is
/// the case whenever `srs.g.len() >= domain.size()`, which always holds for
/// our circuits.
pub fn srs_to_pod_bytes_with_basis(srs: &SRS<Vesta>, basis: &[PolyComm<Vesta>]) -> Vec<u8> {
    let mut srs_points: Vec<PodVesta> = Vec::with_capacity(1 + srs.g.len());
    srs_points.push(vesta_to_pod(&srs.h));
    srs_points.extend(srs.g.iter().map(vesta_to_pod));

    let mut basis_points: Vec<PodVesta> = Vec::with_capacity(basis.len());
    for (i, poly) in basis.iter().enumerate() {
        assert_eq!(
            poly.chunks.len(),
            1,
            "lagrange basis poly {i}: expected single-chunk PolyComm, got {} chunks",
            poly.chunks.len()
        );
        basis_points.push(vesta_to_pod(&poly.chunks[0]));
    }

    let mut out = Vec::with_capacity(
        8 + srs_points.len() * size_of::<PodVesta>()
            + 8
            + basis_points.len() * size_of::<PodVesta>(),
    );
    out.extend_from_slice(&(srs_points.len() as u64).to_le_bytes());
    out.extend_from_slice(bytemuck::cast_slice(&srs_points));
    out.extend_from_slice(&(basis_points.len() as u64).to_le_bytes());
    out.extend_from_slice(bytemuck::cast_slice(&basis_points));
    out
}

/// Decode the blob into the SRS and the Lagrange basis via slice casts.
///
/// `bytes` must be 8-byte aligned. The guest gets alignment from a
/// `#[repr(C, align(8))]` wrapper around `include_bytes!`.
pub fn load_srs_from_pod_bytes(bytes: &[u8]) -> (SRS<Vesta>, Vec<PolyComm<Vesta>>) {
    let (srs_points, after_srs) = read_section(bytes);
    let (basis_points, _tail) = read_section(after_srs);

    assert!(srs_points.len() >= 2, "SRS must have h + at least one g");
    let mut srs = SRS::<Vesta>::default();
    srs.h = srs_points[0];
    srs.g = srs_points[1..].to_vec();

    let basis: Vec<PolyComm<Vesta>> = basis_points
        .iter()
        .map(|v| PolyComm { chunks: vec![*v] })
        .collect();

    (srs, basis)
}

/// Read one `[len: u64][PodVesta * len]` section. Returns the point slice
/// (zero-copy view) and the remaining bytes after the section.
fn read_section(bytes: &[u8]) -> (&[Vesta], &[u8]) {
    assert!(bytes.len() >= 8, "blob too short for section header");
    let (header, rest) = bytes.split_at(8);
    let len = u64::from_le_bytes(header.try_into().unwrap()) as usize;

    let byte_len = len
        .checked_mul(size_of::<PodVesta>())
        .expect("section len overflow");
    assert!(rest.len() >= byte_len, "blob truncated mid-section");

    let (section, tail) = rest.split_at(byte_len);
    let pods: &[PodVesta] = bytemuck::cast_slice(section);
    // SAFETY: PodVesta and Vesta have identical layout for the pinned arkworks
    // versions; verified by the tests in tests/srs_layout.rs.
    let vestas: &[Vesta] =
        unsafe { core::slice::from_raw_parts(pods.as_ptr() as *const Vesta, pods.len()) };
    (vestas, tail)
}
