//! Flat byte layout for an SRS<Vesta>, designed for zero-parse loading inside
//! the SP1 guest. The build host serializes via [`srs_to_pod_bytes`]; the guest
//! reads back via [`load_srs_from_pod_bytes`], which is a slice cast — no
//! deserialization.
//!
//! Blob layout:
//!
//! ```text
//! offset  field         bytes
//! 0       len: u64 LE   8
//! 8       points        72 * len   (h first, then g, repeated)
//! ```
//!
//! Soundness of the unsafe cast depends on [`PodVesta`] being bit-identical to
//! `Vesta` for the pinned arkworks versions. This is checked by the layout
//! tests in `tests/srs_layout.rs`.

use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::{Pod, Zeroable};
use mina_curves::pasta::Vesta;
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

/// Encode an SRS as `[len: u64 LE][PodVesta; len]`, with `h` as the first
/// point followed by `g`. Used by the build script.
pub fn srs_to_pod_bytes(srs: &SRS<Vesta>) -> Vec<u8> {
    let mut points: Vec<PodVesta> = Vec::with_capacity(1 + srs.g.len());
    points.push(vesta_to_pod(&srs.h));
    points.extend(srs.g.iter().map(vesta_to_pod));

    let len = points.len() as u64;
    let mut out = Vec::with_capacity(8 + points.len() * size_of::<PodVesta>());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytemuck::cast_slice(&points));
    out
}

/// Decode a pod blob back into an SRS via a slice cast (no parsing).
///
/// `bytes` must be 8-byte aligned. The guest achieves this by wrapping
/// `include_bytes!` in a `#[repr(C, align(8))]` struct.
pub fn load_srs_from_pod_bytes(bytes: &[u8]) -> SRS<Vesta> {
    assert!(bytes.len() >= 8, "srs blob too short for header");
    let (header, rest) = bytes.split_at(8);
    let len = u64::from_le_bytes(header.try_into().unwrap()) as usize;

    let byte_len = len
        .checked_mul(size_of::<PodVesta>())
        .expect("srs len overflow");
    assert!(rest.len() >= byte_len, "srs blob truncated");

    let pods: &[PodVesta] = bytemuck::cast_slice(&rest[..byte_len]);
    let points: &[Vesta] =
        unsafe { core::slice::from_raw_parts(pods.as_ptr() as *const Vesta, pods.len()) };

    assert!(points.len() >= 2, "SRS must have h + at least one g");
    let mut srs = SRS::<Vesta>::default();
    srs.h = points[0];
    srs.g = points[1..].to_vec();
    srs
}
