//! Backend proof materialization for the new Pickles path.
//!
//! This is the `mina-rust`-aligned replacement for the legacy custom
//! `prev_challenges` reconstruction. At the current exporter boundary we still
//! reuse the existing raw-wrap proof parser, but we rebuild the recursion
//! accumulator padding the way `mina-rust`'s `make_padded_proof_from_p2p`
//! does: prepend the fixed challenge-polynomial commitment padding point, then
//! pair it with the padded wrap challenge vectors.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use core::str::FromStr;

use ark_ff::PrimeField;
use kimchi::curve::KimchiCurve;
use kimchi::proof::RecursionChallenge;
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_poseidon::sponge::ScalarChallenge;
use poly_commitment::PolyComm;

use crate::pickles_error::PicklesError;
use crate::pickles_lowering::{lower_simple_chain_metadata, lower_simple_chain_raw_wrap_artifacts};
use crate::pickles_types::{
    BulletproofChallengeHex, CurvePointHex, PicklesVerifyRequest,
};
use crate::PallasProof;

/// Return the fixed dummy challenge-polynomial commitment that Pickles inserts
/// when the recursive proof carries fewer commitments than the wrap verifier
/// expects.
fn challenge_polynomial_commitment_padding() -> PolyComm<Pallas> {
    let x = Fp::from_str("8063668238751197448664615329057427953229339439010717262869116690340613895496")
        .expect("valid mina-rust padding x-coordinate");
    let y = Fp::from_str("2694491010813221541025626495812026140144933943906714931997499229912601205355")
        .expect("valid mina-rust padding y-coordinate");

    PolyComm::new(vec![Pallas::new_unchecked(x, y)])
}

/// Parse one exporter-side coordinate back into the `Fp` used by the wrap
/// proof's Pallas commitments.
fn parse_hex_field_fp(hex: &str) -> Result<Fp, PicklesError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fp::from(0u64));
    }
    let hex = if hex.len() % 2 == 0 {
        hex.to_owned()
    } else {
        format!("0{hex}")
    };
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PicklesError::InvalidFieldElement(format!("invalid fp hex field: 0x{hex}")))?;

    Ok(Fp::from_be_bytes_mod_order(&bytes))
}

/// Decode one exported wrap commitment into a Pallas affine point.
fn parse_curve_point_hex_pallas(point: &CurvePointHex) -> Result<Pallas, PicklesError> {
    let x = parse_hex_field_fp(&point.x)?;
    let y = parse_hex_field_fp(&point.y)?;
    Ok(Pallas::new_unchecked(x, y))
}

/// Convert one exported wrap bulletproof prechallenge into the field element
/// stored inside Kimchi's recursion accumulator.
///
/// This is the Pickles-side endomorphism conversion that turns compressed wrap
/// challenges into the backend values paired with challenge-polynomial
/// commitments in `prev_challenges`.
pub(crate) fn wrap_bulletproof_challenge_to_field(
    challenge: &BulletproofChallengeHex,
) -> Result<Fq, PicklesError> {
    let packed = challenge
        .prechallenge_inner
        .iter()
        .map(|limb| u64::from_str_radix(limb, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            PicklesError::InvalidJson("wrap bulletproof challenge uses non-hex limb".into())
        })?;

    let mut bytes = Vec::with_capacity(packed.len() * 8);
    for limb in packed {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }

    let challenge = Fq::from_le_bytes_mod_order(&bytes);
    let (_, endo) = Pallas::endos();
    Ok(ScalarChallenge::new(challenge).to_field(endo))
}

/// Materialize the verifier-ready wrap proof expected by Kimchi from the
/// exporter request.
///
/// The raw exported wrap proof is still missing one Pickles layer: the padded
/// recursion accumulator stored in `prev_challenges`. This function rebuilds
/// that accumulator in the same shape used by `mina-rust`, pairing each wrap
/// bulletproof challenge vector with the correct challenge-polynomial
/// commitment before the proof is handed to Kimchi.
pub fn make_padded_wrap_proof_from_request(
    request: &PicklesVerifyRequest,
) -> Result<PallasProof, PicklesError> {
    let metadata = lower_simple_chain_metadata(request)?;
    let mut lowered = lower_simple_chain_raw_wrap_artifacts(request)?;

    let challenge_sets = metadata
        .wrap_old_bulletproof_challenges
        .iter()
        .map(|group| {
            group
                .iter()
                .map(wrap_bulletproof_challenge_to_field)
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let expected_prev_challenges = lowered.verifier_index.prev_challenges;
    if challenge_sets.len() != expected_prev_challenges {
        return Err(PicklesError::InvalidJson(format!(
            "wrap_old_bulletproof_challenges length mismatch: expected {expected_prev_challenges}, got {}",
            challenge_sets.len()
        )));
    }

    let mut commitments = metadata
        .next_step_challenge_polynomial_commitments
        .iter()
        .map(parse_curve_point_hex_pallas)
        .map(|point| point.map(|point| PolyComm::new(vec![point])))
        .collect::<Result<Vec<_>, _>>()?;

    if commitments.len() > expected_prev_challenges {
        return Err(PicklesError::InvalidJson(format!(
            "next_step challenge commitments length mismatch: expected at most {expected_prev_challenges}, got {}",
            commitments.len()
        )));
    }

    while commitments.len() < expected_prev_challenges {
        commitments.insert(0, challenge_polynomial_commitment_padding());
    }

    lowered.proof.prev_challenges = challenge_sets
        .into_iter()
        .zip(commitments)
        .map(|(chals, comm)| RecursionChallenge::new(chals, comm))
        .collect();

    Ok(lowered.proof)
}
