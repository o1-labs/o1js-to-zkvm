//! High-level lowering and verification entrypoints for the new Pickles path.
//!
//! The target end state mirrors the flow in
//! `mina-rust/crates/ledger/src/proofs/verification.rs`. At the current stage
//! this path already owns:
//! - `messages_for_next_wrap_proof` hashing
//! - `messages_for_next_step_proof` hashing
//! - prepared-statement packing
//! - padded wrap-proof materialization
//!
//! It still reuses the existing raw-wrap verifier-index parser while the VK
//! boundary remains exporter-driven.

extern crate alloc;

use alloc::vec::Vec;

use ark_ff::{BigInteger, PrimeField};
use kimchi::curve::KimchiCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use mina_poseidon::sponge::ScalarChallenge;
use rand::{CryptoRng, RngCore};

use crate::pickles_error::PicklesError;
use crate::pickles_lowering::{
    lower_simple_chain_metadata, lower_simple_chain_public_input_plan,
    lower_simple_chain_raw_wrap_artifacts,
};
use crate::pickles_mina_rust::app_state::FieldVectorAppState;
use crate::pickles_mina_rust::messages::{MessagesForNextStepProof, MessagesForNextWrapProof};
use crate::pickles_mina_rust::proof_padding::make_padded_wrap_proof_from_request;
use crate::pickles_mina_rust::types::{
    BranchData, DeferredValues, DlogPlonkVerificationKeyEvals, LoweredWrapVerification, Plonk,
    PreparedStatement, ProofState, ShiftedValue,
};
use crate::pickles_types::{
    BulletproofChallengeHex, CurvePointHex, PicklesVerifyRequest, SideLoadedProofMetadata,
};
use crate::verify_wrap_kimchi_proof;

fn field_to_hex<F: PrimeField>(field: F) -> String {
    let bytes = field.into_bigint().to_bytes_be();
    if bytes.is_empty() {
        "0x0".into()
    } else {
        let mut out = alloc::string::String::with_capacity(2 + bytes.len() * 2);
        out.push_str("0x");
        for byte in bytes {
            use alloc::fmt::Write as _;
            write!(&mut out, "{byte:02X}").expect("write to string");
        }
        out
    }
}

fn parse_hex_field_fp(hex: &str) -> Result<Fp, PicklesError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fp::from(0u64));
    }
    let hex = if hex.len() % 2 == 0 {
        hex.to_owned()
    } else {
        alloc::format!("0{hex}")
    };
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PicklesError::InvalidFieldElement(alloc::format!("invalid fp hex field: 0x{hex}")))?;

    Ok(Fp::from_be_bytes_mod_order(&bytes))
}

fn pack_hex64_limbs_to_field_fp(limbs: &[String]) -> Result<Fp, PicklesError> {
    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        let limb = u64::from_str_radix(limb, 16).map_err(|_| {
            PicklesError::InvalidFieldElement(format!("invalid hex64 limb in challenge: {limb}"))
        })?;
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    Ok(Fp::from_le_bytes_mod_order(&bytes))
}

fn step_bulletproof_challenge_to_field(challenge: &BulletproofChallengeHex) -> Result<Fp, PicklesError> {
    let packed = pack_hex64_limbs_to_field_fp(&challenge.prechallenge_inner)?;
    let (_, endo) = Vesta::endos();
    Ok(ScalarChallenge::new(packed).to_field(endo))
}

fn curve_point_hex_from_pallas(point: Pallas) -> CurvePointHex {
    CurvePointHex {
        x: field_to_hex(point.x),
        y: field_to_hex(point.y),
    }
}

fn build_dlog_plonk_index_evals(
    lowered: &crate::pickles_lowering::LoweredRawWrapArtifacts,
) -> DlogPlonkVerificationKeyEvals {
    DlogPlonkVerificationKeyEvals {
        sigma: core::array::from_fn(|i| curve_point_hex_from_pallas(lowered.verifier_index.sigma_comm[i].chunks[0])),
        coefficients: core::array::from_fn(|i| {
            curve_point_hex_from_pallas(lowered.verifier_index.coefficients_comm[i].chunks[0])
        }),
        generic: curve_point_hex_from_pallas(lowered.verifier_index.generic_comm.chunks[0]),
        psm: curve_point_hex_from_pallas(lowered.verifier_index.psm_comm.chunks[0]),
        complete_add: curve_point_hex_from_pallas(lowered.verifier_index.complete_add_comm.chunks[0]),
        mul: curve_point_hex_from_pallas(lowered.verifier_index.mul_comm.chunks[0]),
        emul: curve_point_hex_from_pallas(lowered.verifier_index.emul_comm.chunks[0]),
        endomul_scalar: curve_point_hex_from_pallas(lowered.verifier_index.endomul_scalar_comm.chunks[0]),
    }
}

fn build_wrap_message(metadata: &SideLoadedProofMetadata) -> Result<MessagesForNextWrapProof, PicklesError> {
    Ok(MessagesForNextWrapProof {
        challenge_polynomial_commitment: metadata.wrap_challenge_polynomial_commitment.clone(),
        old_bulletproof_challenges: metadata
            .wrap_old_bulletproof_challenges
            .iter()
            .map(|group| {
                let fields = group
                    .iter()
                    .map(crate::pickles_mina_rust::proof_padding::wrap_bulletproof_challenge_to_field)
                    .collect::<Result<Vec<_>, _>>()?;
                fields.try_into().map_err(|_| {
                    PicklesError::InvalidJson("expected 15 wrap bulletproof challenges".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn build_step_message(
    request: &PicklesVerifyRequest,
    metadata: &SideLoadedProofMetadata,
    lowered: &crate::pickles_lowering::LoweredRawWrapArtifacts,
) -> Result<MessagesForNextStepProof<FieldVectorAppState>, PicklesError> {
    Ok(MessagesForNextStepProof {
        app_state: FieldVectorAppState {
            fields: request.statement.to_fields(),
        },
        dlog_plonk_index: build_dlog_plonk_index_evals(lowered),
        challenge_polynomial_commitments: metadata.next_step_challenge_polynomial_commitments.clone(),
        old_bulletproof_challenges: metadata
            .next_step_old_bulletproof_challenges
            .iter()
            .map(|group| {
                let fields = group
                    .iter()
                    .map(step_bulletproof_challenge_to_field)
                    .collect::<Result<Vec<_>, _>>()?;
                fields.try_into().map_err(|_| {
                    PicklesError::InvalidJson("expected 16 step bulletproof challenges".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn build_prepared_statement(
    request: &PicklesVerifyRequest,
    metadata: &SideLoadedProofMetadata,
    lowered: &crate::pickles_lowering::LoweredRawWrapArtifacts,
) -> Result<PreparedStatement, PicklesError> {
    let plan = lower_simple_chain_public_input_plan(request)?;
    let oracle = request.exported_wrap_oracle_fields.as_ref().ok_or_else(|| {
        PicklesError::InvalidJson(
            "mina-rust-aligned lowering currently requires exported wrap oracle fields".into(),
        )
    })?;
    let wrap_message = build_wrap_message(metadata)?;
    let step_message = build_step_message(request, metadata, lowered)?;

    let field_to_u64x4_fp = |field: Fp| field.into_bigint().0;

    Ok(PreparedStatement {
        proof_state: ProofState {
            deferred_values: DeferredValues {
                plonk: Plonk {
                    alpha: hex64_limbs_to_u64_array::<2>(&metadata.plonk.alpha_inner)?,
                    beta: hex64_limbs_to_u64_array::<2>(&metadata.plonk.beta)?,
                    gamma: hex64_limbs_to_u64_array::<2>(&metadata.plonk.gamma)?,
                    zeta: hex64_limbs_to_u64_array::<2>(&metadata.plonk.zeta_inner)?,
                    zeta_to_srs_length: ShiftedValue::new(parse_hex_field_fp(
                        plan.fields[2].value_hex.as_deref().ok_or_else(|| {
                            PicklesError::InvalidJson("missing zeta_to_srs_length".into())
                        })?,
                    )?),
                    zeta_to_domain_size: ShiftedValue::new(parse_hex_field_fp(
                        plan.fields[3].value_hex.as_deref().ok_or_else(|| {
                            PicklesError::InvalidJson("missing zeta_to_domain_size".into())
                        })?,
                    )?),
                    perm: ShiftedValue::new(parse_hex_field_fp(
                        plan.fields[4].value_hex.as_deref().ok_or_else(|| {
                            PicklesError::InvalidJson("missing perm".into())
                        })?,
                    )?),
                    lookup: None,
                    feature_flags: metadata.plonk.feature_flags.clone(),
                },
                combined_inner_product: ShiftedValue::new(parse_hex_field_fp(
                    &oracle.combined_inner_product_field_hex,
                )?),
                b: ShiftedValue::new(parse_hex_field_fp(
                    plan.fields[1].value_hex.as_deref().ok_or_else(|| {
                        PicklesError::InvalidJson("missing b".into())
                    })?,
                )?),
                xi: {
                    let limbs = field_to_u64x4_fp(parse_hex_field_fp(
                        plan.fields[9].value_hex.as_deref().ok_or_else(|| {
                            PicklesError::InvalidJson("missing xi".into())
                        })?,
                    )?);
                    [limbs[0], limbs[1]]
                },
                bulletproof_challenges: plan.fields[13..29]
                    .iter()
                    .map(|field| {
                        parse_hex_field_fp(field.value_hex.as_deref().ok_or_else(|| {
                            PicklesError::InvalidJson(
                                "missing deferred bulletproof challenge".into(),
                            )
                        })?)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                branch_data: BranchData {
                    proofs_verified: metadata.proofs_verified,
                    domain_log2: metadata.domain_log2,
                },
            },
            sponge_digest_before_evaluations: hex64_limbs_to_u64_array::<4>(
                &metadata.sponge_digest_before_evaluations,
            )?,
            messages_for_next_wrap_proof: wrap_message.hash()?,
        },
        messages_for_next_step_proof: step_message.hash()?,
    })
}

fn hex64_limbs_to_u64_array<const N: usize>(limbs: &[String]) -> Result<[u64; N], PicklesError> {
    let parsed = limbs
        .iter()
        .map(|limb| {
            u64::from_str_radix(limb, 16).map_err(|_| {
                PicklesError::InvalidFieldElement(format!("invalid hex64 limb: {limb}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    parsed.try_into().map_err(|actual: Vec<u64>| {
        PicklesError::InvalidJson(format!(
            "expected {N} hex64 limbs, got {}",
            actual.len()
        ))
    })
}

/// Lower a request into the fully assembled wrap verifier input using the
/// `mina-rust`-aligned path as far as currently implemented.
pub fn lower_pickles_with_mina_rust_model(
    request: &PicklesVerifyRequest,
) -> Result<LoweredWrapVerification, PicklesError> {
    let metadata = lower_simple_chain_metadata(request)?;
    let lowered_raw = lower_simple_chain_raw_wrap_artifacts(request)?;
    let proof = make_padded_wrap_proof_from_request(request)?;
    let prepared = build_prepared_statement(request, &metadata, &lowered_raw)?;
    let public_input = prepared
        .to_public_input(lowered_raw.verifier_index.public)?
        .public_input;

    Ok(LoweredWrapVerification {
        verifier_index: lowered_raw.verifier_index,
        proof,
        public_input,
    })
}

/// High-level Pickles verification entrypoint aligned with `mina-rust`.
pub fn verify_pickles_with_mina_rust_model<R: RngCore + CryptoRng>(
    request: &PicklesVerifyRequest,
    rng: &mut R,
) -> Result<bool, PicklesError> {
    let lowered = lower_pickles_with_mina_rust_model(request)?;
    Ok(verify_wrap_kimchi_proof(
        &lowered.verifier_index,
        &lowered.proof,
        &lowered.public_input,
        rng,
    ))
}
