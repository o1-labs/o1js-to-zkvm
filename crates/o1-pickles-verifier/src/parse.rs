//! Lower wire-format types (parsed from the OCaml-emitted JSON) into the
//! domain [`crate::statement::WrapStatement`] shape.
//!
//! Pure conversion layer — no file I/O, no JSON parsing. Callers in `std`
//! land deserialize the JSON into `wire::ProofReprWire` first, then feed its
//! `statement` field into [`parse_wrap_statement`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use ark_ec::short_weierstrass::Affine;
use ark_ff::PrimeField;
use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};

use crate::statement::{
    BranchData, BulletproofChallenge, Challenge, DeferredValues, Digest, FeatureFlags,
    MessagesForNextStepProof, MessagesForNextWrapProof, PlonkMinimal, ProofState, ProofsVerified,
    ScalarChallenge, WrapStatement,
};
use crate::wire::{
    BranchDataWire, BulletproofChallengeWire, CurvePointWire, DeferredValuesWire, FeatureFlagsWire,
    MessagesForNextStepProofWire, MessagesForNextWrapProofWire, PlonkMinimalWire, ProofStateWire,
    ProofsVerifiedTag, ScalarChallengeWire, StatementWire,
};

#[derive(Debug)]
pub enum ParseError {
    WrongLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    InvalidDecimalFp(String),
    InvalidHexField(String),
    InvalidCurvePoint(String),
    UnsupportedLookupFeature(&'static str),
}

/// Top-level entry.
pub fn parse_wrap_statement(w: StatementWire) -> Result<WrapStatement, ParseError> {
    Ok(WrapStatement {
        proof_state: parse_proof_state(w.proof_state)?,
        messages_for_next_step_proof: parse_messages_step(w.messages_for_next_step_proof)?,
    })
}

fn parse_proof_state(w: ProofStateWire) -> Result<ProofState, ParseError> {
    Ok(ProofState {
        deferred_values: parse_deferred_values(w.deferred_values)?,
        sponge_digest_before_evaluations: digest_from_wire(&w.sponge_digest_before_evaluations),
        messages_for_next_wrap_proof: parse_messages_wrap(w.messages_for_next_wrap_proof)?,
    })
}

fn parse_deferred_values(w: DeferredValuesWire) -> Result<DeferredValues, ParseError> {
    let bp = exact_length_array::<BulletproofChallenge, 16>(
        "deferred_values.bulletproof_challenges",
        w.bulletproof_challenges.into_iter().map(bp_from_wire),
    )?;
    Ok(DeferredValues {
        plonk: parse_plonk(w.plonk)?,
        bulletproof_challenges: bp,
        branch_data: parse_branch_data(w.branch_data),
    })
}

fn parse_plonk(w: PlonkMinimalWire) -> Result<PlonkMinimal, ParseError> {
    Ok(PlonkMinimal {
        alpha: scalar_challenge_from_wire(&w.alpha),
        beta: challenge_from_wire(&w.beta),
        gamma: challenge_from_wire(&w.gamma),
        zeta: scalar_challenge_from_wire(&w.zeta),
        joint_combiner: w.joint_combiner.as_ref().map(scalar_challenge_from_wire),
        feature_flags: feature_flags_from_wire(&w.feature_flags)?,
    })
}

fn parse_branch_data(w: BranchDataWire) -> BranchData {
    BranchData {
        proofs_verified: match w.proofs_verified {
            ProofsVerifiedTag::N0 => ProofsVerified::N0,
            ProofsVerifiedTag::N1 => ProofsVerified::N1,
            ProofsVerifiedTag::N2 => ProofsVerified::N2,
        },
        domain_log2: w.domain_log2,
    }
}

fn parse_messages_wrap(
    w: MessagesForNextWrapProofWire,
) -> Result<MessagesForNextWrapProof, ParseError> {
    let challenge_polynomial_commitment = parse_vesta_point(&w.challenge_polynomial_commitment)?;
    let old_bulletproof_challenges = w
        .old_bulletproof_challenges
        .into_iter()
        .map(|inner| {
            exact_length_array::<BulletproofChallenge, 15>(
                "messages_for_next_wrap_proof.old_bulletproof_challenges[i]",
                inner.into_iter().map(bp_from_wire),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MessagesForNextWrapProof {
        challenge_polynomial_commitment,
        old_bulletproof_challenges,
    })
}

fn parse_messages_step(
    w: MessagesForNextStepProofWire,
) -> Result<MessagesForNextStepProof, ParseError> {
    let app_state = w
        .app_state
        .iter()
        .map(|s| Fp::from_str(s).map_err(|_| ParseError::InvalidDecimalFp(s.clone())))
        .collect::<Result<Vec<_>, _>>()?;
    let challenge_polynomial_commitments = w
        .challenge_polynomial_commitments
        .iter()
        .map(parse_pallas_point)
        .collect::<Result<Vec<_>, _>>()?;
    let old_bulletproof_challenges = w
        .old_bulletproof_challenges
        .into_iter()
        .map(|inner| {
            exact_length_array::<BulletproofChallenge, 16>(
                "messages_for_next_step_proof.old_bulletproof_challenges[i]",
                inner.into_iter().map(bp_from_wire),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MessagesForNextStepProof {
        app_state,
        challenge_polynomial_commitments,
        old_bulletproof_challenges,
    })
}

// --- leaf helpers ---

fn challenge_from_wire(limbs: &[i64; 2]) -> Challenge {
    Challenge([limbs[0] as u64, limbs[1] as u64])
}

fn digest_from_wire(limbs: &[i64; 4]) -> Digest {
    Digest([
        limbs[0] as u64,
        limbs[1] as u64,
        limbs[2] as u64,
        limbs[3] as u64,
    ])
}

fn scalar_challenge_from_wire(w: &ScalarChallengeWire) -> ScalarChallenge {
    ScalarChallenge {
        inner: challenge_from_wire(&w.inner),
    }
}

fn bp_from_wire(w: BulletproofChallengeWire) -> BulletproofChallenge {
    BulletproofChallenge {
        prechallenge: scalar_challenge_from_wire(&w.prechallenge),
    }
}

fn feature_flags_from_wire(w: &FeatureFlagsWire) -> Result<FeatureFlags, ParseError> {
    // The OCaml `Features.V1.t` collapses kimchi's granular `LookupPatterns`
    // into a single `lookup` bit. We don't have enough signal to reconstruct
    // which specific patterns were active, so for now we only accept the
    // "lookups disabled" case and reject anything that would require a
    // non-trivial mapping.
    if w.lookup || w.runtime_tables {
        return Err(ParseError::UnsupportedLookupFeature(
            "OCaml feature_flags with lookup/runtime_tables enabled lack the \
             granularity to populate kimchi's LookupPatterns; handle when a \
             lookup-using circuit is added",
        ));
    }
    Ok(FeatureFlags {
        range_check0: w.range_check0,
        range_check1: w.range_check1,
        foreign_field_add: w.foreign_field_add,
        foreign_field_mul: w.foreign_field_mul,
        xor: w.xor,
        rot: w.rot,
        lookup_features: LookupFeatures {
            patterns: LookupPatterns {
                xor: false,
                lookup: false,
                range_check: false,
                foreign_field_mul: false,
            },
            joint_lookup_used: false,
            uses_runtime_tables: false,
        },
    })
}

fn parse_hex_field<F: PrimeField>(s: &str) -> Result<F, ParseError> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    // Pad to even length just in case.
    let padded: String = if hex.len() % 2 == 1 {
        let mut t = String::with_capacity(hex.len() + 1);
        t.push('0');
        t.push_str(hex);
        t
    } else {
        hex.to_string()
    };
    let bytes: Result<Vec<u8>, _> = (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16))
        .collect();
    let bytes = bytes.map_err(|_| ParseError::InvalidHexField(s.to_string()))?;
    Ok(F::from_be_bytes_mod_order(&bytes))
}

fn parse_vesta_point(pair: &CurvePointWire) -> Result<Vesta, ParseError> {
    let x = parse_hex_field::<Fq>(&pair[0])?;
    let y = parse_hex_field::<Fq>(&pair[1])?;
    Ok(Affine::<VestaParameters>::new_unchecked(x, y))
}

fn parse_pallas_point(pair: &CurvePointWire) -> Result<Pallas, ParseError> {
    let x = parse_hex_field::<Fp>(&pair[0])?;
    let y = parse_hex_field::<Fp>(&pair[1])?;
    Ok(Affine::<PallasParameters>::new_unchecked(x, y))
}

fn exact_length_array<T, const N: usize>(
    field: &'static str,
    iter: impl Iterator<Item = T>,
) -> Result<[T; N], ParseError> {
    let v: Vec<T> = iter.collect();
    let got = v.len();
    <[T; N]>::try_from(v).map_err(|_| ParseError::WrongLength {
        field,
        expected: N,
        got,
    })
}
