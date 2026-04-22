//! Next-step and next-wrap message shapes for the new Pickles path.
//!
//! These correspond to the concepts in
//! `mina-rust/crates/ledger/src/proofs/public_input/messages.rs`.

extern crate alloc;

use alloc::vec::Vec;

use ark_ff::PrimeField;
use mina_curves::pasta::{Fp, Fq};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::{fp_kimchi, fq_kimchi, FULL_ROUNDS};
use mina_poseidon::poseidon::{ArithmeticSponge, Sponge};

use crate::pickles_error::PicklesError;
use crate::pickles_mina_rust::app_state::AppState;
use crate::pickles_mina_rust::types::DlogPlonkVerificationKeyEvals;
use crate::pickles_types::CurvePointHex;

#[derive(Clone, Debug, PartialEq)]
pub struct MessagesForNextWrapProof {
    pub challenge_polynomial_commitment: CurvePointHex,
    pub old_bulletproof_challenges: Vec<[Fq; 15]>,
}

impl MessagesForNextWrapProof {
    /// Hash `messages_for_next_wrap_proof` into the 4-limb digest embedded in
    /// the Pickles prepared statement.
    ///
    /// This digest is one of the recursive artifacts that survives above
    /// Kimchi: the circuit checks only a compact message, and the external
    /// Pickles verifier must replay the same hash before wrap verification.
    pub fn hash(&self) -> Result<[u64; 4], PicklesError> {
        let field = poseidon_digest_fq(&self.to_fields()?)?;
        Ok(field.into_bigint().0)
    }

    /// Encode the wrap recursive message into the exact `Fq` absorption order
    /// used by Pickles.
    fn to_fields(&self) -> Result<Vec<Fq>, PicklesError> {
        const NFIELDS: usize = 32;

        let mut fields = Vec::with_capacity(NFIELDS);
        let padding = 2usize
            .checked_sub(self.old_bulletproof_challenges.len())
            .ok_or_else(|| {
                PicklesError::InvalidJson(
                    "old_bulletproof_challenges must be of length <= 2".into(),
                )
            })?;

        for _ in 0..padding {
            fields.extend_from_slice(&Self::dummy_padding());
        }

        for challenges in &self.old_bulletproof_challenges {
            fields.extend_from_slice(challenges);
        }

        let point = fq_curve_point_to_fields(&self.challenge_polynomial_commitment)?;
        fields.extend(point);

        if fields.len() != NFIELDS {
            return Err(PicklesError::InvalidJson(format!(
                "messages_for_next_wrap_proof encoded {} fields, expected {NFIELDS}",
                fields.len()
            )));
        }

        Ok(fields)
    }

    /// Return the hard-coded dummy bulletproof-challenge vector that Pickles
    /// prepends when fewer old challenges are present than the wrap verifier
    /// expects.
    fn dummy_padding() -> [Fq; 15] {
        let f = |s: &str| {
            s.parse::<Fq>()
                .expect("valid Mina wrap dummy padding constant")
        };

        [
            f("7048930911355605315581096707847688535149125545610393399193999502037687877674"),
            f("5945064094191074331354717685811267396540107129706976521474145740173204364019"),
            f("20315491820009986698838977727629973056499886675589920515484193128018854963801"),
            f("375929229548289966749422550601268097380795636681684498450629863247980915833"),
            f("19682218496321100578766622300447982536359891434050417209656101638029891689955"),
            f("516598185966802396400068849903674663130928531697254466925429658676832606723"),
            f("23729760760563685146228624125180554011222918208600079938584869191222807389336"),
            f("11155777282048225577422475738306432747575091690354122761439079853293714987855"),
            f("24977767586983413450834833875715786066408803952857478894197349635213480783870"),
            f("2813347787496113574506936084777563965225649411532015639663405402448028142689"),
            f("22626141769059119580550800305467929090916842064220293932303261732461616709448"),
            f("18748107085456859495495117012311103043200881556220793307463332157672741458218"),
            f("22196219950929618042921320796106738233125483954115679355597636800196070731081"),
            f("13054421325261400802177761929986025883530654947859503505174678618288142017333"),
            f("4799483385651443229337780097631636300491234601736019220096005875687579936102"),
        ]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MessagesForNextStepProof<A: AppState> {
    pub app_state: A,
    pub dlog_plonk_index: DlogPlonkVerificationKeyEvals,
    pub challenge_polynomial_commitments: Vec<CurvePointHex>,
    pub old_bulletproof_challenges: Vec<[Fp; 16]>,
}

impl<A: AppState> MessagesForNextStepProof<A> {
    /// Hash `messages_for_next_step_proof` into the 4-limb digest embedded in
    /// the Pickles prepared statement.
    ///
    /// This is the step-side recursive message that binds app state, the dlog
    /// Plonk index commitments, and the next-step challenge data.
    pub fn hash(&self) -> Result<[u64; 4], PicklesError> {
        let field = poseidon_digest_fp(&self.to_fields()?)?;
        Ok(field.into_bigint().0)
    }

    /// Encode the step recursive message into the exact `Fp` absorption order
    /// expected by Pickles.
    fn to_fields(&self) -> Result<Vec<Fp>, PicklesError> {
        let mut fields = Vec::with_capacity(93);

        for point in &self.dlog_plonk_index.sigma {
            fields.extend(fp_curve_point_to_fields(point)?);
        }
        for point in &self.dlog_plonk_index.coefficients {
            fields.extend(fp_curve_point_to_fields(point)?);
        }
        fields.extend(fp_curve_point_to_fields(&self.dlog_plonk_index.generic)?);
        fields.extend(fp_curve_point_to_fields(&self.dlog_plonk_index.psm)?);
        fields.extend(fp_curve_point_to_fields(&self.dlog_plonk_index.complete_add)?);
        fields.extend(fp_curve_point_to_fields(&self.dlog_plonk_index.mul)?);
        fields.extend(fp_curve_point_to_fields(&self.dlog_plonk_index.emul)?);
        fields.extend(fp_curve_point_to_fields(&self.dlog_plonk_index.endomul_scalar)?);

        fields.extend(self.app_state.to_field_elements()?);

        for (commitment, challenges) in self
            .challenge_polynomial_commitments
            .iter()
            .zip(&self.old_bulletproof_challenges)
        {
            fields.extend(fp_curve_point_to_fields(commitment)?);
            fields.extend_from_slice(challenges);
        }

        Ok(fields)
    }
}

/// Parse one exporter field atom into the Pasta `Fp` used by Pickles step
/// transcripts.
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

/// Parse one exporter field atom into the Pasta `Fq` used by Pickles wrap
/// transcripts.
fn parse_hex_field_fq(hex: &str) -> Result<Fq, PicklesError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fq::from(0u64));
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
        .map_err(|_| PicklesError::InvalidFieldElement(format!("invalid fq hex field: 0x{hex}")))?;

    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

/// Convert one exported affine commitment into the two `Fp` coordinates that
/// Pickles absorbs into the step-side Poseidon transcript.
fn fp_curve_point_to_fields(point: &CurvePointHex) -> Result<[Fp; 2], PicklesError> {
    Ok([parse_hex_field_fp(&point.x)?, parse_hex_field_fp(&point.y)?])
}

/// Convert one exported affine commitment into the two `Fq` coordinates that
/// Pickles absorbs into the wrap-side Poseidon transcript.
fn fq_curve_point_to_fields(point: &CurvePointHex) -> Result<[Fq; 2], PicklesError> {
    Ok([parse_hex_field_fq(&point.x)?, parse_hex_field_fq(&point.y)?])
}

/// Replay the Pickles step transcript hash over an `Fp` absorption sequence.
fn poseidon_digest_fp(fields: &[Fp]) -> Result<Fp, PicklesError> {
    let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fp_kimchi::static_params(),
    );
    sponge.absorb(fields);
    Ok(sponge.squeeze())
}

/// Replay the Pickles wrap transcript hash over an `Fq` absorption sequence.
fn poseidon_digest_fq(fields: &[Fq]) -> Result<Fq, PicklesError> {
    let mut sponge = ArithmeticSponge::<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fq_kimchi::static_params(),
    );
    sponge.absorb(fields);
    Ok(sponge.squeeze())
}
