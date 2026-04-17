//! Lowering and inspection logic for Mina side-loaded Pickles proofs.
//!
//! This module currently does three distinct jobs:
//! - parse structured metadata from the Mina side-loaded proof text
//! - expose the current missing lowering boundary explicitly
//! - derive a partial wrap public-input plan from the decoded metadata
//!
//! It does not yet construct the final recursion accumulators needed to turn
//! Mina's exported wrap proof view into a fully verification-ready Kimchi proof.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
#[cfg(feature = "std")]
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
#[cfg(feature = "std")]
use blake2::{Blake2b512, Digest};
use groupmap::GroupMap;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::curve::KimchiCurve;
#[cfg(feature = "std")]
use kimchi::linearization::expr_linearization;
use kimchi::plonk_sponge::FrSponge;
#[cfg(feature = "std")]
use kimchi::proof::{PointEvaluations, ProofEvaluations, ProverCommitments, RecursionChallenge};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::{fp_kimchi, fq_kimchi, FULL_ROUNDS};
use mina_poseidon::poseidon::{ArithmeticSponge, Sponge};
use mina_poseidon::sponge::ScalarChallenge;
#[cfg(feature = "std")]
use poly_commitment::commitment::PolyComm;
#[cfg(feature = "std")]
use poly_commitment::commitment::b_poly_coefficients;
use poly_commitment::commitment::CommitmentCurve;
#[cfg(feature = "std")]
use poly_commitment::ipa::OpeningProof;
use poly_commitment::ipa::SRS;
#[cfg(feature = "std")]
use serde::Deserialize;

use crate::pickles_error::PicklesError;
use crate::pickles_types::{
    BulletproofChallengeHex, CurvePointHex, CurvePointPairHex, ExportedRecursionChallenge,
    FieldEvalPairHex, NamedFieldEvalSectionHex, NamedPointSectionHex, NamedSectionCount,
    PicklesVerifyRequest, PlonkDeferredValuesHex, PlonkFeatureFlags, SideLoadedProofMetadata,
    WrapBulletproofHex, WrapProofBodyHex, WrapProofCommitmentsHex, WrapPublicInputFieldPlan,
    WrapPublicInputPlan,
};
use crate::{PallasProof, PallasVerifierIndex, ScalarSponge};

pub struct LoweredWrapInstance {
    pub verifier_index: PallasVerifierIndex,
    pub proof: PallasProof,
    pub public_input: Vec<Fq>,
}

pub struct LoweredRawWrapArtifacts {
    pub verifier_index: PallasVerifierIndex,
    pub proof: PallasProof,
    pub public_input: Vec<Fq>,
}

/// Future lowering entry point from Mina side-loaded artifacts into raw Kimchi inputs.
///
/// The final goal of this function is to bridge:
/// `PicklesVerifyRequest -> (VerifierIndex, ProverProof, public_input)`.
pub fn lower_simple_chain_request(
    request: &PicklesVerifyRequest,
) -> Result<LoweredWrapInstance, PicklesError> {
    #[cfg(feature = "std")]
    {
        let lowered = lower_simple_chain_raw_wrap_artifacts(request)?;
        return Ok(LoweredWrapInstance {
            verifier_index: lowered.verifier_index,
            proof: lowered.proof,
            public_input: lowered.public_input,
        });
    }

    #[allow(unreachable_code)]
    Err(PicklesError::LoweringNotImplemented(
        "Pickles verification from Mina-exported raw wrap artifacts requires the std-gated lowering path",
    ))
}

#[cfg(feature = "std")]
/// Decode the structured proof metadata Rust can currently extract from a real
/// Mina-exported `Simple_chain` side-loaded proof.
pub fn lower_simple_chain_metadata(
    request: &PicklesVerifyRequest,
) -> Result<SideLoadedProofMetadata, PicklesError> {
    decode_side_loaded_proof_metadata(&request.proof.0)
}

#[cfg(feature = "std")]
/// Build an ordered plan for the wrap public-input vector.
///
/// This is a planning artifact: it marks which slots are already derivable from
/// the exported proof and which still require additional Mina/Kimchi preprocessing.
pub fn lower_simple_chain_public_input_plan(
    request: &PicklesVerifyRequest,
) -> Result<WrapPublicInputPlan, PicklesError> {
    let metadata = lower_simple_chain_metadata(request)?;
    build_wrap_public_input_plan(request, &metadata)
}

#[cfg(feature = "std")]
/// Deserialize the raw wrap verifier/proof JSON artifacts exported by Mina into
/// the Rust Kimchi types already used by the low-level verifier.
///
/// This lowers the raw wrap verifier and proof JSON into the Rust Kimchi types
/// already used by the low-level verifier. The final high-level lowering path
/// still has to attach the real wrap SRS before verification.
pub fn lower_simple_chain_raw_wrap_artifacts(
    request: &PicklesVerifyRequest,
) -> Result<LoweredRawWrapArtifacts, PicklesError> {
    let raw_wrap_verifier = request.exported_raw_wrap_verifier.as_ref().ok_or_else(|| {
        PicklesError::InvalidJson("missing raw_wrap_verification_key_json".into())
    })?;
    let raw_wrap_proof = request
        .exported_raw_wrap_proof
        .as_ref()
        .ok_or_else(|| PicklesError::InvalidJson("missing raw_wrap_proof_json".into()))?;
    let public_input = request
        .exported_wrap_public_input
        .as_ref()
        .ok_or_else(|| PicklesError::InvalidJson("missing wrap_public_input_fields".into()))?
        .fields
        .clone();

    let metadata = lower_simple_chain_metadata(request)?;
    let mut verifier_index = parse_raw_wrap_verifier_index(&raw_wrap_verifier.verifier_index_json)?;
    let srs = reconstruct_wrap_srs(verifier_index.max_poly_size)?;
    let proof = parse_raw_wrap_proof(
        &raw_wrap_proof.proof_json,
        &metadata,
        request.exported_backend_prev_challenges.as_deref(),
        &srs,
        verifier_index.prev_challenges,
    )?;
    verifier_index.srs = alloc::sync::Arc::new(srs);

    Ok(LoweredRawWrapArtifacts {
        verifier_index,
        proof,
        public_input,
    })
}

#[cfg(feature = "std")]
fn reconstruct_wrap_srs(max_poly_size: usize) -> Result<SRS<Pallas>, PicklesError> {
    if max_poly_size == 0 {
        return Err(PicklesError::InvalidJson(
            "raw wrap verifier index has max_poly_size = 0".into(),
        ));
    }

    let map = <Pallas as CommitmentCurve>::Map::setup();
    let g = (0..max_poly_size)
        .map(|i| {
            let mut h = Blake2b512::new();
            #[allow(clippy::cast_possible_truncation)]
            h.update((i as u32).to_be_bytes());
            point_of_random_bytes_pallas(&map, &h.finalize())
        })
        .collect();

    let h = {
        let mut digest = Blake2b512::new();
        digest.update(b"srs_misc");
        digest.update(0_u32.to_be_bytes());
        point_of_random_bytes_pallas(&map, &digest.finalize())
    };

    let mut srs = SRS::<Pallas>::default();
    srs.g = g;
    srs.h = h;
    Ok(srs)
}

#[cfg(feature = "std")]
fn point_of_random_bytes_pallas(
    map: &<Pallas as CommitmentCurve>::Map,
    random_bytes: &[u8],
) -> Pallas {
    const N: usize = 31;
    let extension_degree = <Fp as Field>::extension_degree() as usize;
    let mut base_fields = Vec::with_capacity(N * extension_degree);

    for base_count in 0..extension_degree {
        let mut bits = [false; 8 * N];
        let offset = base_count * N;
        for i in 0..N {
            for j in 0..8 {
                bits[8 * i + j] = (random_bytes[offset + i] >> j) & 1 == 1;
            }
        }

        let n = <<Fp as Field>::BasePrimeField as PrimeField>::BigInt::from_bits_be(&bits);
        let t = <<Fp as Field>::BasePrimeField as PrimeField>::from_bigint(n)
            .expect("packing code has a bug");
        base_fields.push(t);
    }

    let t = Fp::from_base_prime_field_elems(base_fields)
        .expect("invalid extension-field packing for SRS generation");
    let (x, y) = map.to_group(t);
    Pallas::of_coordinates(x, y).mul_by_cofactor()
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapVerifierIndexJson {
    domain: RawWrapDomainJson,
    max_poly_size: usize,
    public: usize,
    prev_challenges: usize,
    evals: RawWrapVerificationEvalsJson,
    shifts: Vec<String>,
    lookup_index: Option<serde_json::Value>,
    zk_rows: u64,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapDomainJson {
    log_size_of_group: usize,
    group_gen: String,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapVerificationEvalsJson {
    sigma_comm: Vec<RawWrapPolyCommJson>,
    coefficients_comm: Vec<RawWrapPolyCommJson>,
    generic_comm: RawWrapPolyCommJson,
    psm_comm: RawWrapPolyCommJson,
    complete_add_comm: RawWrapPolyCommJson,
    mul_comm: RawWrapPolyCommJson,
    emul_comm: RawWrapPolyCommJson,
    endomul_scalar_comm: RawWrapPolyCommJson,
    xor_comm: Option<RawWrapPolyCommJson>,
    range_check0_comm: Option<RawWrapPolyCommJson>,
    range_check1_comm: Option<RawWrapPolyCommJson>,
    foreign_field_add_comm: Option<RawWrapPolyCommJson>,
    foreign_field_mul_comm: Option<RawWrapPolyCommJson>,
    rot_comm: Option<RawWrapPolyCommJson>,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapPolyCommJson {
    unshifted: Vec<RawWrapPointJson>,
    #[allow(dead_code)]
    shifted: Option<serde_json::Value>,
}

#[cfg(feature = "std")]
#[derive(Clone)]
struct RawWrapPointJson {
    x: String,
    y: String,
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for RawWrapPointJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Array(mut outer) if outer.len() == 2 => {
                let tag = outer.remove(0);
                let payload = outer.remove(0);
                if tag != serde_json::Value::String("Finite".into()) {
                    return Err(serde::de::Error::custom(
                        "expected Finite point in raw wrap poly commitment",
                    ));
                }
                match payload {
                    serde_json::Value::Array(coords) if coords.len() == 2 => {
                        let x = coords[0]
                            .as_str()
                            .ok_or_else(|| serde::de::Error::custom("invalid x coordinate"))?
                            .to_string();
                        let y = coords[1]
                            .as_str()
                            .ok_or_else(|| serde::de::Error::custom("invalid y coordinate"))?
                            .to_string();
                        Ok(Self { x, y })
                    }
                    _ => Err(serde::de::Error::custom(
                        "expected [x, y] payload for Finite point",
                    )),
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected [\"Finite\", [x, y]] raw point encoding",
            )),
        }
    }
}

#[cfg(feature = "std")]
fn parse_raw_wrap_verifier_index(json: &str) -> Result<PallasVerifierIndex, PicklesError> {
    let raw: RawWrapVerifierIndexJson = serde_json::from_str(json)
        .map_err(|err| PicklesError::InvalidJson(format!("raw wrap verifier index: {err}")))?;

    if raw.lookup_index.is_some() {
        return Err(PicklesError::LoweringNotImplemented(
            "lookup-enabled raw wrap verifier indexes are not supported yet",
        ));
    }

    let parsed_group_gen = parse_hex_field_fq(&raw.domain.group_gen)?;
    let size = 1u64 << raw.domain.log_size_of_group;
    let size_as_field_element = Fq::from(size);
    let size_inv = size_as_field_element.inverse().ok_or_else(|| {
        PicklesError::InvalidJson("raw wrap domain size is not invertible".into())
    })?;
    let group_gen_inv = parsed_group_gen.inverse().ok_or_else(|| {
        PicklesError::InvalidJson("raw wrap domain group_gen is not invertible".into())
    })?;
    let domain = ark_poly::domain::Radix2EvaluationDomain::<Fq> {
        size,
        log_size_of_group: raw.domain.log_size_of_group as u32,
        size_as_field_element,
        size_inv,
        group_gen: parsed_group_gen,
        group_gen_inv,
        offset: Fq::from(1u64),
        offset_inv: Fq::from(1u64),
        offset_pow_size: Fq::from(1u64),
    };

    let sigma_comm = raw
        .evals
        .sigma_comm
        .into_iter()
        .map(parse_raw_wrap_poly_comm)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| PicklesError::InvalidJson("raw wrap sigma_comm length mismatch".into()))?;
    let coefficients_comm = raw
        .evals
        .coefficients_comm
        .into_iter()
        .map(parse_raw_wrap_poly_comm)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| {
            PicklesError::InvalidJson("raw wrap coefficients_comm length mismatch".into())
        })?;
    let shift = raw
        .shifts
        .iter()
        .map(|field| parse_hex_field_fq(field))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| PicklesError::InvalidJson("raw wrap shifts length mismatch".into()))?;

    let range_check0_comm = raw
        .evals
        .range_check0_comm
        .map(parse_raw_wrap_poly_comm)
        .transpose()?;
    let range_check1_comm = raw
        .evals
        .range_check1_comm
        .map(parse_raw_wrap_poly_comm)
        .transpose()?;
    let foreign_field_add_comm = raw
        .evals
        .foreign_field_add_comm
        .map(parse_raw_wrap_poly_comm)
        .transpose()?;
    let foreign_field_mul_comm = raw
        .evals
        .foreign_field_mul_comm
        .map(parse_raw_wrap_poly_comm)
        .transpose()?;
    let xor_comm = raw
        .evals
        .xor_comm
        .map(parse_raw_wrap_poly_comm)
        .transpose()?;
    let rot_comm = raw
        .evals
        .rot_comm
        .map(parse_raw_wrap_poly_comm)
        .transpose()?;

    let feature_flags = kimchi::circuits::constraints::FeatureFlags {
        range_check0: range_check0_comm.is_some(),
        range_check1: range_check1_comm.is_some(),
        foreign_field_add: foreign_field_add_comm.is_some(),
        foreign_field_mul: foreign_field_mul_comm.is_some(),
        xor: xor_comm.is_some(),
        rot: rot_comm.is_some(),
        lookup_features: Default::default(),
    };
    let (linearization, powers_of_alpha) = expr_linearization::<Fq>(Some(&feature_flags), true);
    let (_, endo) = Pallas::endos();

    Ok(PallasVerifierIndex {
        domain,
        max_poly_size: raw.max_poly_size,
        zk_rows: raw.zk_rows,
        srs: alloc::sync::Arc::new(Default::default()),
        public: raw.public,
        prev_challenges: raw.prev_challenges,
        sigma_comm,
        coefficients_comm,
        generic_comm: parse_raw_wrap_poly_comm(raw.evals.generic_comm)?,
        psm_comm: parse_raw_wrap_poly_comm(raw.evals.psm_comm)?,
        complete_add_comm: parse_raw_wrap_poly_comm(raw.evals.complete_add_comm)?,
        mul_comm: parse_raw_wrap_poly_comm(raw.evals.mul_comm)?,
        emul_comm: parse_raw_wrap_poly_comm(raw.evals.emul_comm)?,
        endomul_scalar_comm: parse_raw_wrap_poly_comm(raw.evals.endomul_scalar_comm)?,
        range_check0_comm,
        range_check1_comm,
        foreign_field_add_comm,
        foreign_field_mul_comm,
        xor_comm,
        rot_comm,
        shift,
        permutation_vanishing_polynomial_m: Default::default(),
        w: Default::default(),
        endo: *endo,
        lookup_index: None,
        linearization,
        powers_of_alpha,
    })
}

#[cfg(feature = "std")]
fn parse_raw_wrap_poly_comm(raw: RawWrapPolyCommJson) -> Result<PolyComm<Pallas>, PicklesError> {
    Ok(PolyComm::new(
        raw.unshifted
            .into_iter()
            .map(parse_raw_wrap_point)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

#[cfg(feature = "std")]
fn parse_raw_wrap_point(raw: RawWrapPointJson) -> Result<Pallas, PicklesError> {
    let x = parse_hex_field(&raw.x)?;
    let y = parse_hex_field(&raw.y)?;
    Ok(Pallas::new_unchecked(x, y))
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapProofJson {
    messages: RawWrapProofMessagesJson,
    openings: RawWrapProofOpeningsJson,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapProofMessagesJson {
    w_comm: Vec<RawProofPolyCommJson>,
    z_comm: RawProofPolyCommJson,
    t_comm: RawProofPolyCommJson,
    #[allow(dead_code)]
    lookup: Option<serde_json::Value>,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawWrapProofOpeningsJson {
    proof: RawOpeningProofJson,
    evals: RawProofEvaluationsJson,
    ft_eval1: String,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawOpeningProofJson {
    lr: Vec<[RawProofPointJson; 2]>,
    z_1: String,
    z_2: String,
    delta: RawProofPointJson,
    challenge_polynomial_commitment: RawProofPointJson,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawProofEvaluationsJson {
    w: Vec<RawPointEvaluationsJson>,
    coefficients: Vec<RawPointEvaluationsJson>,
    z: RawPointEvaluationsJson,
    s: Vec<RawPointEvaluationsJson>,
    generic_selector: RawPointEvaluationsJson,
    poseidon_selector: RawPointEvaluationsJson,
    complete_add_selector: RawPointEvaluationsJson,
    mul_selector: RawPointEvaluationsJson,
    emul_selector: RawPointEvaluationsJson,
    endomul_scalar_selector: RawPointEvaluationsJson,
    range_check0_selector: Option<RawPointEvaluationsJson>,
    range_check1_selector: Option<RawPointEvaluationsJson>,
    foreign_field_add_selector: Option<RawPointEvaluationsJson>,
    foreign_field_mul_selector: Option<RawPointEvaluationsJson>,
    xor_selector: Option<RawPointEvaluationsJson>,
    rot_selector: Option<RawPointEvaluationsJson>,
    lookup_aggregation: Option<RawPointEvaluationsJson>,
    lookup_table: Option<RawPointEvaluationsJson>,
    lookup_sorted: Vec<Option<RawPointEvaluationsJson>>,
    runtime_lookup_table: Option<RawPointEvaluationsJson>,
    runtime_lookup_table_selector: Option<RawPointEvaluationsJson>,
    xor_lookup_selector: Option<RawPointEvaluationsJson>,
    lookup_gate_lookup_selector: Option<RawPointEvaluationsJson>,
    range_check_lookup_selector: Option<RawPointEvaluationsJson>,
    foreign_field_mul_lookup_selector: Option<RawPointEvaluationsJson>,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct RawProofPolyCommJson(Vec<RawProofPointJson>);

#[cfg(feature = "std")]
#[derive(Clone)]
struct RawProofPointJson {
    x: String,
    y: String,
}

#[cfg(feature = "std")]
struct RawPointEvaluationsJson {
    zeta: Vec<String>,
    zeta_omega: Vec<String>,
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for RawProofPointJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Array(coords) if coords.len() == 2 => {
                let x = coords[0]
                    .as_str()
                    .ok_or_else(|| serde::de::Error::custom("invalid x coordinate"))?
                    .to_string();
                let y = coords[1]
                    .as_str()
                    .ok_or_else(|| serde::de::Error::custom("invalid y coordinate"))?
                    .to_string();
                Ok(Self { x, y })
            }
            _ => Err(serde::de::Error::custom("expected [x, y] point encoding")),
        }
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for RawPointEvaluationsJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Array(items) if items.len() == 2 => {
                let zeta = items[0]
                    .as_array()
                    .ok_or_else(|| serde::de::Error::custom("invalid zeta evaluations"))?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| serde::de::Error::custom("invalid zeta field"))
                            .map(ToString::to_string)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let zeta_omega = items[1]
                    .as_array()
                    .ok_or_else(|| serde::de::Error::custom("invalid zeta_omega evaluations"))?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| serde::de::Error::custom("invalid zeta_omega field"))
                            .map(ToString::to_string)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self { zeta, zeta_omega })
            }
            _ => Err(serde::de::Error::custom(
                "expected [[zeta...], [zeta_omega...]] evaluation encoding",
            )),
        }
    }
}

#[cfg(feature = "std")]
fn parse_raw_wrap_proof(
    json: &str,
    metadata: &SideLoadedProofMetadata,
    exported_prev_challenges: Option<&[ExportedRecursionChallenge]>,
    srs: &SRS<Pallas>,
    expected_prev_challenges: usize,
) -> Result<PallasProof, PicklesError> {
    let raw: RawWrapProofJson = serde_json::from_str(json)
        .map_err(|err| PicklesError::InvalidJson(format!("raw wrap proof: {err}")))?;

    let w_comm = raw
        .messages
        .w_comm
        .into_iter()
        .map(parse_raw_proof_poly_comm)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| PicklesError::InvalidJson("raw wrap w_comm length mismatch".into()))?;
    let t_comm = parse_raw_proof_poly_comm(raw.messages.t_comm)?;
    let lookup_sorted: [Option<PointEvaluations<Vec<Fq>>>; 5] = raw
        .openings
        .evals
        .lookup_sorted
        .into_iter()
        .map(|item| item.map(parse_raw_point_evaluations).transpose())
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| PicklesError::InvalidJson("raw wrap lookup_sorted length mismatch".into()))?;

    Ok(PallasProof {
        commitments: ProverCommitments {
            w_comm,
            z_comm: parse_raw_proof_poly_comm(raw.messages.z_comm)?,
            t_comm,
            lookup: None,
        },
        proof: OpeningProof {
            lr: raw
                .openings
                .proof
                .lr
                .into_iter()
                .map(|[left, right]| {
                    Ok((parse_raw_proof_point(left)?, parse_raw_proof_point(right)?))
                })
                .collect::<Result<Vec<_>, PicklesError>>()?,
            delta: parse_raw_proof_point(raw.openings.proof.delta)?,
            z1: parse_hex_field_fq(&raw.openings.proof.z_1)?,
            z2: parse_hex_field_fq(&raw.openings.proof.z_2)?,
            sg: parse_raw_proof_point(raw.openings.proof.challenge_polynomial_commitment)?,
        },
        evals: ProofEvaluations {
            public: None,
            w: raw
                .openings
                .evals
                .w
                .into_iter()
                .map(parse_raw_point_evaluations)
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| {
                    PicklesError::InvalidJson("raw wrap evals.w length mismatch".into())
                })?,
            z: parse_raw_point_evaluations(raw.openings.evals.z)?,
            s: raw
                .openings
                .evals
                .s
                .into_iter()
                .map(parse_raw_point_evaluations)
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| {
                    PicklesError::InvalidJson("raw wrap evals.s length mismatch".into())
                })?,
            coefficients: raw
                .openings
                .evals
                .coefficients
                .into_iter()
                .map(parse_raw_point_evaluations)
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| {
                    PicklesError::InvalidJson("raw wrap evals.coefficients length mismatch".into())
                })?,
            generic_selector: parse_raw_point_evaluations(raw.openings.evals.generic_selector)?,
            poseidon_selector: parse_raw_point_evaluations(raw.openings.evals.poseidon_selector)?,
            complete_add_selector: parse_raw_point_evaluations(
                raw.openings.evals.complete_add_selector,
            )?,
            mul_selector: parse_raw_point_evaluations(raw.openings.evals.mul_selector)?,
            emul_selector: parse_raw_point_evaluations(raw.openings.evals.emul_selector)?,
            endomul_scalar_selector: parse_raw_point_evaluations(
                raw.openings.evals.endomul_scalar_selector,
            )?,
            range_check0_selector: raw
                .openings
                .evals
                .range_check0_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            range_check1_selector: raw
                .openings
                .evals
                .range_check1_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            foreign_field_add_selector: raw
                .openings
                .evals
                .foreign_field_add_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            foreign_field_mul_selector: raw
                .openings
                .evals
                .foreign_field_mul_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            xor_selector: raw
                .openings
                .evals
                .xor_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            rot_selector: raw
                .openings
                .evals
                .rot_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            lookup_aggregation: raw
                .openings
                .evals
                .lookup_aggregation
                .map(parse_raw_point_evaluations)
                .transpose()?,
            lookup_table: raw
                .openings
                .evals
                .lookup_table
                .map(parse_raw_point_evaluations)
                .transpose()?,
            lookup_sorted,
            runtime_lookup_table: raw
                .openings
                .evals
                .runtime_lookup_table
                .map(parse_raw_point_evaluations)
                .transpose()?,
            runtime_lookup_table_selector: raw
                .openings
                .evals
                .runtime_lookup_table_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            xor_lookup_selector: raw
                .openings
                .evals
                .xor_lookup_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            lookup_gate_lookup_selector: raw
                .openings
                .evals
                .lookup_gate_lookup_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            range_check_lookup_selector: raw
                .openings
                .evals
                .range_check_lookup_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
            foreign_field_mul_lookup_selector: raw
                .openings
                .evals
                .foreign_field_mul_lookup_selector
                .map(parse_raw_point_evaluations)
                .transpose()?,
        },
        ft_eval1: parse_hex_field_fq(&raw.openings.ft_eval1)?,
        prev_challenges: match exported_prev_challenges {
            Some(exported_prev_challenges) => {
                parse_exported_prev_challenges(exported_prev_challenges, expected_prev_challenges)?
            }
            None => materialize_wrap_prev_challenges(metadata, srs, expected_prev_challenges)?,
        },
    })
}

#[cfg(feature = "std")]
fn parse_raw_proof_poly_comm(raw: RawProofPolyCommJson) -> Result<PolyComm<Pallas>, PicklesError> {
    Ok(PolyComm::new(
        raw.0
            .into_iter()
            .map(parse_raw_proof_point)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

#[cfg(feature = "std")]
fn parse_raw_proof_point(raw: RawProofPointJson) -> Result<Pallas, PicklesError> {
    let x = parse_hex_field(&raw.x)?;
    let y = parse_hex_field(&raw.y)?;
    Ok(Pallas::new_unchecked(x, y))
}

#[cfg(feature = "std")]
fn parse_raw_point_evaluations(
    raw: RawPointEvaluationsJson,
) -> Result<PointEvaluations<Vec<Fq>>, PicklesError> {
    Ok(PointEvaluations {
        zeta: raw
            .zeta
            .iter()
            .map(|field| parse_hex_field_fq(field))
            .collect::<Result<Vec<_>, _>>()?,
        zeta_omega: raw
            .zeta_omega
            .iter()
            .map(|field| parse_hex_field_fq(field))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

#[cfg(feature = "std")]
fn materialize_wrap_prev_challenges(
    metadata: &SideLoadedProofMetadata,
    srs: &SRS<Pallas>,
    expected_prev_challenges: usize,
) -> Result<Vec<RecursionChallenge<Pallas>>, PicklesError> {
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

    if challenge_sets.len() != expected_prev_challenges {
        return Err(PicklesError::InvalidJson(format!(
            "wrap_old_bulletproof_challenges length mismatch: expected {expected_prev_challenges}, got {}",
            challenge_sets.len()
        )));
    }

    let dummy_comm = wrap_b_poly_commitment(srs, challenge_sets.first().ok_or_else(|| {
        PicklesError::InvalidJson("missing wrap_old_bulletproof_challenges".into())
    })?);

    let mut commitments = Vec::with_capacity(expected_prev_challenges);
    let actual_commitments = metadata
        .next_step_challenge_polynomial_commitments
        .iter()
        .map(parse_curve_point_hex_pallas)
        .collect::<Result<Vec<_>, _>>()?;

    if actual_commitments.len() > expected_prev_challenges {
        return Err(PicklesError::InvalidJson(format!(
            "next_step challenge commitments length mismatch: expected at most {expected_prev_challenges}, got {}",
            actual_commitments.len()
        )));
    }

    for _ in 0..(expected_prev_challenges - actual_commitments.len()) {
        commitments.push(dummy_comm.clone());
    }
    commitments.extend(
        actual_commitments
            .into_iter()
            .map(|point| PolyComm::new(vec![point])),
    );

    Ok(challenge_sets
        .into_iter()
        .zip(commitments)
        .map(|(chals, comm)| RecursionChallenge::new(chals, comm))
        .collect())
}

#[cfg(feature = "std")]
fn parse_exported_prev_challenges(
    exported_prev_challenges: &[ExportedRecursionChallenge],
    expected_prev_challenges: usize,
) -> Result<Vec<RecursionChallenge<Pallas>>, PicklesError> {
    if exported_prev_challenges.len() != expected_prev_challenges {
        return Err(PicklesError::InvalidJson(format!(
            "exported backend prev_challenges length mismatch: expected {expected_prev_challenges}, got {}",
            exported_prev_challenges.len()
        )));
    }

    exported_prev_challenges
        .iter()
        .map(|exported| {
            let chals = exported
                .chals_hex
                .iter()
                .map(|hex| parse_hex_field_fq(hex))
                .collect::<Result<Vec<_>, _>>()?;
            let comm = parse_poly_comm_hex_pallas(&exported.comm)?;
            Ok(RecursionChallenge::new(chals, comm))
        })
        .collect()
}

#[cfg(feature = "std")]
fn parse_curve_point_hex_pallas(point: &CurvePointHex) -> Result<Pallas, PicklesError> {
    let x = parse_hex_field(&point.x)?;
    let y = parse_hex_field(&point.y)?;
    Ok(Pallas::new_unchecked(x, y))
}

#[cfg(feature = "std")]
fn parse_poly_comm_hex_pallas(
    poly_comm: &crate::pickles_types::PolyCommHex,
) -> Result<PolyComm<Pallas>, PicklesError> {
    if poly_comm.shifted.is_some() {
        return Err(PicklesError::InvalidJson(
            "shifted backend prev_challenge commitments are not supported".into(),
        ));
    }

    Ok(PolyComm::new(
        poly_comm
            .unshifted
            .iter()
            .map(parse_curve_point_hex_pallas)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

#[cfg(feature = "std")]
fn wrap_b_poly_commitment(srs: &SRS<Pallas>, chals: &[Fq]) -> PolyComm<Pallas> {
    let coeffs = b_poly_coefficients(chals);
    let poly = DensePolynomial::from_coefficients_vec(coeffs);
    type PallasGroup = <Pallas as AffineRepr>::Group;

    let mut chunks = if poly.is_zero() {
        vec![PallasGroup::zero().into_affine()]
    } else {
        poly.coeffs
            .chunks(srs.g.len())
            .map(|chunk| {
                let coeffs = chunk.iter().map(|c| c.into_bigint()).collect::<Vec<_>>();
                PallasGroup::msm_bigint(&srs.g[..chunk.len()], &coeffs).into_affine()
            })
            .collect()
    };

    for _ in chunks.len()..1 {
        chunks.push(Pallas::zero());
    }

    PolyComm::new(chunks)
}

#[cfg(feature = "std")]
fn build_wrap_public_input_plan(
    request: &PicklesVerifyRequest,
    metadata: &SideLoadedProofMetadata,
) -> Result<WrapPublicInputPlan, PicklesError> {
    let derived = derive_wrap_deferred_inputs(metadata)?;
    let deferred_bulletproof_len = metadata.deferred_bulletproof_challenges.len();
    let mut fields = Vec::with_capacity(24 + deferred_bulletproof_len);

    if let Some(oracle) = &request.exported_wrap_oracle_fields {
        fields.push(known_field(
            0,
            "combined_inner_product",
            oracle.combined_inner_product_field_hex.clone(),
            "exact packed wrap public-input slot exported by Mina while Rust-side ft_eval0 / combined evaluation lowering is still incomplete",
        ));
    } else {
        fields.push(missing_field(
            0,
            "combined_inner_product",
            "current Rust derivation still disagrees with Mina's oracle; ft_eval0 / combined evaluation lowering is not trustworthy yet",
        ));
    }
    fields.push(known_field(
        1,
        "b",
        derived.b_hex.clone(),
        "new bulletproof challenge polynomial evaluated at zeta and zeta*omega with transcript-derived r",
    ));
    fields.push(known_field(
        2,
        "zeta_to_srs_length",
        derived.zeta_to_srs_length_hex.clone(),
        "scalar-challenge zeta raised to Mina's step SRS length (2^16)",
    ));
    fields.push(known_field(
        3,
        "zeta_to_domain_size",
        derived.zeta_to_domain_size_hex.clone(),
        "scalar-challenge zeta raised to the current step domain size",
    ));
    fields.push(known_field(
        4,
        "perm",
        derived.perm_hex.clone(),
        "permutation scalar from Mina Plonk_checks.Type1.derive_plonk for the no-lookup Simple_chain case",
    ));
    fields.push(known_field(
        5,
        "beta",
        pack_hex64_limbs_to_field_hex(&metadata.plonk.beta)?,
        "deferred_values.plonk.beta packed with Mina Challenge.typ",
    ));
    fields.push(known_field(
        6,
        "gamma",
        pack_hex64_limbs_to_field_hex(&metadata.plonk.gamma)?,
        "deferred_values.plonk.gamma packed with Mina Challenge.typ",
    ));
    fields.push(known_field(
        7,
        "alpha",
        pack_hex64_limbs_to_field_hex(&metadata.plonk.alpha_inner)?,
        "deferred_values.plonk.alpha packed with Mina Challenge.typ via scalar_challenge",
    ));
    fields.push(known_field(
        8,
        "zeta",
        pack_hex64_limbs_to_field_hex(&metadata.plonk.zeta_inner)?,
        "deferred_values.plonk.zeta packed with Mina Challenge.typ via scalar_challenge",
    ));
    fields.push(known_field(
        9,
        "xi",
        field_to_hex(derived.xi_packed),
        "challenge squeezed from the deferred wrap transcript and packed with Mina Challenge.typ",
    ));
    fields.push(known_field(
        10,
        "sponge_digest_before_evaluations",
        pack_hex64_limbs_to_field_hex(&metadata.sponge_digest_before_evaluations)?,
        "proof_state.sponge_digest_before_evaluations packed with Mina Digest.typ",
    ));
    fields.push(known_field(
        11,
        "messages_for_next_wrap_proof",
        derived.messages_for_next_wrap_proof_digest_hex.clone(),
        "Poseidon digest of the prepared next-wrap message payload",
    ));
    if let Some(oracle) = &request.exported_wrap_oracle_fields {
        fields.push(known_field(
            12,
            "messages_for_next_step_proof",
            oracle.messages_for_next_step_proof_field_hex.clone(),
            "exact packed wrap public-input slot exported by Mina while Rust-side next-step message hashing and VK lowering are incomplete",
        ));
    } else {
        fields.push(missing_field(
            12,
            "messages_for_next_step_proof",
            "requires Mina hash over prepared next-step messages including step verification-key commitments",
        ));
    }

    for (offset, challenge) in metadata.deferred_bulletproof_challenges.iter().enumerate() {
        fields.push(known_field(
            13 + offset,
            &format!("bulletproof_challenges[{offset}]"),
            pack_hex64_limbs_to_field_hex(&challenge.prechallenge_inner)?,
            "deferred_values.bulletproof_challenges packed with Mina Bulletproof_challenge.wrap_typ",
        ));
    }

    let branch_index = 13 + deferred_bulletproof_len;
    fields.push(known_field(
        branch_index,
        "branch_data",
        field_to_hex(pack_branch_data(
            metadata.proofs_verified,
            metadata.domain_log2,
        )?),
        "branch_data packed as 4 * domain_log2 + wrap prefix-mask(proofs_verified)",
    ));
    let feature_flag_start = branch_index + 1;
    for (offset, (name, enabled)) in wrap_feature_flag_slots(&metadata.plonk.feature_flags)
        .into_iter()
        .enumerate()
    {
        fields.push(known_field(
            feature_flag_start + offset,
            name,
            bool_to_field_hex(enabled),
            "feature flag slot from Wrap.Statement.In_circuit.spec",
        ));
    }
    let lookup_opt_start = feature_flag_start + 8;
    fields.push(known_field(
        lookup_opt_start,
        "joint_combiner.present",
        bool_to_field_hex(metadata.plonk.joint_combiner_inner.is_some()),
        "lookup opt flag from Wrap.Statement.In_circuit.spec",
    ));
    fields.push(known_field(
        lookup_opt_start + 1,
        "joint_combiner.value",
        pack_optional_joint_combiner(&metadata.plonk.joint_combiner_inner)?,
        "lookup opt payload uses a zero scalar challenge when lookups are disabled",
    ));

    Ok(WrapPublicInputPlan {
        total_fields: fields.len(),
        exact_public_input_available: fields.iter().all(|field| field.value_hex.is_some()),
        elided_constant_segments: Vec::new(),
        fields,
    })
}

#[cfg(feature = "std")]
struct DerivedWrapDeferredInputs {
    xi_packed: Fp,
    b_hex: String,
    perm_hex: String,
    zeta_to_domain_size_hex: String,
    zeta_to_srs_length_hex: String,
    messages_for_next_wrap_proof_digest_hex: String,
}

#[cfg(feature = "std")]
fn derive_wrap_deferred_inputs(
    metadata: &SideLoadedProofMetadata,
) -> Result<DerivedWrapDeferredInputs, PicklesError> {
    let (xi_challenge, r_challenge) = derive_transcript_challenges(metadata)?;
    let xi_packed = xi_challenge.inner();
    let r = r_challenge.to_field(vesta_scalar_endo());
    let b_hex = derive_b_value_hex(metadata, r)?;
    let zeta = scalar_challenge_field_from_limbs(&metadata.plonk.zeta_inner)?;
    let alpha = scalar_challenge_field_from_limbs(&metadata.plonk.alpha_inner)?;
    let beta = pack_hex64_limbs_to_field(&metadata.plonk.beta)?;
    let gamma = pack_hex64_limbs_to_field(&metadata.plonk.gamma)?;
    let domain = EvaluationDomains::<Fp>::create(1usize << usize::from(metadata.domain_log2))
        .map_err(|err| PicklesError::InvalidSexp(format!("invalid step domain: {err}")))?;

    Ok(DerivedWrapDeferredInputs {
        xi_packed,
        b_hex,
        perm_hex: derive_perm_hex(metadata, alpha, beta, gamma, zeta, domain.d1.group_gen)?,
        zeta_to_domain_size_hex: field_to_hex(type1_shifted_value_from_field(pow_2pow(
            zeta,
            u32::from(metadata.domain_log2),
        ))),
        zeta_to_srs_length_hex: field_to_hex(type1_shifted_value_from_field(pow_2pow(
            zeta,
            STEP_SRS_LOG2,
        ))),
        messages_for_next_wrap_proof_digest_hex: hash_messages_for_next_wrap_proof(metadata)?,
    })
}

#[cfg(feature = "std")]
fn derive_transcript_challenges(
    metadata: &SideLoadedProofMetadata,
) -> Result<(ScalarChallenge<Fp>, ScalarChallenge<Fp>), PicklesError> {
    let mut sponge: ScalarSponge = ScalarSponge::from(fp_kimchi::static_params());
    sponge.absorb(&pack_hex64_limbs_to_field(
        &metadata.sponge_digest_before_evaluations,
    )?);

    let old_bulletproof_digest =
        field_poseidon_digest(&flatten_old_step_bulletproof_challenges_for_digest(
            &metadata.next_step_old_bulletproof_challenges,
        )?)?;
    sponge.absorb(&old_bulletproof_digest);
    sponge.absorb(&parse_hex_field(&metadata.ft_eval1)?);

    for field in &metadata.prev_evals_public_input {
        sponge.absorb(&parse_hex_field(field)?);
    }

    // This intentionally uses Pickles statement-side deferred `prev_evals`, not
    // the raw wrap proof's backend `ProofEvaluations`.
    //
    // That matches Mina's verification flow and `mina-rust`'s
    // `compute_deferred_values`, which derive transcript/deferred scalars from
    // `proof.prev_evals`.
    for section in canonical_deferred_prev_eval_absorption_sections(metadata) {
        for evaluation in &section.evaluations {
            for field in &evaluation.zeta {
                sponge.absorb(&parse_hex_field(field)?);
            }
            for field in &evaluation.zeta_omega {
                sponge.absorb(&parse_hex_field(field)?);
            }
        }
    }

    let xi = sponge.challenge();
    let r = sponge.challenge();
    Ok((xi, r))
}

#[cfg(feature = "std")]
fn derive_b_value_hex(metadata: &SideLoadedProofMetadata, r: Fp) -> Result<String, PicklesError> {
    let zeta = scalar_challenge_field_from_limbs(&metadata.plonk.zeta_inner)?;
    let domain = EvaluationDomains::<Fp>::create(1usize << usize::from(metadata.domain_log2))
        .map_err(|err| PicklesError::InvalidSexp(format!("invalid step domain: {err}")))?;
    let zetaw = zeta * domain.d1.group_gen;
    let challenges = metadata
        .deferred_bulletproof_challenges
        .iter()
        .map(step_bulletproof_challenge_to_field)
        .collect::<Result<Vec<_>, _>>()?;
    let challenge_polynomial = |point: Fp| evaluate_challenge_polynomial(&challenges, point);
    let b_actual = challenge_polynomial(zeta) + (r * challenge_polynomial(zetaw));

    Ok(field_to_hex(type1_shifted_value_from_field(b_actual)))
}

#[cfg(feature = "std")]
const STEP_SRS_LOG2: u32 = 16;

#[cfg(feature = "std")]
const PERM_ALPHA0: usize = 21;

#[cfg(feature = "std")]
fn derive_perm_hex(
    metadata: &SideLoadedProofMetadata,
    alpha: Fp,
    beta: Fp,
    gamma: Fp,
    zeta: Fp,
    omega: Fp,
) -> Result<String, PicklesError> {
    let z_section = deferred_prev_eval_section(metadata, "z")?;
    let s_section = deferred_prev_eval_section(metadata, "s")?;
    let w_section = deferred_prev_eval_section(metadata, "w")?;
    let z_next = parse_hex_field(
        z_section
            .evaluations
            .first()
            .and_then(|pair| pair.zeta_omega.first())
            .ok_or_else(|| PicklesError::InvalidSexp("prev_evals.z missing zeta_omega".into()))?,
    )?;
    let witness_curr = w_section
        .evaluations
        .iter()
        .map(|pair| {
            parse_hex_field(pair.zeta.first().ok_or_else(|| {
                PicklesError::InvalidSexp("prev_evals.w entry missing zeta evaluation".into())
            })?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let sigma_curr = s_section
        .evaluations
        .iter()
        .map(|pair| {
            parse_hex_field(pair.zeta.first().ok_or_else(|| {
                PicklesError::InvalidSexp("prev_evals.s entry missing zeta evaluation".into())
            })?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let alpha_pow_perm = pow_field(alpha, PERM_ALPHA0);
    let zkp = zk_polynomial(zeta, omega);
    let init = (z_next * beta) * alpha_pow_perm * zkp;
    let product = sigma_curr
        .iter()
        .zip(witness_curr.iter())
        .fold(init, |acc, (s, w)| acc * (gamma + (beta * *s) + *w));

    Ok(field_to_hex(type1_shifted_value_from_field(-product)))
}

fn zk_polynomial(zeta: Fp, omega: Fp) -> Fp {
    let omega_inv = omega.inverse().expect("domain generator is non-zero");
    let omega_inv_sq = omega_inv.square();
    let omega_inv_cu = omega_inv_sq * omega_inv;
    (zeta - omega_inv) * (zeta - omega_inv_sq) * (zeta - omega_inv_cu)
}

#[cfg(feature = "std")]
fn deferred_prev_eval_section<'a>(
    metadata: &'a SideLoadedProofMetadata,
    name: &str,
) -> Result<&'a NamedFieldEvalSectionHex, PicklesError> {
    metadata
        .prev_evals
        .iter()
        .find(|section| section.name == name)
        .ok_or_else(|| PicklesError::InvalidSexp(format!("missing prev_evals section: {name}")))
}

#[cfg(feature = "std")]
fn pow_field(value: Fp, exponent: usize) -> Fp {
    let mut acc = Fp::from(1u64);
    for _ in 0..exponent {
        acc *= value;
    }
    acc
}

#[cfg(feature = "std")]
fn pow_2pow(mut value: Fp, squarings: u32) -> Fp {
    for _ in 0..squarings {
        value = value.square();
    }
    value
}

#[cfg(feature = "std")]
fn evaluate_challenge_polynomial(challenges: &[Fp], point: Fp) -> Fp {
    if challenges.is_empty() {
        return Fp::from(1u64);
    }

    let mut pow_two_pows = Vec::with_capacity(challenges.len());
    let mut acc = point;
    pow_two_pows.push(acc);
    for _ in 1..challenges.len() {
        acc = acc.square();
        pow_two_pows.push(acc);
    }

    challenges
        .iter()
        .enumerate()
        .fold(Fp::from(1u64), |product, (i, challenge)| {
            let power = pow_two_pows[challenges.len() - 1 - i];
            product * (Fp::from(1u64) + (*challenge * power))
        })
}

#[cfg(feature = "std")]
fn scalar_challenge_field_from_limbs(limbs: &[String]) -> Result<Fp, PicklesError> {
    let challenge = pack_hex64_limbs_to_field(limbs)?;
    Ok(ScalarChallenge::new(challenge).to_field(vesta_scalar_endo()))
}

#[cfg(feature = "std")]
fn type1_shifted_value_from_field(value: Fp) -> Fp {
    let shift = type1_shift_constant();
    let two_inverse = Fp::from(2u64)
        .inverse()
        .expect("two must be invertible in Pasta fields");
    (value - shift) * two_inverse
}

#[cfg(feature = "std")]
fn type1_shift_constant() -> Fp {
    let mut shift = Fp::from(1u64);
    for _ in 0..Fp::MODULUS_BIT_SIZE {
        shift += shift;
    }
    shift + Fp::from(1u64)
}

#[cfg(feature = "std")]
fn hash_messages_for_next_wrap_proof(
    metadata: &SideLoadedProofMetadata,
) -> Result<String, PicklesError> {
    let mut fields =
        flatten_wrap_bulletproof_challenges_for_digest(&metadata.wrap_old_bulletproof_challenges)?;
    fields.push(parse_hex_field_fq(
        &metadata.wrap_challenge_polynomial_commitment.x,
    )?);
    fields.push(parse_hex_field_fq(
        &metadata.wrap_challenge_polynomial_commitment.y,
    )?);
    Ok(field_to_hex_fq(field_poseidon_digest_fq(&fields)?))
}

#[cfg(feature = "std")]
fn flatten_wrap_bulletproof_challenges_for_digest(
    groups: &[Vec<BulletproofChallengeHex>],
) -> Result<Vec<Fq>, PicklesError> {
    let mut fields = Vec::new();
    for group in groups {
        for challenge in group {
            fields.push(wrap_bulletproof_challenge_to_field(challenge)?);
        }
    }
    Ok(fields)
}

#[cfg(feature = "std")]
fn flatten_old_step_bulletproof_challenges_for_digest(
    groups: &[Vec<BulletproofChallengeHex>],
) -> Result<Vec<Fp>, PicklesError> {
    let mut fields = Vec::new();
    for group in groups {
        for challenge in group {
            fields.push(step_bulletproof_challenge_to_field(challenge)?);
        }
    }
    Ok(fields)
}

#[cfg(feature = "std")]
fn wrap_bulletproof_challenge_to_field(
    challenge: &BulletproofChallengeHex,
) -> Result<Fq, PicklesError> {
    let challenge = pack_hex64_limbs_to_field_fq(&challenge.prechallenge_inner)?;
    Ok(ScalarChallenge::new(challenge).to_field(pallas_scalar_endo()))
}

#[cfg(feature = "std")]
fn step_bulletproof_challenge_to_field(
    challenge: &BulletproofChallengeHex,
) -> Result<Fp, PicklesError> {
    let challenge = pack_hex64_limbs_to_field(&challenge.prechallenge_inner)?;
    Ok(ScalarChallenge::new(challenge).to_field(vesta_scalar_endo()))
}

#[cfg(feature = "std")]
fn field_poseidon_digest(fields: &[Fp]) -> Result<Fp, PicklesError> {
    let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fp_kimchi::static_params(),
    );
    sponge.absorb(fields);
    Ok(sponge.squeeze())
}

#[cfg(feature = "std")]
fn field_poseidon_digest_fq(fields: &[Fq]) -> Result<Fq, PicklesError> {
    let mut sponge = ArithmeticSponge::<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fq_kimchi::static_params(),
    );
    sponge.absorb(fields);
    Ok(sponge.squeeze())
}

#[cfg(feature = "std")]
fn vesta_scalar_endo() -> &'static Fp {
    let (_, endo) = Vesta::endos();
    endo
}

#[cfg(feature = "std")]
fn pallas_scalar_endo() -> &'static Fq {
    let (_, endo) = Pallas::endos();
    endo
}

#[cfg(feature = "std")]
/// Return the deferred Pickles `prev_evals` sections in Mina's transcript
/// absorption order.
///
/// This helper is intentionally *not* based on the raw wrap proof's backend
/// `ProofEvaluations`. The backend opening evaluations differ from the deferred
/// `prev_evals` and are used for a different layer of verification.
fn canonical_deferred_prev_eval_absorption_sections<'a>(
    metadata: &'a SideLoadedProofMetadata,
) -> Vec<&'a NamedFieldEvalSectionHex> {
    const ABSORPTION_ORDER: &[&str] = &[
        "z",
        "generic_selector",
        "poseidon_selector",
        "complete_add_selector",
        "mul_selector",
        "emul_selector",
        "endomul_scalar_selector",
        "w",
        "coefficients",
        "s",
        "range_check0_selector",
        "range_check1_selector",
        "foreign_field_add_selector",
        "foreign_field_mul_selector",
        "xor_selector",
        "rot_selector",
        "lookup_aggregation",
        "lookup_table",
        "lookup_sorted",
        "runtime_lookup_table",
        "runtime_lookup_table_selector",
        "xor_lookup_selector",
        "lookup_gate_lookup_selector",
        "range_check_lookup_selector",
        "foreign_field_mul_lookup_selector",
    ];

    ABSORPTION_ORDER
        .iter()
        .filter_map(|name| {
            metadata
                .prev_evals
                .iter()
                .find(|section| section.name == *name && !section.evaluations.is_empty())
        })
        .collect()
}

#[cfg(feature = "std")]
fn decode_side_loaded_proof_metadata(
    proof_bytes: &[u8],
) -> Result<SideLoadedProofMetadata, PicklesError> {
    let proof_text = normalize_proof_text(
        core::str::from_utf8(proof_bytes).map_err(|_| PicklesError::InvalidProofText("proof"))?,
    );
    let sexp =
        sexp::parse(&proof_text).map_err(|err| PicklesError::InvalidSexp(err.to_string()))?;

    let top = list_items(&sexp)?;
    let (statement, proof_or_wrapper) = split_statement_and_proof(top)?;
    let proof_state = with_context("proof_state", group_entries(statement, "proof_state"))?;
    let deferred_values = with_context(
        "deferred_values",
        group_entries(proof_state, "deferred_values"),
    )?;
    let branch_data = with_context("branch_data", group_entries(deferred_values, "branch_data"))?;
    let plonk = with_context("plonk", group_entries(deferred_values, "plonk"))?;
    let wrap_messages = with_context(
        "messages_for_next_wrap_proof",
        group_entries(proof_state, "messages_for_next_wrap_proof"),
    )?;
    let next_step_messages = with_context(
        "messages_for_next_step_proof",
        group_entries(statement, "messages_for_next_step_proof")
            .or_else(|_| group_entries(proof_or_wrapper, "messages_for_next_step_proof")),
    )?;
    let prev_evals = with_context(
        "prev_evals",
        group_entries(statement, "prev_evals")
            .or_else(|_| group_entries(top, "prev_evals"))
            .or_else(|_| group_entries(proof_or_wrapper, "prev_evals")),
    )?;
    let prev_eval_wrapper = with_context("prev_evals.evals", group_entries(prev_evals, "evals"))?;
    let prev_eval_sections = with_context(
        "prev_evals.evals.evals",
        binding_payload_items(prev_eval_wrapper, "evals").and_then(normalize_section_entries),
    )?;
    let inner_proof = with_context("inner_proof", group_entries(proof_or_wrapper, "proof"))
        .unwrap_or(proof_or_wrapper);

    Ok(SideLoadedProofMetadata {
        proofs_verified: with_context(
            "branch_data.proofs_verified",
            parse_proofs_verified(atom(binding_one(branch_data, "proofs_verified")?)?),
        )?,
        domain_log2: with_context(
            "branch_data.domain_log2",
            parse_domain_log2(atom(binding_one(branch_data, "domain_log2")?)?),
        )?,
        plonk: with_context("plonk", parse_plonk(plonk))?,
        deferred_bulletproof_challenges: with_context(
            "deferred_values.bulletproof_challenges",
            parse_prechallenge_group(binding_rest(deferred_values, "bulletproof_challenges")?),
        )?,
        sponge_digest_before_evaluations: with_context(
            "proof_state.sponge_digest_before_evaluations",
            parse_atom_vector(binding_rest(
                proof_state,
                "sponge_digest_before_evaluations",
            )?),
        )?,
        wrap_challenge_polynomial_commitment: with_context(
            "messages_for_next_wrap_proof.challenge_polynomial_commitment",
            parse_point(binding_one(
                wrap_messages,
                "challenge_polynomial_commitment",
            )?),
        )?,
        wrap_old_bulletproof_challenges: with_context(
            "messages_for_next_wrap_proof.old_bulletproof_challenges",
            parse_prechallenge_groups(binding_rest(wrap_messages, "old_bulletproof_challenges")?),
        )?,
        next_step_challenge_polynomial_commitments: with_context(
            "messages_for_next_step_proof.challenge_polynomial_commitments",
            parse_point_vector(binding_rest(
                next_step_messages,
                "challenge_polynomial_commitments",
            )?),
        )?,
        next_step_old_bulletproof_challenges: with_context(
            "messages_for_next_step_proof.old_bulletproof_challenges",
            parse_prechallenge_groups(binding_rest(
                next_step_messages,
                "old_bulletproof_challenges",
            )?),
        )?,
        prev_evals_public_input: with_context(
            "prev_evals.evals.public_input",
            parse_atom_vector(binding_rest(prev_eval_wrapper, "public_input")?),
        )?,
        prev_evals: with_context(
            "prev_evals.evals.evals.detail",
            parse_named_field_eval_sections(prev_eval_sections),
        )?,
        prev_evals_sections: with_context(
            "prev_evals.evals.evals.counts",
            parse_named_section_counts(prev_eval_sections),
        )?,
        ft_eval1: with_context(
            "prev_evals.ft_eval1",
            atom_owned(binding_one(prev_evals, "ft_eval1")?),
        )?,
        inner_proof: with_context("inner_proof", parse_inner_proof(inner_proof))?,
    })
}

#[cfg(feature = "std")]
fn normalize_proof_text(proof_text: &str) -> String {
    let proof_text = proof_text.replace("domain_log2\"", "domain_log2 \"");
    let mut normalized = String::with_capacity(proof_text.len() + 64);
    let mut token = String::new();
    let mut in_string = false;

    fn flush_token(normalized: &mut String, token: &mut String) {
        if token.is_empty() {
            return;
        }

        let is_hex_body = token.chars().all(|ch| ch.is_ascii_hexdigit());
        let is_prefixed_hex = token.starts_with("0x")
            && token.len() > 2
            && token[2..].chars().all(|ch| ch.is_ascii_hexdigit());
        let should_quote = is_hex_body || is_prefixed_hex;

        if should_quote {
            normalized.push('"');
            normalized.push_str(token);
            normalized.push('"');
        } else {
            normalized.push_str(token);
        }

        token.clear();
    }

    for ch in proof_text.chars() {
        if in_string {
            normalized.push(ch);
            if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                flush_token(&mut normalized, &mut token);
                normalized.push(ch);
                in_string = true;
            }
            '(' | ')' => {
                flush_token(&mut normalized, &mut token);
                normalized.push(ch);
            }
            ch if ch.is_whitespace() => {
                flush_token(&mut normalized, &mut token);
                normalized.push(ch);
            }
            other => token.push(other),
        }
    }

    flush_token(&mut normalized, &mut token);
    normalized
}

#[cfg(feature = "std")]
fn peel_singletons<'a>(mut sexp: &'a sexp::Sexp) -> &'a sexp::Sexp {
    while let sexp::Sexp::List(items) = sexp {
        if items.len() != 1 {
            break;
        }
        sexp = &items[0];
    }
    sexp
}

#[cfg(feature = "std")]
fn list_items(sexp: &sexp::Sexp) -> Result<&[sexp::Sexp], PicklesError> {
    match peel_singletons(sexp) {
        sexp::Sexp::List(items) => Ok(items),
        _ => Err(PicklesError::InvalidSexp(
            "expected list at current node".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn normalize_section_entries(entries: &[sexp::Sexp]) -> Result<&[sexp::Sexp], PicklesError> {
    if entries.len() == 1 {
        match peel_singletons(&entries[0]) {
            sexp::Sexp::List(inner) => Ok(inner),
            _ => Ok(entries),
        }
    } else {
        Ok(entries)
    }
}

#[cfg(feature = "std")]
fn atom(sexp: &sexp::Sexp) -> Result<&str, PicklesError> {
    match peel_singletons(sexp) {
        sexp::Sexp::Atom(sexp::Atom::S(atom)) => Ok(atom.as_str()),
        sexp::Sexp::Atom(sexp::Atom::I(_)) => Err(PicklesError::InvalidSexp(
            "integer atoms are unsupported in side-loaded proofs".to_string(),
        )),
        sexp::Sexp::Atom(sexp::Atom::F(_)) => Err(PicklesError::InvalidSexp(
            "floating-point atoms are unsupported in side-loaded proofs".to_string(),
        )),
        _ => Err(PicklesError::InvalidSexp(
            "expected atom at current node".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn atom_owned(sexp: &sexp::Sexp) -> Result<String, PicklesError> {
    Ok(atom(sexp)?.to_string())
}

#[cfg(feature = "std")]
fn binding_rest<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a [sexp::Sexp], PicklesError> {
    if matches!(entries.first().map(atom), Some(Ok(found)) if found == key) {
        if entries.len() == 2 {
            return Ok(&entries[1..]);
        }
        let next_binding = entries
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(idx, entry)| is_binding_entry(entry).then_some(idx))
            .unwrap_or(entries.len());
        return Ok(&entries[1..next_binding]);
    }

    if entries.len() == 1 {
        if let Ok(inner) = list_items(&entries[0]) {
            if let Ok(rest) = binding_rest(inner, key) {
                return Ok(rest);
            }
        }
    }

    let entry = entries
        .iter()
        .find(|entry| match peel_singletons(entry) {
            sexp::Sexp::List(items) => {
                matches!(items.first(), Some(first) if atom(first).ok() == Some(key))
            }
            _ => false,
        })
        .ok_or_else(|| {
            PicklesError::InvalidSexp(format!(
                "missing proof field: {key}; available keys: {}",
                describe_entry_keys(entries)
            ))
        })?;

    let items = list_items(entry)?;
    Ok(&items[1..])
}

#[cfg(feature = "std")]
fn is_binding_entry(sexp: &sexp::Sexp) -> bool {
    match peel_singletons(sexp) {
        sexp::Sexp::List(items) => matches!(items.first().map(atom), Some(Ok(_))),
        sexp::Sexp::Atom(_) => false,
    }
}

#[cfg(feature = "std")]
fn binding_one<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a sexp::Sexp, PicklesError> {
    let rest = binding_rest(entries, key)?;
    if rest.len() != 1 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected exactly one payload item for {key}, got {}",
            rest.len()
        )));
    }
    Ok(&rest[0])
}

#[cfg(feature = "std")]
fn binding_optional_rest<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Option<&'a [sexp::Sexp]> {
    binding_rest(entries, key).ok()
}

#[cfg(feature = "std")]
fn binding_payload_items<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a [sexp::Sexp], PicklesError> {
    if let Some(entry) = entries.iter().find(|entry| match peel_singletons(entry) {
        sexp::Sexp::List(items) => {
            matches!(items.first(), Some(first) if atom(first).ok() == Some(key))
        }
        _ => false,
    }) {
        let items = list_items(entry)?;
        return Ok(&items[1..]);
    }

    Err(PicklesError::InvalidSexp(format!(
        "missing proof field: {key}; available keys: {}",
        describe_entry_keys(entries)
    )))
}

#[cfg(feature = "std")]
fn group_entries<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a [sexp::Sexp], PicklesError> {
    list_items(binding_one(entries, key)?)
}

#[cfg(feature = "std")]
fn split_statement_and_proof<'a>(
    top: &'a [sexp::Sexp],
) -> Result<(&'a [sexp::Sexp], &'a [sexp::Sexp]), PicklesError> {
    if matches!(top.first().map(atom), Some(Ok("statement"))) {
        let proof_index = top
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(idx, item)| {
                let items = list_items(item).ok()?;
                matches!(items.first().map(atom), Some(Ok("proof"))).then_some(idx)
            })
            .ok_or_else(|| {
                PicklesError::InvalidSexp(format!(
                    "flattened statement root is missing proof payload; available keys: {}",
                    describe_entry_keys(top)
                ))
            })?;

        return Ok((
            &top[1..proof_index],
            list_items(binding_one(&top[proof_index..=proof_index], "proof")?)?,
        ));
    }

    if binding_optional_rest(top, "statement").is_some() {
        return Ok((
            group_entries(top, "statement")?,
            group_entries(top, "proof")?,
        ));
    }

    Err(PicklesError::InvalidSexp(format!(
        "missing proof field: statement; available keys: {}",
        describe_entry_keys(top)
    )))
}

#[cfg(feature = "std")]
fn with_context<T>(
    label: &'static str,
    result: Result<T, PicklesError>,
) -> Result<T, PicklesError> {
    result.map_err(|err| match err {
        PicklesError::InvalidSexp(message) => {
            PicklesError::InvalidSexp(format!("{label}: {message}"))
        }
        PicklesError::MissingProofField(field) => {
            PicklesError::InvalidSexp(format!("{label}: missing proof field: {field}"))
        }
        other => other,
    })
}

#[cfg(feature = "std")]
fn describe_entry_keys(entries: &[sexp::Sexp]) -> String {
    let mut keys = Vec::new();
    for entry in entries {
        match peel_singletons(entry) {
            sexp::Sexp::List(items) => {
                if let Some(first) = items.first() {
                    if let Ok(name) = atom(first) {
                        keys.push(name.to_string());
                        continue;
                    }
                }
                keys.push("<list>".to_string());
            }
            sexp::Sexp::Atom(_) => keys.push("<atom>".to_string()),
        }
    }
    format!("[{}]", keys.join(", "))
}

#[cfg(feature = "std")]
fn parse_proofs_verified(value: &str) -> Result<u8, PicklesError> {
    match value {
        "N0" => Ok(0),
        "N1" => Ok(1),
        "N2" => Ok(2),
        other => Err(PicklesError::InvalidSexp(format!(
            "unsupported proofs_verified atom: {other}"
        ))),
    }
}

#[cfg(feature = "std")]
fn parse_domain_log2(value: &str) -> Result<u8, PicklesError> {
    let bytes = value.as_bytes();
    if bytes.len() == 1 {
        return Ok(bytes[0]);
    }

    if bytes.len() == 4 && bytes[0] == b'\\' && bytes[1..].iter().all(u8::is_ascii_digit) {
        let decimal = core::str::from_utf8(&bytes[1..]).map_err(|_| {
            PicklesError::InvalidSexp(format!("invalid domain_log2 escape: {value:?}"))
        })?;
        return decimal.parse::<u8>().map_err(|_| {
            PicklesError::InvalidSexp(format!("invalid domain_log2 escape: {value:?}"))
        });
    }

    Err(PicklesError::InvalidSexp(format!(
        "expected domain_log2 byte string, got {value:?}"
    )))
}

#[cfg(feature = "std")]
fn parse_atom_vector(items: &[sexp::Sexp]) -> Result<Vec<String>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(_) => list_items(&items[0])?,
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(atom_owned).collect()
}

#[cfg(feature = "std")]
fn parse_point(sexp: &sexp::Sexp) -> Result<CurvePointHex, PicklesError> {
    let coords = list_items(sexp)?;
    if coords.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected affine point with 2 coordinates, got {}",
            coords.len()
        )));
    }
    Ok(CurvePointHex {
        x: atom_owned(&coords[0])?,
        y: atom_owned(&coords[1])?,
    })
}

#[cfg(feature = "std")]
fn parse_point_vector(items: &[sexp::Sexp]) -> Result<Vec<CurvePointHex>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(inner) if inner.iter().all(|item| parse_point(item).is_ok()) => inner,
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(parse_point).collect()
}

#[cfg(feature = "std")]
fn parse_inner_hex(sexp: &sexp::Sexp) -> Result<Vec<String>, PicklesError> {
    match peel_singletons(sexp) {
        sexp::Sexp::List(items) if items.is_empty() => Err(PicklesError::InvalidSexp(
            "expected inner(...) wrapper".to_string(),
        )),
        sexp::Sexp::List(items) => match atom(&items[0]) {
            Ok("inner") => {
                let payload = if items.len() == 2 {
                    match peel_singletons(&items[1]) {
                        sexp::Sexp::List(_) => list_items(&items[1])?,
                        _ => &items[1..],
                    }
                } else {
                    &items[1..]
                };
                payload.iter().map(atom_owned).collect()
            }
            Ok(_) if items.len() == 1 => parse_inner_hex(&items[0]),
            Ok(other) => Err(PicklesError::InvalidSexp(format!(
                "expected inner(...) wrapper, got {other}"
            ))),
            Err(_) if items.len() == 1 => parse_inner_hex(&items[0]),
            Err(_) => parse_inner_hex(&items[0]),
        },
        _ => Err(PicklesError::InvalidSexp(
            "expected inner(...) wrapper".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn parse_pchallenge(sexp: &sexp::Sexp) -> Result<BulletproofChallengeHex, PicklesError> {
    let items = list_items(sexp)?;
    if items.is_empty() || atom(&items[0])? != "prechallenge" {
        return Err(PicklesError::InvalidSexp(
            "expected prechallenge(...) wrapper".to_string(),
        ));
    }
    if items.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected exactly one prechallenge payload, got {}",
            items.len() - 1
        )));
    }
    Ok(BulletproofChallengeHex {
        prechallenge_inner: parse_inner_hex(&items[1])?,
    })
}

#[cfg(feature = "std")]
fn parse_prechallenge_group(
    items: &[sexp::Sexp],
) -> Result<Vec<BulletproofChallengeHex>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(inner) if inner.iter().all(|item| parse_pchallenge(item).is_ok()) => {
                inner
            }
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(parse_pchallenge).collect()
}

#[cfg(feature = "std")]
fn parse_prechallenge_groups(
    items: &[sexp::Sexp],
) -> Result<Vec<Vec<BulletproofChallengeHex>>, PicklesError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(group) = parse_prechallenge_group(items) {
        return Ok(vec![group]);
    }

    if items.len() == 1 {
        return parse_prechallenge_groups(list_items(&items[0])?);
    }

    items
        .iter()
        .map(|item| parse_prechallenge_group(list_items(item)?))
        .collect()
}

#[cfg(feature = "std")]
fn parse_bool_atom(sexp: &sexp::Sexp) -> Result<bool, PicklesError> {
    match atom(sexp)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(PicklesError::InvalidSexp(format!(
            "expected boolean atom, got {other}"
        ))),
    }
}

#[cfg(feature = "std")]
fn parse_feature_flags(entries: &[sexp::Sexp]) -> Result<PlonkFeatureFlags, PicklesError> {
    Ok(PlonkFeatureFlags {
        range_check0: with_context(
            "feature_flags.range_check0",
            parse_bool_atom(binding_one(entries, "range_check0")?),
        )?,
        range_check1: with_context(
            "feature_flags.range_check1",
            parse_bool_atom(binding_one(entries, "range_check1")?),
        )?,
        foreign_field_add: with_context(
            "feature_flags.foreign_field_add",
            parse_bool_atom(binding_one(entries, "foreign_field_add")?),
        )?,
        foreign_field_mul: with_context(
            "feature_flags.foreign_field_mul",
            parse_bool_atom(binding_one(entries, "foreign_field_mul")?),
        )?,
        xor: with_context(
            "feature_flags.xor",
            parse_bool_atom(binding_one(entries, "xor")?),
        )?,
        rot: with_context(
            "feature_flags.rot",
            parse_bool_atom(binding_one(entries, "rot")?),
        )?,
        lookup: with_context(
            "feature_flags.lookup",
            parse_bool_atom(binding_one(entries, "lookup")?),
        )?,
        runtime_tables: with_context(
            "feature_flags.runtime_tables",
            parse_bool_atom(binding_one(entries, "runtime_tables")?),
        )?,
    })
}

#[cfg(feature = "std")]
fn parse_plonk(entries: &[sexp::Sexp]) -> Result<PlonkDeferredValuesHex, PicklesError> {
    let feature_flags = with_context("feature_flags", group_entries(entries, "feature_flags"))?;
    Ok(PlonkDeferredValuesHex {
        alpha_inner: with_context(
            "plonk.alpha",
            parse_inner_hex(binding_one(entries, "alpha")?),
        )?,
        beta: with_context(
            "plonk.beta",
            parse_atom_vector(binding_rest(entries, "beta")?),
        )?,
        gamma: with_context(
            "plonk.gamma",
            parse_atom_vector(binding_rest(entries, "gamma")?),
        )?,
        zeta_inner: with_context("plonk.zeta", parse_inner_hex(binding_one(entries, "zeta")?))?,
        joint_combiner_inner: match binding_optional_rest(entries, "joint_combiner") {
            Some(rest)
                if !rest.is_empty()
                    && !matches!(peel_singletons(&rest[0]), sexp::Sexp::List(inner) if inner.is_empty()) =>
            {
                Some(with_context(
                    "plonk.joint_combiner",
                    parse_inner_hex(&rest[0]),
                )?)
            }
            _ => None,
        },
        feature_flags: with_context("plonk.feature_flags", parse_feature_flags(feature_flags))?,
    })
}

#[cfg(feature = "std")]
fn payload_summary_count(rest: &[sexp::Sexp]) -> usize {
    if rest.is_empty() {
        return 0;
    }

    if rest.len() == 1 {
        match peel_singletons(&rest[0]) {
            sexp::Sexp::List(items) => items.len(),
            sexp::Sexp::Atom(_) => 1,
        }
    } else {
        1
    }
}

#[cfg(feature = "std")]
fn parse_named_section_counts(
    entries: &[sexp::Sexp],
) -> Result<Vec<NamedSectionCount>, PicklesError> {
    entries
        .iter()
        .map(|entry| {
            let items = list_items(entry)?;
            if items.is_empty() {
                return Err(PicklesError::InvalidSexp(
                    "expected named section entry".to_string(),
                ));
            }
            Ok(NamedSectionCount {
                name: atom_owned(&items[0])?,
                count: payload_summary_count(&items[1..]),
            })
        })
        .collect()
}

#[cfg(feature = "std")]
fn parse_named_field_eval_sections(
    entries: &[sexp::Sexp],
) -> Result<Vec<NamedFieldEvalSectionHex>, PicklesError> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    if atom(&entries[0]).is_ok() {
        return Ok(vec![parse_named_field_eval_section_from_items(entries)?]);
    }

    let mut sections = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        sections.push(
            parse_named_field_eval_section(entry).map_err(|err| match err {
                PicklesError::InvalidSexp(message) => {
                    PicklesError::InvalidSexp(format!("section[{index}]={} {message}", entry))
                }
                other => other,
            })?,
        );
    }
    Ok(sections)
}

#[cfg(feature = "std")]
fn parse_named_field_eval_section(
    entry: &sexp::Sexp,
) -> Result<NamedFieldEvalSectionHex, PicklesError> {
    parse_named_field_eval_section_from_items(list_items(entry)?)
}

#[cfg(feature = "std")]
fn parse_named_field_eval_section_from_items(
    items: &[sexp::Sexp],
) -> Result<NamedFieldEvalSectionHex, PicklesError> {
    if items.is_empty() {
        return Err(PicklesError::InvalidSexp(
            "expected named field-eval section entry".to_string(),
        ));
    }

    let payload_items = if items.len() == 2 {
        match peel_singletons(&items[1]) {
            sexp::Sexp::List(inner) => inner,
            _ => &items[1..],
        }
    } else {
        &items[1..]
    };

    let mut evaluations = Vec::new();
    if payload_items.len() == 2
        && parse_scalar_field_vector(&payload_items[0]).is_ok()
        && parse_scalar_field_vector(&payload_items[1]).is_ok()
    {
        evaluations.push(FieldEvalPairHex {
            zeta: parse_scalar_field_vector(&payload_items[0])?,
            zeta_omega: parse_scalar_field_vector(&payload_items[1])?,
        });
    } else {
        for payload in payload_items {
            if matches!(peel_singletons(payload), sexp::Sexp::List(inner) if inner.is_empty()) {
                continue;
            }
            evaluations.push(parse_field_eval_pair(payload)?);
        }
    }

    Ok(NamedFieldEvalSectionHex {
        name: atom_owned(&items[0])?,
        evaluations,
    })
}

#[cfg(feature = "std")]
fn parse_field_eval_pair(entry: &sexp::Sexp) -> Result<FieldEvalPairHex, PicklesError> {
    let items = list_items(entry)?;
    if items.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected evaluation pair with 2 entries, got {}",
            items.len()
        )));
    }

    Ok(FieldEvalPairHex {
        zeta: parse_scalar_field_vector(&items[0])?,
        zeta_omega: parse_scalar_field_vector(&items[1])?,
    })
}

#[cfg(feature = "std")]
fn parse_scalar_field_vector(entry: &sexp::Sexp) -> Result<Vec<String>, PicklesError> {
    match peel_singletons(entry) {
        sexp::Sexp::Atom(_) => Ok(vec![atom_owned(entry)?]),
        sexp::Sexp::List(items) => items.iter().map(atom_owned).collect(),
    }
}

#[cfg(feature = "std")]
fn parse_inner_proof(entries: &[sexp::Sexp]) -> Result<WrapProofBodyHex, PicklesError> {
    let commitments = group_entries(entries, "commitments")?;
    let evaluations = group_entries(entries, "evaluations")?;
    let bulletproof = group_entries(entries, "bulletproof")?;

    Ok(WrapProofBodyHex {
        commitments: WrapProofCommitmentsHex {
            w_comm: parse_point_vector(binding_rest(commitments, "w_comm")?)?,
            z_comm: parse_point_vector(binding_rest(commitments, "z_comm")?)?,
            t_comm: parse_point_vector(binding_rest(commitments, "t_comm")?)?,
            lookup: binding_optional_rest(commitments, "lookup")
                .map(parse_point_vector)
                .transpose()?,
        },
        evaluations: parse_named_point_sections(evaluations)?,
        ft_eval1: atom_owned(binding_one(entries, "ft_eval1")?)?,
        bulletproof: WrapBulletproofHex {
            lr_pairs: parse_point_pair_vector(binding_rest(bulletproof, "lr")?)?,
            z_1: atom_owned(binding_one(bulletproof, "z_1")?)?,
            z_2: atom_owned(binding_one(bulletproof, "z_2")?)?,
            delta: parse_point(binding_one(bulletproof, "delta")?)?,
            challenge_polynomial_commitment: parse_point(binding_one(
                bulletproof,
                "challenge_polynomial_commitment",
            )?)?,
        },
    })
}

#[cfg(feature = "std")]
fn parse_point_pair(sexp: &sexp::Sexp) -> Result<CurvePointPairHex, PicklesError> {
    let items = list_items(sexp)?;
    if items.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected curve-point pair with 2 entries, got {}",
            items.len()
        )));
    }

    Ok(CurvePointPairHex {
        left: parse_point(&items[0])?,
        right: parse_point(&items[1])?,
    })
}

#[cfg(feature = "std")]
fn parse_point_pair_vector(items: &[sexp::Sexp]) -> Result<Vec<CurvePointPairHex>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(inner) if inner.iter().all(|item| parse_point_pair(item).is_ok()) => {
                inner
            }
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(parse_point_pair).collect()
}

#[cfg(feature = "std")]
fn parse_named_point_sections(
    entries: &[sexp::Sexp],
) -> Result<Vec<NamedPointSectionHex>, PicklesError> {
    entries.iter().map(parse_named_point_section).collect()
}

#[cfg(feature = "std")]
fn parse_named_point_section(entry: &sexp::Sexp) -> Result<NamedPointSectionHex, PicklesError> {
    let items = list_items(entry)?;
    if items.is_empty() {
        return Err(PicklesError::InvalidSexp(
            "expected named point section entry".to_string(),
        ));
    }

    let name = atom_owned(&items[0])?;
    let raw_payload_items = items[1..].iter().map(|item| item.to_string()).collect();
    let points = parse_section_points(&items[1..])?;

    Ok(NamedPointSectionHex {
        name,
        raw_payload_items,
        points,
    })
}

#[cfg(feature = "std")]
fn parse_section_points(items: &[sexp::Sexp]) -> Result<Vec<CurvePointHex>, PicklesError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(points) = parse_point_vector(items) {
        return Ok(points);
    }

    if items.len() == 1 {
        if let Ok(inner) = list_items(&items[0]) {
            if let Ok(points) = parse_point_vector(inner) {
                return Ok(points);
            }
        }
    }

    Ok(Vec::new())
}

#[cfg(feature = "std")]
fn missing_field(index: usize, name: &str, source: &str) -> WrapPublicInputFieldPlan {
    WrapPublicInputFieldPlan {
        index,
        name: name.into(),
        value_hex: None,
        source: source.into(),
    }
}

#[cfg(feature = "std")]
fn known_field(
    index: usize,
    name: &str,
    value_hex: String,
    source: &str,
) -> WrapPublicInputFieldPlan {
    WrapPublicInputFieldPlan {
        index,
        name: name.into(),
        value_hex: Some(value_hex),
        source: source.into(),
    }
}

#[cfg(feature = "std")]
fn pack_hex64_limbs_to_field_hex(limbs: &[String]) -> Result<String, PicklesError> {
    let field = pack_hex64_limbs_to_field(limbs)?;
    Ok(field_to_hex(field))
}

#[cfg(feature = "std")]
fn pack_hex64_limbs_to_field(limbs: &[String]) -> Result<Fp, PicklesError> {
    use ark_ff::PrimeField;

    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        let limb = parse_hex64_limb(limb)?;
        bytes.extend_from_slice(&limb.to_le_bytes());
    }

    Ok(Fp::from_le_bytes_mod_order(&bytes))
}

#[cfg(feature = "std")]
fn pack_hex64_limbs_to_field_fq(limbs: &[String]) -> Result<Fq, PicklesError> {
    use ark_ff::PrimeField;

    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        let limb = parse_hex64_limb(limb)?;
        bytes.extend_from_slice(&limb.to_le_bytes());
    }

    Ok(Fq::from_le_bytes_mod_order(&bytes))
}

#[cfg(feature = "std")]
fn parse_hex64_limb(limb: &str) -> Result<u64, PicklesError> {
    u64::from_str_radix(limb, 16)
        .map_err(|_| PicklesError::InvalidFieldElement(format!("invalid Hex64 limb: {limb}")))
}

#[cfg(feature = "std")]
fn parse_hex_field(hex: &str) -> Result<Fp, PicklesError> {
    use ark_ff::PrimeField;

    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fp::from(0u64));
    }

    let normalized = if hex.len() % 2 == 0 {
        hex.to_owned()
    } else {
        format!("0{hex}")
    };

    let bytes = (0..normalized.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&normalized[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            PicklesError::InvalidFieldElement(format!(
                "invalid canonical hex field: 0x{normalized}"
            ))
        })?;

    Ok(Fp::from_be_bytes_mod_order(&bytes))
}

#[cfg(feature = "std")]
fn parse_hex_field_fq(hex: &str) -> Result<Fq, PicklesError> {
    use ark_ff::PrimeField;

    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fq::from(0u64));
    }

    let normalized = if hex.len() % 2 == 0 {
        hex.to_owned()
    } else {
        format!("0{hex}")
    };

    let bytes = (0..normalized.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&normalized[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            PicklesError::InvalidFieldElement(format!(
                "invalid canonical hex field: 0x{normalized}"
            ))
        })?;

    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

#[cfg(feature = "std")]
fn pack_branch_data(proofs_verified: u8, domain_log2: u8) -> Result<Fp, PicklesError> {
    let proofs_verified_mask = match proofs_verified {
        0 => 0u64,
        1 => 2u64,
        2 => 3u64,
        other => {
            return Err(PicklesError::InvalidSexp(format!(
                "unsupported proofs_verified value for branch_data packing: {other}"
            )))
        }
    };

    Ok(Fp::from(
        4u64 * u64::from(domain_log2) + proofs_verified_mask,
    ))
}

#[cfg(feature = "std")]
fn wrap_feature_flag_slots(feature_flags: &PlonkFeatureFlags) -> [(&'static str, bool); 8] {
    [
        ("feature_flags.range_check0", feature_flags.range_check0),
        ("feature_flags.range_check1", feature_flags.range_check1),
        (
            "feature_flags.foreign_field_add",
            feature_flags.foreign_field_add,
        ),
        (
            "feature_flags.foreign_field_mul",
            feature_flags.foreign_field_mul,
        ),
        ("feature_flags.xor", feature_flags.xor),
        ("feature_flags.rot", feature_flags.rot),
        ("feature_flags.lookup", feature_flags.lookup),
        ("feature_flags.runtime_tables", feature_flags.runtime_tables),
    ]
}

#[cfg(feature = "std")]
fn pack_optional_joint_combiner(
    joint_combiner_inner: &Option<Vec<String>>,
) -> Result<String, PicklesError> {
    match joint_combiner_inner {
        Some(limbs) => pack_hex64_limbs_to_field_hex(limbs),
        None => Ok(field_to_hex(Fp::from(0u64))),
    }
}

#[cfg(feature = "std")]
fn bool_to_field_hex(value: bool) -> String {
    field_to_hex(Fp::from(u64::from(value)))
}

#[cfg(feature = "std")]
fn field_to_hex(field: Fp) -> String {
    use ark_ff::{BigInteger, PrimeField};

    let bytes = field.into_bigint().to_bytes_be();
    if bytes.iter().all(|byte| *byte == 0) {
        return "0x0".into();
    }
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero byte present");
    let trimmed = &bytes[first_non_zero..];
    let mut out = String::from("0x");
    for byte in trimmed {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[cfg(feature = "std")]
fn field_to_hex_fq(field: Fq) -> String {
    use ark_ff::{BigInteger, PrimeField};

    let bytes = field.into_bigint().to_bytes_be();
    if bytes.iter().all(|byte| *byte == 0) {
        return "0x0".into();
    }
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero byte present");
    let trimmed = &bytes[first_non_zero..];
    let mut out = String::from("0x");
    for byte in trimmed {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::str::FromStr;
    use mina_curves::pasta::Fq;

    fn challenge(lo: &str, hi: &str) -> BulletproofChallengeHex {
        BulletproofChallengeHex {
            prechallenge_inner: vec![lo.to_string(), hi.to_string()],
        }
    }

    #[test]
    fn test_step_bulletproof_challenge_to_field_matches_mina_regression() {
        let field = step_bulletproof_challenge_to_field(&challenge("1", "2"))
            .expect("challenge should map to field");
        assert_eq!(
            field,
            Fp::from_str(
                "6572569482697360481513594310601353836203307207270872842979315960925898757767"
            )
            .expect("valid field element"),
        );
    }

    #[test]
    fn test_wrap_bulletproof_challenge_to_field_matches_mina_regression() {
        let field = wrap_bulletproof_challenge_to_field(&challenge("1", "2"))
            .expect("challenge should map to field");
        assert_eq!(
            field,
            Fq::from_str(
                "2719017978331529270847521198778747340188358548055489578169293623337352440597"
            )
            .expect("valid field element"),
        );
    }
}
