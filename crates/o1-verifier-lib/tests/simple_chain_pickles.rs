//! Regression tests for the current Mina `Simple_chain` Pickles scaffold.
//!
//! These tests do not prove end-to-end Pickles verification yet. They lock:
//! - bundle parsing
//! - proof metadata decoding from real Mina fixtures
//! - the current wrap public-input planning boundary

#![cfg(feature = "std")]

use std::str::FromStr;

use groupmap::GroupMap;
use ark_ff::{BigInteger, PrimeField};
use kimchi::curve::KimchiCurve;
use kimchi::error::VerifyError;
use kimchi::verifier::verify_with_rng;
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use mina_poseidon::sponge::ScalarChallenge;
use poly_commitment::commitment::CommitmentCurve;
use o1_verifier_lib::{
    pickles_mina_rust::{
        DlogPlonkVerificationKeyEvals as MinaRustDlogPlonkVerificationKeyEvals,
        BranchData as MinaRustBranchData, DeferredValues as MinaRustDeferredValues,
        FieldVectorAppState, MessagesForNextStepProof as MinaRustMessagesForNextStepProof,
        MessagesForNextWrapProof as MinaRustMessagesForNextWrapProof,
        lower_pickles_with_mina_rust_model,
        Plonk as MinaRustPlonk, PreparedStatement as MinaRustPreparedStatement,
        ProofState as MinaRustProofState, ShiftedValue as MinaRustShiftedValue,
        make_padded_wrap_proof_from_request as make_mina_rust_padded_wrap_proof_from_request,
    },
    lower_simple_chain_metadata, lower_simple_chain_public_input_plan, lower_simple_chain_request,
    lower_simple_chain_raw_wrap_artifacts, parse_simple_chain_bundle, WrapBaseSponge,
    WrapScalarSponge,
};
use o1_verifier_lib::pickles_types::{
    BulletproofChallengeHex, CurvePointHex, PicklesVerifyRequest, SideLoadedProofMetadata,
};
use poly_commitment::ipa::OpeningProof;
use poly_commitment::SRS as _;
use rand::SeedableRng;
use rand::rngs::StdRng;

const SIMPLE_CHAIN_BUNDLE_JSON: &str = include_str!("../../../fixtures/simple_chain_bundle.json");
const REAL_SIMPLE_CHAIN_BUNDLE_JSON: &str =
    include_str!("../../../fixtures/simple_chain_real_bundle.json");

fn normalize_hex(hex: &str) -> String {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.to_ascii_uppercase()
    }
}

fn parse_hex_field_fp(hex: &str) -> Fp {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Fp::from(0u64);
    }
    let hex = if hex.len() % 2 == 0 {
        hex.to_owned()
    } else {
        format!("0{hex}")
    };
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid canonical hex"))
        .collect::<Vec<_>>();
    Fp::from_be_bytes_mod_order(&bytes)
}

fn hex64_limbs_to_u64_array<const N: usize>(limbs: &[String]) -> [u64; N] {
    let parsed = limbs
        .iter()
        .map(|limb| u64::from_str_radix(limb, 16).expect("valid hex64 limb"))
        .collect::<Vec<_>>();
    let len = parsed.len();
    parsed
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} hex64 limbs, got {len}"))
}

fn field_to_hex<F: PrimeField>(field: F) -> String {
    let bytes = field.into_bigint().to_bytes_be();
    if bytes.is_empty() {
        "0x0".into()
    } else {
        let mut out = String::with_capacity(2 + bytes.len() * 2);
        out.push_str("0x");
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut out, "{byte:02X}").expect("write to string");
        }
        out
    }
}

fn pack_hex64_limbs_to_field_fp(limbs: &[String]) -> Fp {
    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        let limb = u64::from_str_radix(limb, 16).expect("valid hex64 limb");
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    Fp::from_le_bytes_mod_order(&bytes)
}

fn pack_hex64_limbs_to_field_fq(limbs: &[String]) -> Fq {
    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        let limb = u64::from_str_radix(limb, 16).expect("valid hex64 limb");
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    Fq::from_le_bytes_mod_order(&bytes)
}

fn step_bulletproof_challenge_to_field(challenge: &BulletproofChallengeHex) -> Fp {
    let packed = pack_hex64_limbs_to_field_fp(&challenge.prechallenge_inner);
    let (_, endo) = Vesta::endos();
    ScalarChallenge::new(packed).to_field(endo)
}

fn wrap_bulletproof_challenge_to_field(challenge: &BulletproofChallengeHex) -> Fq {
    let packed = pack_hex64_limbs_to_field_fq(&challenge.prechallenge_inner);
    let (_, endo) = Pallas::endos();
    ScalarChallenge::new(packed).to_field(endo)
}

fn build_mina_rust_vk_evals(
    lowered: &o1_verifier_lib::pickles_lowering::LoweredRawWrapArtifacts,
) -> MinaRustDlogPlonkVerificationKeyEvals {
    let point_hex = |point: Pallas| {
        CurvePointHex {
            x: field_to_hex(point.x),
            y: field_to_hex(point.y),
        }
    };

    MinaRustDlogPlonkVerificationKeyEvals {
        sigma: std::array::from_fn(|i| point_hex(lowered.verifier_index.sigma_comm[i].chunks[0])),
        coefficients: std::array::from_fn(|i| {
            point_hex(lowered.verifier_index.coefficients_comm[i].chunks[0])
        }),
        generic: point_hex(lowered.verifier_index.generic_comm.chunks[0]),
        psm: point_hex(lowered.verifier_index.psm_comm.chunks[0]),
        complete_add: point_hex(lowered.verifier_index.complete_add_comm.chunks[0]),
        mul: point_hex(lowered.verifier_index.mul_comm.chunks[0]),
        emul: point_hex(lowered.verifier_index.emul_comm.chunks[0]),
        endomul_scalar: point_hex(lowered.verifier_index.endomul_scalar_comm.chunks[0]),
    }
}

fn build_mina_rust_wrap_message(
    metadata: &SideLoadedProofMetadata,
) -> MinaRustMessagesForNextWrapProof {
    MinaRustMessagesForNextWrapProof {
        challenge_polynomial_commitment: metadata.wrap_challenge_polynomial_commitment.clone(),
        old_bulletproof_challenges: metadata
            .wrap_old_bulletproof_challenges
            .iter()
            .map(|group: &Vec<BulletproofChallengeHex>| {
                let fields = group
                    .iter()
                    .map(wrap_bulletproof_challenge_to_field)
                    .collect::<Vec<_>>();
                fields.try_into().expect("15 wrap bulletproof challenges")
            })
            .collect(),
    }
}

fn build_mina_rust_step_message(
    request: &PicklesVerifyRequest,
    metadata: &SideLoadedProofMetadata,
    lowered: &o1_verifier_lib::pickles_lowering::LoweredRawWrapArtifacts,
) -> MinaRustMessagesForNextStepProof<FieldVectorAppState> {
    MinaRustMessagesForNextStepProof {
        app_state: FieldVectorAppState {
            fields: request.statement.to_fields(),
        },
        dlog_plonk_index: build_mina_rust_vk_evals(lowered),
        challenge_polynomial_commitments: metadata
            .next_step_challenge_polynomial_commitments
            .clone(),
        old_bulletproof_challenges: metadata
            .next_step_old_bulletproof_challenges
            .iter()
            .map(|group: &Vec<BulletproofChallengeHex>| {
                let fields = group
                    .iter()
                    .map(step_bulletproof_challenge_to_field)
                    .collect::<Vec<_>>();
                fields.try_into().expect("16 step bulletproof challenges")
            })
            .collect(),
    }
}

fn expected_mina_rust_padding_point_hex() -> CurvePointHex {
    CurvePointHex {
        x: field_to_hex(
            Fp::from_str(
                "8063668238751197448664615329057427953229339439010717262869116690340613895496",
            )
            .expect("valid mina-rust padding x-coordinate"),
        ),
        y: field_to_hex(
            Fp::from_str(
                "2694491010813221541025626495812026140144933943906714931997499229912601205355",
            )
            .expect("valid mina-rust padding y-coordinate"),
        ),
    }
}

fn assert_poly_comm_matches_exported(
    actual: &poly_commitment::commitment::PolyComm<Pallas>,
    expected: &o1_verifier_lib::pickles_types::PolyCommHex,
) {
    assert_eq!(actual.chunks.len(), expected.unshifted.len());
    assert!(expected.shifted.is_none(), "unexpected shifted commitment export");

    for (actual_chunk, expected_chunk) in actual.chunks.iter().zip(&expected.unshifted) {
        assert_eq!(
            normalize_hex(&field_to_hex(actual_chunk.x)),
            normalize_hex(&expected_chunk.x)
        );
        assert_eq!(
            normalize_hex(&field_to_hex(actual_chunk.y)),
            normalize_hex(&expected_chunk.y)
        );
    }
}

fn assert_curve_point_matches_exported(actual: &Pallas, expected: &CurvePointHex) {
    assert_eq!(normalize_hex(&field_to_hex(actual.x)), normalize_hex(&expected.x));
    assert_eq!(normalize_hex(&field_to_hex(actual.y)), normalize_hex(&expected.y));
}

fn assert_curve_point_pair_matches_exported(
    actual: &(Pallas, Pallas),
    expected: &o1_verifier_lib::pickles_types::CurvePointPairHex,
) {
    assert_curve_point_matches_exported(&actual.0, &expected.left);
    assert_curve_point_matches_exported(&actual.1, &expected.right);
}

fn assert_lowered_wrap_proof_core_matches_metadata(
    lowered: &o1_verifier_lib::pickles_lowering::LoweredRawWrapArtifacts,
    metadata: &SideLoadedProofMetadata,
) {
    assert_eq!(
        lowered.proof.commitments.w_comm.len(),
        metadata.inner_proof.commitments.w_comm.len()
    );
    for (actual, expected) in lowered
        .proof
        .commitments
        .w_comm
        .iter()
        .zip(&metadata.inner_proof.commitments.w_comm)
    {
        assert_eq!(actual.chunks.len(), 1);
        assert_curve_point_matches_exported(&actual.chunks[0], expected);
    }

    assert_eq!(lowered.proof.commitments.z_comm.chunks.len(), 1);
    assert_curve_point_matches_exported(
        &lowered.proof.commitments.z_comm.chunks[0],
        metadata
            .inner_proof
            .commitments
            .z_comm
            .first()
            .expect("z_comm export"),
    );

    assert_eq!(
        lowered.proof.commitments.t_comm.chunks.len(),
        metadata.inner_proof.commitments.t_comm.len()
    );
    for (actual, expected) in lowered
        .proof
        .commitments
        .t_comm
        .chunks
        .iter()
        .zip(&metadata.inner_proof.commitments.t_comm)
    {
        assert_curve_point_matches_exported(actual, expected);
    }

    assert_eq!(
        lowered.proof.proof.lr.len(),
        metadata.inner_proof.bulletproof.lr_pairs.len()
    );
    for (actual, expected) in lowered
        .proof
        .proof
        .lr
        .iter()
        .zip(&metadata.inner_proof.bulletproof.lr_pairs)
    {
        assert_curve_point_pair_matches_exported(actual, expected);
    }

    assert_curve_point_matches_exported(
        &lowered.proof.proof.delta,
        &metadata.inner_proof.bulletproof.delta,
    );
    assert_curve_point_matches_exported(
        &lowered.proof.proof.sg,
        &metadata.inner_proof.bulletproof.challenge_polynomial_commitment,
    );
    assert_eq!(
        normalize_hex(&field_to_hex(lowered.proof.proof.z1)),
        normalize_hex(&metadata.inner_proof.bulletproof.z_1)
    );
    assert_eq!(
        normalize_hex(&field_to_hex(lowered.proof.proof.z2)),
        normalize_hex(&metadata.inner_proof.bulletproof.z_2)
    );
    assert_eq!(
        normalize_hex(&field_to_hex(lowered.proof.ft_eval1)),
        normalize_hex(&metadata.inner_proof.ft_eval1)
    );
}

fn first_eval_mismatch_against_side_loaded_prev_evals(
    lowered: &o1_verifier_lib::pickles_lowering::LoweredRawWrapArtifacts,
    metadata: &SideLoadedProofMetadata,
) -> Option<String> {
    let w_evals = metadata
        .prev_evals
        .iter()
        .find(|section| section.name == "w")
        .expect("w prev_evals");
    if lowered.proof.evals.w.len() != w_evals.evaluations.len() {
        return Some(format!(
            "w length mismatch: lowered={}, exported={}",
            lowered.proof.evals.w.len(),
            w_evals.evaluations.len()
        ));
    }
    for (index, (actual, expected)) in lowered
        .proof
        .evals
        .w
        .iter()
        .zip(&w_evals.evaluations)
        .enumerate()
    {
        for (field_index, (actual, expected)) in actual.zeta.iter().zip(&expected.zeta).enumerate() {
            if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
                return Some(format!("w[{index}].zeta[{field_index}]"));
            }
        }
        for (field_index, (actual, expected)) in actual
            .zeta_omega
            .iter()
            .zip(&expected.zeta_omega)
            .enumerate()
        {
            if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
                return Some(format!("w[{index}].zeta_omega[{field_index}]"));
            }
        }
    }

    let coeff_evals = metadata
        .prev_evals
        .iter()
        .find(|section| section.name == "coefficients")
        .expect("coefficients prev_evals");
    if lowered.proof.evals.coefficients.len() != coeff_evals.evaluations.len() {
        return Some(format!(
            "coefficients length mismatch: lowered={}, exported={}",
            lowered.proof.evals.coefficients.len(),
            coeff_evals.evaluations.len()
        ));
    }
    for (index, (actual, expected)) in lowered
        .proof
        .evals
        .coefficients
        .iter()
        .zip(&coeff_evals.evaluations)
        .enumerate()
    {
        for (field_index, (actual, expected)) in actual.zeta.iter().zip(&expected.zeta).enumerate() {
            if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
                return Some(format!("coefficients[{index}].zeta[{field_index}]"));
            }
        }
        for (field_index, (actual, expected)) in actual
            .zeta_omega
            .iter()
            .zip(&expected.zeta_omega)
            .enumerate()
        {
            if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
                return Some(format!("coefficients[{index}].zeta_omega[{field_index}]"));
            }
        }
    }

    let z_evals = metadata
        .prev_evals
        .iter()
        .find(|section| section.name == "z")
        .expect("z prev_evals");
    if z_evals.evaluations.len() != 1 {
        return Some(format!("z length mismatch: exported={}", z_evals.evaluations.len()));
    }
    for (field_index, (actual, expected)) in lowered
        .proof
        .evals
        .z
        .zeta
        .iter()
        .zip(&z_evals.evaluations[0].zeta)
        .enumerate()
    {
        if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
            return Some(format!("z.zeta[{field_index}]"));
        }
    }
    for (field_index, (actual, expected)) in lowered
        .proof
        .evals
        .z
        .zeta_omega
        .iter()
        .zip(&z_evals.evaluations[0].zeta_omega)
        .enumerate()
    {
        if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
            return Some(format!("z.zeta_omega[{field_index}]"));
        }
    }

    let s_evals = metadata
        .prev_evals
        .iter()
        .find(|section| section.name == "s")
        .expect("s prev_evals");
    if lowered.proof.evals.s.len() != s_evals.evaluations.len() {
        return Some(format!(
            "s length mismatch: lowered={}, exported={}",
            lowered.proof.evals.s.len(),
            s_evals.evaluations.len()
        ));
    }
    for (index, (actual, expected)) in lowered
        .proof
        .evals
        .s
        .iter()
        .zip(&s_evals.evaluations)
        .enumerate()
    {
        for (field_index, (actual, expected)) in actual.zeta.iter().zip(&expected.zeta).enumerate() {
            if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
                return Some(format!("s[{index}].zeta[{field_index}]"));
            }
        }
        for (field_index, (actual, expected)) in actual
            .zeta_omega
            .iter()
            .zip(&expected.zeta_omega)
            .enumerate()
        {
            if normalize_hex(&field_to_hex(*actual)) != normalize_hex(expected) {
                return Some(format!("s[{index}].zeta_omega[{field_index}]"));
            }
        }
    }

    None
}

fn assert_point_evaluations_match_probe(
    actual: &kimchi::proof::PointEvaluations<Vec<Fq>>,
    expected: &o1_verifier_lib::pickles_types::FieldEvalPairHex,
    label: &str,
) {
    assert_eq!(
        actual.zeta.len(),
        expected.zeta.len(),
        "{label}.zeta length mismatch"
    );
    assert_eq!(
        actual.zeta_omega.len(),
        expected.zeta_omega.len(),
        "{label}.zeta_omega length mismatch"
    );
    for (index, (actual, expected)) in actual.zeta.iter().zip(&expected.zeta).enumerate() {
        assert_eq!(
            normalize_hex(&field_to_hex(*actual)),
            normalize_hex(expected),
            "{label}.zeta[{index}] mismatch",
        );
    }
    for (index, (actual, expected)) in actual.zeta_omega.iter().zip(&expected.zeta_omega).enumerate()
    {
        assert_eq!(
            normalize_hex(&field_to_hex(*actual)),
            normalize_hex(expected),
            "{label}.zeta_omega[{index}] mismatch",
        );
    }
}

#[test]
fn test_parse_simple_chain_bundle() {
    let bundle = parse_simple_chain_bundle(SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");

    assert_eq!(bundle.fixtures.len(), 2);
    assert_eq!(bundle.verification_key.0, vec![1, 2, 3]);
    assert!(bundle.exported_raw_wrap_verifier.is_none());
    assert!(bundle.exported_srs_identity.is_none());

    let base_case = bundle.fixture("base_case").expect("base_case fixture");
    assert_eq!(base_case.statement.to_fields().len(), 1);
    assert!(!base_case.proof.0.is_empty());

    let recursive_step = bundle
        .fixture("recursive_step")
        .expect("recursive_step fixture");
    assert_eq!(recursive_step.statement.to_fields().len(), 1);
    assert!(!recursive_step.proof.0.is_empty());
}

#[test]
fn test_lower_simple_chain_metadata() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let lowered = lower_simple_chain_metadata(&request).expect("metadata should decode");

    assert_eq!(lowered.proofs_verified, 1);
    assert_eq!(lowered.domain_log2, 14);
    assert_eq!(lowered.plonk.alpha_inner.len(), 2);
    assert_eq!(lowered.deferred_bulletproof_challenges.len(), 16);
    assert!(lowered
        .wrap_challenge_polynomial_commitment
        .x
        .starts_with("0x"));
    assert_eq!(lowered.wrap_old_bulletproof_challenges.len(), 2);
    assert_eq!(lowered.wrap_old_bulletproof_challenges[0].len(), 15);
    assert_eq!(lowered.wrap_old_bulletproof_challenges[1].len(), 15);
    assert_eq!(lowered.next_step_challenge_polynomial_commitments.len(), 1);
    assert_eq!(lowered.next_step_old_bulletproof_challenges.len(), 1);
    assert_eq!(lowered.next_step_old_bulletproof_challenges[0].len(), 16);
    assert_eq!(lowered.prev_evals_public_input.len(), 2);
    assert!(lowered
        .prev_evals_public_input
        .iter()
        .all(|field| field.starts_with("0x")));
    assert_eq!(lowered.prev_evals.len(), 25);
    assert_eq!(lowered.prev_evals[0].name, "w");
    assert_eq!(lowered.prev_evals[0].evaluations.len(), 15);
    assert_eq!(lowered.prev_evals[0].evaluations[0].zeta.len(), 1);
    assert_eq!(lowered.prev_evals[0].evaluations[0].zeta_omega.len(), 1);
    assert!(lowered.ft_eval1.starts_with("0x"));
    assert!(!lowered.prev_evals_sections.is_empty());
    assert_eq!(lowered.inner_proof.commitments.w_comm.len(), 15);
    assert_eq!(lowered.inner_proof.commitments.z_comm.len(), 1);
    assert_eq!(lowered.inner_proof.commitments.t_comm.len(), 7);
    assert!(lowered.inner_proof.commitments.lookup.is_none());
    assert_eq!(lowered.inner_proof.evaluations.len(), 10);
    assert_eq!(lowered.inner_proof.evaluations[0].name, "w");
    assert_eq!(lowered.inner_proof.evaluations[0].points.len(), 15);
    assert_eq!(lowered.inner_proof.evaluations[2].name, "z");
    assert_eq!(lowered.inner_proof.evaluations[2].points.len(), 1);
    assert!(lowered.inner_proof.ft_eval1.starts_with("0x"));
    assert!(lowered.inner_proof.bulletproof.z_1.starts_with("0x"));
    assert_eq!(lowered.inner_proof.bulletproof.lr_pairs.len(), 15);
    assert!(lowered
        .inner_proof
        .bulletproof
        .challenge_polynomial_commitment
        .x
        .starts_with("0x"));
}

#[test]
fn test_lower_simple_chain_base_case_metadata() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("base_case")
        .expect("base_case fixture request");

    let lowered = lower_simple_chain_metadata(&request).expect("base_case metadata should decode");

    assert_eq!(lowered.proofs_verified, 1);
    assert_eq!(lowered.domain_log2, 14);
    assert_eq!(lowered.deferred_bulletproof_challenges.len(), 16);
    assert_eq!(lowered.inner_proof.commitments.w_comm.len(), 15);
    assert_eq!(lowered.inner_proof.commitments.t_comm.len(), 7);
    assert_eq!(lowered.inner_proof.bulletproof.lr_pairs.len(), 15);
}

#[test]
fn test_lower_simple_chain_public_input_plan() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let plan = lower_simple_chain_public_input_plan(&request).expect("public-input plan");
    let exported = request
        .exported_wrap_public_input
        .clone()
        .expect("recursive_step should include exported wrap public input");
    let exported_oracle = request
        .exported_wrap_oracle_fields
        .clone()
        .expect("recursive_step should include exported oracle fields");

    assert_eq!(plan.total_fields, 40);
    assert!(plan.exact_public_input_available);
    assert_eq!(plan.fields.len(), 40);
    assert_eq!(plan.fields[0].name, "combined_inner_product");
    assert_eq!(
        plan.fields[0].value_hex.as_deref(),
        Some(exported_oracle.combined_inner_product_field_hex.as_str())
    );
    assert_eq!(plan.fields[1].name, "b");
    assert_eq!(plan.fields[2].name, "zeta_to_srs_length");
    assert_eq!(plan.fields[3].name, "zeta_to_domain_size");
    assert_eq!(plan.fields[4].name, "perm");
    assert_eq!(plan.fields[5].name, "beta");
    assert_eq!(plan.fields[6].name, "gamma");
    assert_eq!(plan.fields[7].name, "alpha");
    assert_eq!(plan.fields[8].name, "zeta");
    assert_eq!(plan.fields[9].name, "xi");
    assert_eq!(plan.fields[10].name, "sponge_digest_before_evaluations");
    assert_eq!(plan.fields[11].name, "messages_for_next_wrap_proof");
    assert_eq!(plan.fields[12].name, "messages_for_next_step_proof");
    assert_eq!(
        plan.fields[12].value_hex.as_deref(),
        Some(
            exported_oracle
                .messages_for_next_step_proof_field_hex
                .as_str()
        )
    );
    assert_eq!(plan.fields[13].name, "bulletproof_challenges[0]");
    assert_eq!(plan.fields[28].name, "bulletproof_challenges[15]");
    assert_eq!(plan.fields[29].name, "branch_data");
    assert_eq!(plan.fields[30].name, "feature_flags.range_check0");
    assert_eq!(plan.fields[31].name, "feature_flags.range_check1");
    assert_eq!(plan.fields[32].name, "feature_flags.foreign_field_add");
    assert_eq!(plan.fields[33].name, "feature_flags.foreign_field_mul");
    assert_eq!(plan.fields[34].name, "feature_flags.xor");
    assert_eq!(plan.fields[35].name, "feature_flags.rot");
    assert_eq!(plan.fields[36].name, "feature_flags.lookup");
    assert_eq!(plan.fields[37].name, "feature_flags.runtime_tables");
    assert_eq!(plan.fields[38].name, "joint_combiner.present");
    assert_eq!(plan.fields[39].name, "joint_combiner.value");
    assert!(plan.fields.iter().all(|field| field.value_hex.is_some()));
    for (planned, exported_hex) in plan.fields.iter().zip(exported.hex_fields.iter()) {
        assert_eq!(
            normalize_hex(planned.value_hex.as_deref().expect("planned hex")),
            normalize_hex(exported_hex)
        );
    }
}

#[test]
fn test_parse_exported_wrap_public_input_fields() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let exported = request
        .exported_wrap_public_input
        .expect("recursive_step should include exported wrap public input");

    assert_eq!(exported.hex_fields.len(), 40);
    let oracle = request
        .exported_wrap_oracle_fields
        .expect("recursive_step should include exported oracle fields");
    assert_eq!(
        oracle.combined_inner_product_field_hex,
        exported.hex_fields[0]
    );
    assert_eq!(
        oracle.messages_for_next_step_proof_field_hex,
        exported.hex_fields[12]
    );
    assert_eq!(exported.fields.len(), 40);
}

#[test]
fn test_mina_rust_prepared_statement_matches_exported_wrap_public_input() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let plan = lower_simple_chain_public_input_plan(&request).expect("public-input plan");
    let lowered = lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap lowering");
    let oracle = request
        .exported_wrap_oracle_fields
        .as_ref()
        .expect("recursive_step should include exported oracle fields");
    let exported = request
        .exported_wrap_public_input
        .as_ref()
        .expect("recursive_step should include exported wrap public input");
    let wrap_message = build_mina_rust_wrap_message(&metadata);
    let step_message = build_mina_rust_step_message(&request, &metadata, &lowered);

    let field_to_u64x4_fp = |field: Fp| field.into_bigint().0;
    let prepared = MinaRustPreparedStatement {
        proof_state: MinaRustProofState {
            deferred_values: MinaRustDeferredValues {
                plonk: MinaRustPlonk {
                    alpha: hex64_limbs_to_u64_array::<2>(&metadata.plonk.alpha_inner),
                    beta: hex64_limbs_to_u64_array::<2>(&metadata.plonk.beta),
                    gamma: hex64_limbs_to_u64_array::<2>(&metadata.plonk.gamma),
                    zeta: hex64_limbs_to_u64_array::<2>(&metadata.plonk.zeta_inner),
                    zeta_to_srs_length: MinaRustShiftedValue::new(parse_hex_field_fp(
                        plan.fields[2].value_hex.as_deref().expect("zeta_to_srs_length"),
                    )),
                    zeta_to_domain_size: MinaRustShiftedValue::new(parse_hex_field_fp(
                        plan.fields[3].value_hex.as_deref().expect("zeta_to_domain_size"),
                    )),
                    perm: MinaRustShiftedValue::new(parse_hex_field_fp(
                        plan.fields[4].value_hex.as_deref().expect("perm"),
                    )),
                    lookup: None,
                    feature_flags: metadata.plonk.feature_flags.clone(),
                },
                combined_inner_product: MinaRustShiftedValue::new(parse_hex_field_fp(
                    &oracle.combined_inner_product_field_hex,
                )),
                b: MinaRustShiftedValue::new(parse_hex_field_fp(
                    plan.fields[1].value_hex.as_deref().expect("b"),
                )),
                xi: {
                    let limbs = field_to_u64x4_fp(parse_hex_field_fp(
                        plan.fields[9].value_hex.as_deref().expect("xi"),
                    ));
                    [limbs[0], limbs[1]]
                },
                bulletproof_challenges: plan.fields[13..29]
                    .iter()
                    .map(|field| parse_hex_field_fp(field.value_hex.as_deref().expect("bp challenge")))
                    .collect(),
                branch_data: MinaRustBranchData {
                    proofs_verified: metadata.proofs_verified,
                    domain_log2: metadata.domain_log2,
                },
            },
            sponge_digest_before_evaluations: hex64_limbs_to_u64_array::<4>(
                &metadata.sponge_digest_before_evaluations,
            ),
            messages_for_next_wrap_proof: wrap_message.hash().expect("wrap message hash"),
        },
        messages_for_next_step_proof: step_message.hash().expect("step message hash"),
    };

    let packed = prepared
        .to_public_input(40)
        .expect("mina-rust prepared statement should pack")
        .public_input;

    assert_eq!(packed.len(), 40);
    for (actual, expected_hex) in packed.iter().zip(exported.hex_fields.iter()) {
        let bytes = actual.into_bigint().to_bytes_be();
        let actual_hex = if bytes.is_empty() {
            "0".to_string()
        } else {
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                use std::fmt::Write as _;
                write!(&mut out, "{byte:02X}").expect("write to string");
            }
            out
        };
        assert_eq!(normalize_hex(&actual_hex), normalize_hex(expected_hex));
    }
}

#[test]
fn test_mina_rust_lowered_wrap_verification_matches_exported_public_input() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let exported = request
        .exported_wrap_public_input
        .as_ref()
        .expect("recursive_step should include exported wrap public input");

    let lowered =
        lower_pickles_with_mina_rust_model(&request).expect("mina-rust lowering should succeed");

    assert_eq!(lowered.verifier_index.public, 40);
    assert_eq!(lowered.public_input.len(), 40);
    assert_eq!(lowered.proof.prev_challenges.len(), 2);

    for (expected, actual) in exported.hex_fields.iter().zip(&lowered.public_input) {
        assert_eq!(
            normalize_hex(expected),
            normalize_hex(&field_to_hex(*actual)),
        );
    }
}

#[test]
fn test_mina_rust_wrap_message_hash_matches_exported_wrap_field() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let plan = lower_simple_chain_public_input_plan(&request).expect("public-input plan");

    let wrap_message = build_mina_rust_wrap_message(&metadata);
    let hash = Fq::from_bigint(ark_ff::BigInt::<4>::new(wrap_message.hash().expect("wrap hash")))
        .expect("valid wrap hash field");

    assert_eq!(
        normalize_hex(&field_to_hex(hash)),
        normalize_hex(
            plan.fields[11]
                .value_hex
                .as_deref()
                .expect("messages_for_next_wrap_proof")
        )
    );
}

#[test]
fn test_mina_rust_step_message_hash_matches_exported_oracle_field() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let lowered = lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap lowering");
    let oracle = request
        .exported_wrap_oracle_fields
        .as_ref()
        .expect("recursive_step should include exported oracle fields");

    let step_message = build_mina_rust_step_message(&request, &metadata, &lowered);
    let hash = Fp::from_bigint(ark_ff::BigInt::<4>::new(step_message.hash().expect("step hash")))
        .expect("valid step hash field");

    assert_eq!(
        normalize_hex(&field_to_hex(hash)),
        normalize_hex(&oracle.messages_for_next_step_proof_field_hex)
    );
}

#[test]
fn test_lower_simple_chain_raw_wrap_artifacts() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    assert!(bundle.exported_raw_wrap_verifier.is_some());

    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    assert!(request.exported_raw_wrap_proof.is_some());

    let lowered =
        lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap artifacts should parse");

    assert_eq!(lowered.public_input.len(), 40);
    assert_eq!(lowered.verifier_index.domain.log_size_of_group, 14);
    assert_eq!(lowered.verifier_index.public, 40);
    assert_eq!(lowered.verifier_index.prev_challenges, 2);
    assert_eq!(lowered.proof.commitments.w_comm.len(), 15);
    assert_eq!(lowered.proof.commitments.t_comm.len(), 7);
    assert_eq!(lowered.proof.proof.lr.len(), 15);
    assert_eq!(lowered.proof.prev_challenges.len(), 2);
    assert_eq!(lowered.proof.prev_challenges[0].chals.len(), 15);
    assert_eq!(lowered.proof.prev_challenges[1].chals.len(), 15);
    assert_eq!(lowered.proof.prev_challenges[0].comm.chunks.len(), 1);
    assert_eq!(lowered.proof.prev_challenges[1].comm.chunks.len(), 1);
}

#[test]
fn test_lowered_recursive_wrap_proof_core_matches_exported_opening_boundary() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let lowered =
        lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap artifacts should parse");

    assert_lowered_wrap_proof_core_matches_metadata(&lowered, &metadata);
}

#[test]
fn test_recursive_wrap_evals_diverge_from_side_loaded_prev_evals_at_first_witness_slot() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let lowered =
        lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap artifacts should parse");

    let mismatch =
        first_eval_mismatch_against_side_loaded_prev_evals(&lowered, &metadata).expect("mismatch");
    assert_eq!(mismatch, "w[0].zeta[0]");
}

#[test]
fn test_lowered_prev_challenges_match_exported_backend_prev_challenges() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let exported = request
        .exported_backend_prev_challenges
        .as_ref()
        .expect("recursive_step should include exported backend prev_challenges");
    let lowered =
        lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap artifacts should parse");

    assert_eq!(lowered.proof.prev_challenges.len(), exported.len());

    for (actual, expected) in lowered.proof.prev_challenges.iter().zip(exported) {
        assert_eq!(actual.chals.len(), expected.chals_hex.len());
        for (actual_chal, expected_chal) in actual.chals.iter().zip(&expected.chals_hex) {
            assert_eq!(
                normalize_hex(&field_to_hex(*actual_chal)),
                normalize_hex(expected_chal)
            );
        }
        assert_poly_comm_matches_exported(&actual.comm, &expected.comm);
    }
}

#[test]
fn test_lowered_recursive_wrap_evals_match_exported_backend_probe() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let probe = request
        .exported_backend_evals_probe
        .as_ref()
        .expect("recursive_step should include exported backend eval probe");
    let lowered =
        lower_simple_chain_raw_wrap_artifacts(&request).expect("raw wrap artifacts should parse");

    assert_point_evaluations_match_probe(&lowered.proof.evals.w[0], &probe.w0, "w0");
    assert_point_evaluations_match_probe(&lowered.proof.evals.z, &probe.z, "z");
    assert_point_evaluations_match_probe(&lowered.proof.evals.s[0], &probe.s0, "s0");
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.coefficients[0],
        &probe.coeff0,
        "coeff0",
    );
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.generic_selector,
        &probe.generic_selector,
        "generic_selector",
    );
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.poseidon_selector,
        &probe.poseidon_selector,
        "poseidon_selector",
    );
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.complete_add_selector,
        &probe.complete_add_selector,
        "complete_add_selector",
    );
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.mul_selector,
        &probe.mul_selector,
        "mul_selector",
    );
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.emul_selector,
        &probe.emul_selector,
        "emul_selector",
    );
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.endomul_scalar_selector,
        &probe.endomul_scalar_selector,
        "endomul_scalar_selector",
    );
}

#[test]
fn test_lower_simple_chain_base_case_raw_wrap_artifacts() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    assert!(bundle.exported_raw_wrap_verifier.is_some());

    let request = bundle
        .request_for_fixture("base_case")
        .expect("base_case fixture request");
    assert!(request.exported_raw_wrap_proof.is_some());

    let lowered = lower_simple_chain_raw_wrap_artifacts(&request)
        .expect("base_case raw wrap artifacts should parse");

    assert_eq!(lowered.public_input.len(), 40);
    assert_eq!(lowered.verifier_index.domain.log_size_of_group, 14);
    assert_eq!(lowered.verifier_index.public, 40);
    assert_eq!(lowered.verifier_index.prev_challenges, 2);
    assert_eq!(lowered.proof.commitments.w_comm.len(), 15);
    assert_eq!(lowered.proof.commitments.t_comm.len(), 7);
    assert_eq!(lowered.proof.proof.lr.len(), 15);
    assert_eq!(lowered.proof.prev_challenges.len(), 2);
    assert_eq!(lowered.proof.prev_challenges[0].chals.len(), 15);
    assert_eq!(lowered.proof.prev_challenges[1].chals.len(), 15);
    assert_eq!(lowered.proof.prev_challenges[0].comm.chunks.len(), 1);
    assert_eq!(lowered.proof.prev_challenges[1].comm.chunks.len(), 1);
}

#[test]
fn test_lowered_base_case_wrap_evals_match_exported_backend_probe() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("base_case")
        .expect("base_case fixture request");
    let probe = request
        .exported_backend_evals_probe
        .as_ref()
        .expect("base_case should include exported backend eval probe");
    let lowered = lower_simple_chain_raw_wrap_artifacts(&request)
        .expect("base_case raw wrap artifacts should parse");

    assert_point_evaluations_match_probe(&lowered.proof.evals.w[0], &probe.w0, "w0");
    assert_point_evaluations_match_probe(&lowered.proof.evals.z, &probe.z, "z");
    assert_point_evaluations_match_probe(&lowered.proof.evals.s[0], &probe.s0, "s0");
    assert_point_evaluations_match_probe(
        &lowered.proof.evals.coefficients[0],
        &probe.coeff0,
        "coeff0",
    );
}

#[test]
fn test_lowered_base_case_wrap_proof_core_matches_exported_opening_boundary() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("base_case")
        .expect("base_case fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let lowered = lower_simple_chain_raw_wrap_artifacts(&request)
        .expect("base_case raw wrap artifacts should parse");

    assert_lowered_wrap_proof_core_matches_metadata(&lowered, &metadata);
}

#[test]
fn test_base_case_wrap_evals_diverge_from_side_loaded_prev_evals_at_first_witness_slot() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("base_case")
        .expect("base_case fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let lowered = lower_simple_chain_raw_wrap_artifacts(&request)
        .expect("base_case raw wrap artifacts should parse");

    let mismatch =
        first_eval_mismatch_against_side_loaded_prev_evals(&lowered, &metadata).expect("mismatch");
    assert_eq!(mismatch, "w[0].zeta[0]");
}

#[test]
fn test_mina_rust_padded_wrap_proof_uses_padding_commitment() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");
    let metadata = lower_simple_chain_metadata(&request).expect("metadata should decode");
    let legacy = lower_simple_chain_raw_wrap_artifacts(&request).expect("legacy raw wrap lowering");
    let padded =
        make_mina_rust_padded_wrap_proof_from_request(&request).expect("mina-rust padded proof");

    assert_eq!(padded.commitments.w_comm, legacy.proof.commitments.w_comm);
    assert_eq!(padded.commitments.z_comm, legacy.proof.commitments.z_comm);
    assert_eq!(padded.commitments.t_comm, legacy.proof.commitments.t_comm);
    assert_eq!(padded.proof.lr, legacy.proof.proof.lr);
    assert_eq!(padded.proof.delta, legacy.proof.proof.delta);
    assert_eq!(padded.proof.sg, legacy.proof.proof.sg);
    assert_eq!(padded.ft_eval1, legacy.proof.ft_eval1);

    assert_eq!(padded.prev_challenges.len(), 2);
    assert_eq!(padded.prev_challenges[0].chals.len(), 15);
    assert_eq!(padded.prev_challenges[1].chals.len(), 15);

    let expected_padding = expected_mina_rust_padding_point_hex();
    let padding_chunk = padded.prev_challenges[0].comm.chunks[0];
    assert_eq!(normalize_hex(&field_to_hex(padding_chunk.x)), normalize_hex(&expected_padding.x));
    assert_eq!(normalize_hex(&field_to_hex(padding_chunk.y)), normalize_hex(&expected_padding.y));

    let actual_chunk = padded.prev_challenges[1].comm.chunks[0];
    let expected_actual = &metadata.next_step_challenge_polynomial_commitments[0];
    assert_eq!(normalize_hex(&field_to_hex(actual_chunk.x)), normalize_hex(&expected_actual.x));
    assert_eq!(normalize_hex(&field_to_hex(actual_chunk.y)), normalize_hex(&expected_actual.y));
}

#[test]
fn test_mina_rust_padded_wrap_proof_base_case_uses_padding_commitment() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("base_case")
        .expect("base_case fixture request");
    let padded =
        make_mina_rust_padded_wrap_proof_from_request(&request).expect("mina-rust padded proof");

    assert_eq!(padded.prev_challenges.len(), 2);
    assert_eq!(padded.prev_challenges[0].chals.len(), 15);
    assert_eq!(padded.prev_challenges[1].chals.len(), 15);

    let expected_padding = expected_mina_rust_padding_point_hex();
    let padding_chunk = padded.prev_challenges[0].comm.chunks[0];
    assert_eq!(normalize_hex(&field_to_hex(padding_chunk.x)), normalize_hex(&expected_padding.x));
    assert_eq!(normalize_hex(&field_to_hex(padding_chunk.y)), normalize_hex(&expected_padding.y));
}

#[test]
fn test_lower_simple_chain_request_reconstructs_srs() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let lowered = lower_simple_chain_request(&request).expect("lowering should succeed");
    let exported_srs_identity = request
        .exported_srs_identity
        .as_ref()
        .expect("real fixture should include exported SRS identity");

    assert_eq!(lowered.public_input.len(), 40);
    assert_eq!(lowered.verifier_index.max_poly_size, 32768);
    assert_eq!(lowered.verifier_index.srs.g.len(), 32768);
    assert_eq!(
        exported_srs_identity.lagrange_commitments_domain_size,
        1 << lowered.verifier_index.domain.log_size_of_group
    );
    assert_eq!(
        exported_srs_identity.lagrange_commitments.len(),
        exported_srs_identity.lagrange_commitments_domain_size
    );
    assert_eq!(
        normalize_hex(&field_to_hex(lowered.verifier_index.srs.h.x)),
        normalize_hex(&exported_srs_identity.urs_h.x)
    );
    assert_eq!(
        normalize_hex(&field_to_hex(lowered.verifier_index.srs.h.y)),
        normalize_hex(&exported_srs_identity.urs_h.y)
    );
}

#[test]
#[ignore = "expensive full wrap lagrange-basis comparison against Mina export"]
fn test_lower_simple_chain_request_matches_exported_lagrange_commitment_order() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let lowered = lower_simple_chain_request(&request).expect("lowering should succeed");
    let exported_srs_identity = request
        .exported_srs_identity
        .as_ref()
        .expect("real fixture should include exported SRS identity");

    let lagrange_basis = lowered
        .verifier_index
        .srs
        .get_lagrange_basis(lowered.verifier_index.domain);

    assert_eq!(
        lagrange_basis.len(),
        exported_srs_identity.lagrange_commitments.len()
    );

    for (actual, expected) in lagrange_basis
        .iter()
        .zip(&exported_srs_identity.lagrange_commitments)
    {
        assert_poly_comm_matches_exported(actual, expected);
    }
}

#[test]
fn test_verify_simple_chain_recursive_step_reports_current_wrap_failure() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let lowered = lower_simple_chain_request(&request).expect("lowering should succeed");
    let group_map = <Pallas as CommitmentCurve>::Map::setup();
    let mut rng = StdRng::seed_from_u64(42);

    let result = verify_with_rng::<
        FULL_ROUNDS,
        Pallas,
        WrapBaseSponge,
        WrapScalarSponge,
        OpeningProof<Pallas, FULL_ROUNDS>,
        _,
    >(
        &group_map,
        &lowered.verifier_index,
        &lowered.proof,
        &lowered.public_input,
        &mut rng,
    );

    assert!(
        matches!(result, Err(VerifyError::OpenProof)),
        "unexpected wrap verification result: {result:?}"
    );
}
