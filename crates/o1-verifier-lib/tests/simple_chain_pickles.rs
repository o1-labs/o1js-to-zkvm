//! Regression tests for the current Mina `Simple_chain` Pickles scaffold.
//!
//! These tests do not prove end-to-end Pickles verification yet. They lock:
//! - bundle parsing
//! - proof metadata decoding from real Mina fixtures
//! - the current wrap public-input planning boundary

#![cfg(feature = "std")]

use groupmap::GroupMap;
use ark_ff::{BigInteger, PrimeField};
use kimchi::error::VerifyError;
use kimchi::verifier::verify_with_rng;
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::commitment::CommitmentCurve;
use o1_verifier_lib::{
    pickles_mina_rust::{
        BranchData as MinaRustBranchData, DeferredValues as MinaRustDeferredValues,
        Plonk as MinaRustPlonk, PreparedStatement as MinaRustPreparedStatement,
        ProofState as MinaRustProofState, ShiftedValue as MinaRustShiftedValue,
    },
    lower_simple_chain_metadata, lower_simple_chain_public_input_plan, lower_simple_chain_request,
    lower_simple_chain_raw_wrap_artifacts, parse_simple_chain_bundle, WrapBaseSponge,
    WrapScalarSponge,
};
use poly_commitment::ipa::OpeningProof;
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

fn parse_hex_field_fq(hex: &str) -> Fq {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Fq::from(0u64);
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
    Fq::from_be_bytes_mod_order(&bytes)
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

#[test]
fn test_parse_simple_chain_bundle() {
    let bundle = parse_simple_chain_bundle(SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");

    assert_eq!(bundle.fixtures.len(), 2);
    assert_eq!(bundle.verification_key.0, vec![1, 2, 3]);
    assert!(bundle.exported_raw_wrap_verifier.is_none());

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
    let oracle = request
        .exported_wrap_oracle_fields
        .as_ref()
        .expect("recursive_step should include exported oracle fields");
    let exported = request
        .exported_wrap_public_input
        .as_ref()
        .expect("recursive_step should include exported wrap public input");

    let field_to_u64x4_fp = |field: Fp| field.into_bigint().0;
    let field_to_u64x4_fq = |field: Fq| field.into_bigint().0;
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
            messages_for_next_wrap_proof: field_to_u64x4_fq(parse_hex_field_fq(
                plan.fields[11]
                    .value_hex
                    .as_deref()
                    .expect("messages_for_next_wrap_proof"),
            )),
        },
        messages_for_next_step_proof: field_to_u64x4_fp(parse_hex_field_fp(
            &oracle.messages_for_next_step_proof_field_hex,
        )),
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
fn test_lower_simple_chain_request_reconstructs_srs() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let lowered = lower_simple_chain_request(&request).expect("lowering should succeed");

    assert_eq!(lowered.public_input.len(), 40);
    assert_eq!(lowered.verifier_index.max_poly_size, 32768);
    assert_eq!(lowered.verifier_index.srs.g.len(), 32768);
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
