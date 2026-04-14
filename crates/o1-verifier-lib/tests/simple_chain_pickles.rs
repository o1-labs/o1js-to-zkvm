//! Regression tests for the current Mina `Simple_chain` Pickles scaffold.
//!
//! These tests do not prove end-to-end Pickles verification yet. They lock:
//! - bundle parsing
//! - proof metadata decoding from real Mina fixtures
//! - the current wrap public-input planning boundary

#![cfg(feature = "std")]

use o1_verifier_lib::{
    lower_simple_chain_metadata, lower_simple_chain_public_input_plan, parse_simple_chain_bundle,
};

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

#[test]
fn test_parse_simple_chain_bundle() {
    let bundle = parse_simple_chain_bundle(SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");

    assert_eq!(bundle.fixtures.len(), 2);
    assert_eq!(bundle.verification_key.0, vec![1, 2, 3]);

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
