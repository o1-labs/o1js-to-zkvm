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
    assert_eq!(lowered.domain_log2, 12);
    assert_eq!(
        lowered.plonk.alpha_inner,
        vec!["8f2d11c04a54a4fd", "8606c33dbba5d84c"]
    );
    assert_eq!(lowered.deferred_bulletproof_challenges.len(), 16);
    assert_eq!(
        lowered.wrap_challenge_polynomial_commitment.x,
        "0x2543A55A68CBCACBE2EA255903DA9DC11925129ABE26B43A2ED1F5D20913F7B3"
    );
    assert_eq!(lowered.wrap_old_bulletproof_challenges.len(), 2);
    assert_eq!(lowered.wrap_old_bulletproof_challenges[0].len(), 15);
    assert_eq!(lowered.wrap_old_bulletproof_challenges[1].len(), 15);
    assert_eq!(lowered.next_step_challenge_polynomial_commitments.len(), 1);
    assert_eq!(lowered.next_step_old_bulletproof_challenges.len(), 1);
    assert_eq!(lowered.next_step_old_bulletproof_challenges[0].len(), 16);
    assert_eq!(
        lowered.prev_evals_public_input,
        vec![
            "0x195C0C0CA1B0E03C4D2EE138CF99E474D2E183FB5856B496270115A70C49CB5B",
            "0x27F0983EEEEDA6C38F9CADED64D50C2A76DC03DA50CC9F2FA1EB3B052901A397"
        ]
    );
    assert_eq!(
        lowered.ft_eval1,
        "0x1D25ADB2CE3DABE0F470EB79FBF66F87520F8DC8B3215DD209E3B440EFA7556F"
    );
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
    assert_eq!(
        lowered.inner_proof.ft_eval1,
        "0x3DD15AF6BADFE05215F61DEB459D26169033D3B6BD2C7EA6D6B91A56564CE0AF"
    );
    assert_eq!(
        lowered.inner_proof.bulletproof.z_1,
        "0x3B1026ACFC569C001CEBB5A6242686AF61728EB29DD0AD4CF61065EC9ADB6BBC"
    );
    assert_eq!(lowered.inner_proof.bulletproof.lr_pairs.len(), 15);
    assert_eq!(
        lowered
            .inner_proof
            .bulletproof
            .challenge_polynomial_commitment
            .x,
        "0x0D918C88788C71CB003406E68116B70B2EA006F21CCBFD89E8D0618F2E86EE7E"
    );
}

#[test]
fn test_lower_simple_chain_public_input_plan() {
    let bundle =
        parse_simple_chain_bundle(REAL_SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let plan = lower_simple_chain_public_input_plan(&request).expect("public-input plan");

    assert_eq!(plan.total_fields, 31);
    assert!(!plan.exact_public_input_available);
    assert_eq!(plan.fields.len(), 31);
    assert_eq!(plan.fields[0].name, "combined_inner_product");
    assert_eq!(plan.fields[0].value_hex, None);
    assert_eq!(plan.fields[5].name, "beta");
    assert_eq!(
        plan.fields[5].value_hex.as_deref(),
        Some("0x8D2379A80F8D7765D77AF31566E7AD99")
    );
    assert_eq!(plan.fields[6].name, "gamma");
    assert_eq!(
        plan.fields[6].value_hex.as_deref(),
        Some("0xDC53B439E866978B7665A2A86632BCC5")
    );
    assert_eq!(plan.fields[7].name, "alpha");
    assert_eq!(
        plan.fields[7].value_hex.as_deref(),
        Some("0x8606C33DBBA5D84C8F2D11C04A54A4FD")
    );
    assert_eq!(plan.fields[8].name, "zeta");
    assert_eq!(
        plan.fields[8].value_hex.as_deref(),
        Some("0x83F28D3719302A9607961A46AE39E522")
    );
    assert_eq!(plan.fields[9].name, "xi");
    assert_eq!(plan.fields[9].value_hex, None);
    assert_eq!(plan.fields[10].name, "sponge_digest_before_evaluations");
    assert_eq!(
        plan.fields[10].value_hex.as_deref(),
        Some("0x10BC8C92DADDE12BA2468A184E7B0047492848E427F589AF71FF935BACD018A0")
    );
    assert_eq!(plan.fields[11].name, "messages_for_next_wrap_proof");
    assert_eq!(plan.fields[11].value_hex, None);
    assert_eq!(plan.fields[12].name, "messages_for_next_step_proof");
    assert_eq!(plan.fields[12].value_hex, None);
    assert_eq!(plan.fields[13].name, "bulletproof_challenges[0]");
    assert_eq!(
        plan.fields[13].value_hex.as_deref(),
        Some("0x6C6D99207D5904F5B8AFE30B62A02B60")
    );
    assert_eq!(plan.fields[28].name, "bulletproof_challenges[15]");
    assert_eq!(
        plan.fields[28].value_hex.as_deref(),
        Some("0xD414D3811880F6FACA619656C6668715")
    );
    assert_eq!(plan.fields[29].name, "branch_data");
    assert_eq!(plan.fields[29].value_hex.as_deref(), Some("0x32"));
    assert_eq!(plan.fields[30].name, "joint_combiner");
    assert_eq!(plan.fields[30].value_hex.as_deref(), Some("0x0"));
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
    assert_eq!(
        exported.hex_fields[0],
        "0x12E67AEEA19DB8E50502C4BE19B06498624E1695E1505CDB0CE5C94CE02B930E"
    );
    assert_eq!(
        exported.hex_fields[5],
        "0x000000000000000000000000000000008D2379A80F8D7765D77AF31566E7AD99"
    );
    assert_eq!(
        exported.hex_fields[10],
        "0x10BC8C92DADDE12BA2468A184E7B0047492848E427F589AF71FF935BACD018A0"
    );
    assert_eq!(
        exported.hex_fields[29],
        "0x000000000000000000000000000000000000000000000000000000000000003A"
    );
    assert_eq!(
        exported.hex_fields[39],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(exported.fields.len(), 40);
}
