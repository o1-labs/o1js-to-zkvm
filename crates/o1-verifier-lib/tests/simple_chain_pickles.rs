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
        vec!["a72bd6db3fcb6313", "54635d608720548c"]
    );
    assert_eq!(lowered.deferred_bulletproof_challenges.len(), 16);
    assert_eq!(
        lowered.wrap_challenge_polynomial_commitment.x,
        "0x3424A09EE3D5AA7DB20E1995F17F6ADA8CB857950992AD18B52C819508A4AB94"
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
            "0x3989D1F6E6C9BAFC070CF883D4D56D10FEF86BB82E1F64F5DB545E0D31298258",
            "0x2BB0CE7E98BCA070FF41AA4D12D268A3463E0513AEF5E4027220EC4751D4654C"
        ]
    );
    assert_eq!(
        lowered.ft_eval1,
        "0x10AA42A4D9ABF87EC84D2C1B533BAB1A8DE7493077AC05D35A927FC7B0D3C2AE"
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
        "0x28694F3753767EBE810BAA341397F715A1E45AD0111C3CD9E158F4907EDA8558"
    );
    assert_eq!(
        lowered.inner_proof.bulletproof.z_1,
        "0x1742B94B5E3D90C58AE270F32ED4C3FA96421DF9871970BA932CE563EA1683AB"
    );
    assert_eq!(lowered.inner_proof.bulletproof.lr_pairs.len(), 15);
    assert_eq!(
        lowered
            .inner_proof
            .bulletproof
            .challenge_polynomial_commitment
            .x,
        "0x34BE5355D36CCB119E1B2B4AC68BDB62257708551FF0D6EE57FB72E65B599DAD"
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
    assert_eq!(plan.fields[5].value_hex.as_deref(), Some("0x61C695095C3215A71A53517E5ED64C42"));
    assert_eq!(plan.fields[6].name, "gamma");
    assert_eq!(plan.fields[6].value_hex.as_deref(), Some("0xD0107795EF949526488602478FDA390A"));
    assert_eq!(plan.fields[7].name, "alpha");
    assert_eq!(plan.fields[7].value_hex.as_deref(), Some("0x54635D608720548CA72BD6DB3FCB6313"));
    assert_eq!(plan.fields[8].name, "zeta");
    assert_eq!(plan.fields[8].value_hex.as_deref(), Some("0xDD5DC4D8C688A1BD2AE9FAE5D2CBF4A6"));
    assert_eq!(plan.fields[9].name, "xi");
    assert_eq!(plan.fields[9].value_hex, None);
    assert_eq!(plan.fields[10].name, "sponge_digest_before_evaluations");
    assert_eq!(
        plan.fields[10].value_hex.as_deref(),
        Some("0x211BAB24893562D458BF562A7203FAD70E531A2F4DE06BA47124D1067385677E")
    );
    assert_eq!(plan.fields[11].name, "messages_for_next_wrap_proof");
    assert_eq!(plan.fields[11].value_hex, None);
    assert_eq!(plan.fields[12].name, "messages_for_next_step_proof");
    assert_eq!(plan.fields[12].value_hex, None);
    assert_eq!(plan.fields[13].name, "bulletproof_challenges[0]");
    assert_eq!(
        plan.fields[13].value_hex.as_deref(),
        Some("0xEDB28D7CF4AE20A749D5859EE2EC9E84")
    );
    assert_eq!(plan.fields[28].name, "bulletproof_challenges[15]");
    assert_eq!(
        plan.fields[28].value_hex.as_deref(),
        Some("0xA76229A9A0BFB8A61B65D85E5CB3B4A4")
    );
    assert_eq!(plan.fields[29].name, "branch_data");
    assert_eq!(plan.fields[29].value_hex.as_deref(), Some("0x32"));
    assert_eq!(plan.fields[30].name, "joint_combiner");
    assert_eq!(plan.fields[30].value_hex.as_deref(), Some("0x0"));
}
