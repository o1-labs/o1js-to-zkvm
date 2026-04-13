#![cfg(feature = "std")]

use o1_verifier_lib::{lower_simple_chain_metadata, parse_simple_chain_bundle};

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
