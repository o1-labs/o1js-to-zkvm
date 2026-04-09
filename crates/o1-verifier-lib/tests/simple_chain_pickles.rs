#![cfg(feature = "std")]

use o1_verifier_lib::{lower_simple_chain_metadata, parse_simple_chain_bundle};

const SIMPLE_CHAIN_BUNDLE_JSON: &str = include_str!("../../../fixtures/simple_chain_bundle.json");

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
    let bundle = parse_simple_chain_bundle(SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");
    let request = bundle
        .request_for_fixture("recursive_step")
        .expect("recursive_step fixture request");

    let lowered = lower_simple_chain_metadata(&request).expect("metadata should decode");

    assert_eq!(lowered.proofs_verified, 1);
    assert_eq!(lowered.domain_log2, 15);
    assert_eq!(lowered.wrap_challenge_polynomial_commitment.x, "0x41");
    assert_eq!(lowered.wrap_challenge_polynomial_commitment.y, "0x42");
    assert_eq!(lowered.wrap_old_bulletproof_challenges_count, 1);
    assert_eq!(lowered.next_step_challenge_polynomial_commitments.len(), 2);
    assert_eq!(lowered.next_step_old_bulletproof_challenges_count, 2);
    assert_eq!(lowered.prev_evals_public_input, vec!["0x61", "0x62"]);
    assert_eq!(lowered.ft_eval1, "0x63");
}
