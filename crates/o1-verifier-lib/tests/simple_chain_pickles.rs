#![cfg(feature = "std")]

use o1_verifier_lib::parse_simple_chain_bundle;

const SIMPLE_CHAIN_BUNDLE_JSON: &str = include_str!("../../../fixtures/simple_chain_bundle.json");

#[test]
fn test_parse_simple_chain_bundle() {
    let bundle = parse_simple_chain_bundle(SIMPLE_CHAIN_BUNDLE_JSON).expect("bundle should parse");

    assert_eq!(bundle.fixtures.len(), 2);
    assert_eq!(bundle.verification_key.0, vec![1, 2, 3]);

    let base_case = bundle.fixture("base_case").expect("base_case fixture");
    assert_eq!(base_case.statement.to_fields().len(), 1);
    assert_eq!(base_case.proof.0, vec![4, 5, 6]);

    let recursive_step = bundle
        .fixture("recursive_step")
        .expect("recursive_step fixture");
    assert_eq!(recursive_step.statement.to_fields().len(), 1);
    assert_eq!(recursive_step.proof.0, vec![7, 8, 9]);
}
