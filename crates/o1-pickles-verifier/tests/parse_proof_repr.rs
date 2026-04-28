//! Parse `fixtures/simple_chain_proof_repr_b0.json` end-to-end through the
//! public `parse_proof_repr_json` API and confirm the resulting domain
//! statement has the expected shape.

#![cfg(feature = "std")]

use std::str::FromStr;

use o1_pickles_verifier::parse::parse_proof_repr_json;
use o1_pickles_verifier::statement::ProofsVerified;
use o1_pickles_verifier::Fp;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");

#[test]
fn lowers_proof_repr_into_domain_statement() {
    let parsed = parse_proof_repr_json(FIXTURE).expect("parse_proof_repr_json");
    let stmt = &parsed.statement;

    // app_state parses into Fp with the expected values for b0.
    assert_eq!(stmt.messages_for_next_step_proof.app_state.len(), 2);
    assert_eq!(
        stmt.messages_for_next_step_proof.app_state[0],
        Fp::from_str("41").unwrap()
    );
    assert_eq!(
        stmt.messages_for_next_step_proof.app_state[1],
        Fp::from_str("42").unwrap()
    );

    // Each stored proof's branch_data records `proofs_verified = N1`.
    assert!(matches!(
        stmt.proof_state.deferred_values.branch_data.proofs_verified,
        ProofsVerified::N1
    ));
    assert_eq!(stmt.proof_state.deferred_values.branch_data.domain_log2, 14);

    // mlmb = 1 on both message sides.
    assert_eq!(
        stmt.messages_for_next_step_proof
            .challenge_polynomial_commitments
            .len(),
        1
    );
    assert_eq!(
        stmt.messages_for_next_step_proof
            .old_bulletproof_challenges
            .len(),
        1
    );
    assert_eq!(
        stmt.proof_state
            .messages_for_next_wrap_proof
            .old_bulletproof_challenges
            .len(),
        1
    );

    // Both inner old_bulletproof_challenges have the right rounds (16/15).
    assert_eq!(
        stmt.messages_for_next_step_proof.old_bulletproof_challenges[0].len(),
        16,
    );
    assert_eq!(
        stmt.proof_state
            .messages_for_next_wrap_proof
            .old_bulletproof_challenges[0]
            .len(),
        15,
    );

    // The bp_chals at the deferred-values layer are length-16.
    assert_eq!(
        stmt.proof_state
            .deferred_values
            .bulletproof_challenges
            .len(),
        16,
    );

    // Curve points are non-infinity.
    assert!(
        !stmt
            .proof_state
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment
            .infinity
    );
    assert!(
        !stmt
            .messages_for_next_step_proof
            .challenge_polynomial_commitments[0]
            .infinity
    );
}
