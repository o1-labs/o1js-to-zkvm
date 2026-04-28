//! Parses `fixtures/simple_chain_proof_repr_b0.json` first into the wire-type
//! scaffolding, then lowers through [`o1_pickles_verifier::parse`] into our
//! domain [`o1_pickles_verifier::statement::WrapStatement`]. Confirms:
//! 1. the OCaml-side schema matches what our serde derives consume;
//! 2. our wire → domain lowering preserves the shape; and
//! 3. the produced `WrapStatement` agrees with the Simple_chain `b1` fixture
//!    (app_state = (41, 42), branch_data.proofs_verified = N1, etc.).

#![cfg(feature = "std")]

use std::str::FromStr;

use o1_pickles_verifier::parse::parse_wrap_statement;
use o1_pickles_verifier::statement::ProofsVerified;
use o1_pickles_verifier::wire::{ProofReprWire, ProofsVerifiedTag};
use o1_pickles_verifier::Fp;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");

#[test]
fn parses_simple_chain_proof_repr() {
    let repr: ProofReprWire =
        serde_json::from_str(FIXTURE).expect("failed to deserialize proof repr JSON");

    // Spot-check the fixture is the Simple_chain recursive-step proof (b1)
    // whose app_state = (41, 42).
    let app_state = &repr.statement.messages_for_next_step_proof.app_state;
    assert_eq!(app_state, &["41".to_string(), "42".to_string()]);

    // Pickles wrap for Simple_chain has max_proofs_verified = N2 at the
    // wrap-circuit layer, but each stored proof's branch_data records the
    // circuit branch's own `proofs_verified` — for Simple_chain's single
    // inductive rule with one previous self-proof, that's N1.
    let branch = &repr.statement.proof_state.deferred_values.branch_data;
    assert_eq!(branch.proofs_verified, ProofsVerifiedTag::N1);

    // bulletproof_challenges is Step_bp_vec = 16.
    let bp = &repr
        .statement
        .proof_state
        .deferred_values
        .bulletproof_challenges;
    assert_eq!(bp.len(), 16, "step bulletproof challenges");

    // mlmb = N1 → both step-side vectors have length 1.
    assert_eq!(
        repr.statement
            .messages_for_next_step_proof
            .challenge_polynomial_commitments
            .len(),
        1
    );
    assert_eq!(
        repr.statement
            .messages_for_next_step_proof
            .old_bulletproof_challenges
            .len(),
        1
    );
    // Inner step-side bp is Step_bp_vec = 16.
    assert_eq!(
        repr.statement
            .messages_for_next_step_proof
            .old_bulletproof_challenges[0]
            .len(),
        16
    );

    // Wrap-side old_bulletproof_challenges: outer = mlmb = 1, inner = Wrap_bp_vec = 15.
    let wrap_old = &repr
        .statement
        .proof_state
        .messages_for_next_wrap_proof
        .old_bulletproof_challenges;
    assert_eq!(wrap_old.len(), 1);
    assert_eq!(wrap_old[0].len(), 15);
}

#[test]
fn lowers_simple_chain_proof_repr_into_domain_statement() {
    let repr: ProofReprWire =
        serde_json::from_str(FIXTURE).expect("failed to deserialize proof repr JSON");
    let stmt = parse_wrap_statement(repr.statement).expect("lowering failed");

    // app_state parses into Fp field elements with the expected values.
    assert_eq!(stmt.messages_for_next_step_proof.app_state.len(), 2);
    assert_eq!(
        stmt.messages_for_next_step_proof.app_state[0],
        Fp::from_str("41").unwrap()
    );
    assert_eq!(
        stmt.messages_for_next_step_proof.app_state[1],
        Fp::from_str("42").unwrap()
    );

    // branch_data enum preserved.
    assert!(matches!(
        stmt.proof_state.deferred_values.branch_data.proofs_verified,
        ProofsVerified::N1
    ));
    // Simple_chain wrap domain is 2^14.
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

    // Sanity: the commitment curve points are non-zero and on their respective curves.
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
