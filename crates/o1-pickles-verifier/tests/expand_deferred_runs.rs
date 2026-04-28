//! Run `expand_deferred` end-to-end on a real fixture and confirm the
//! step-IPA challenges it produces still pass the
//! `accumulator_check.rs` check.

#![cfg(feature = "std")]

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::messages::STEP_IPA_ROUNDS;
use o1_pickles_verifier::parse::{parse_prev_evals, parse_wrap_statement};
use o1_pickles_verifier::verify::expand_deferred_for_statement;
use o1_pickles_verifier::wire::ProofReprWire;
use o1_pickles_verifier::Vesta;
use poly_commitment::ipa::SRS;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");

#[test]
fn expand_deferred_runs_on_real_prev_evals() {
    let repr: ProofReprWire =
        serde_json::from_str(FIXTURE).expect("failed to deserialize proof repr JSON");
    let stmt = parse_wrap_statement(repr.statement).expect("lowering statement failed");
    let parsed_prev = parse_prev_evals(repr.prev_evals).expect("lowering prev_evals failed");

    let expanded = expand_deferred_for_statement(&stmt, &parsed_prev);
    assert_eq!(expanded.new_bulletproof_challenges.len(), STEP_IPA_ROUNDS);

    let srs: SRS<Vesta> = SRS::create_parallel(1 << STEP_IPA_ROUNDS);
    assert!(accumulator_check(
        &expanded.new_bulletproof_challenges,
        stmt.proof_state
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment,
        &srs,
    ));
}
