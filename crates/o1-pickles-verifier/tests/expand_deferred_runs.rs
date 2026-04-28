//! Run `expand_deferred` end-to-end on a real fixture and confirm the
//! step-IPA challenges it produces still pass the
//! `accumulator_check.rs` check.

#![cfg(feature = "std")]

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::messages::STEP_IPA_ROUNDS;
use o1_pickles_verifier::parse::parse_proof_repr_json;
use o1_pickles_verifier::verify::expand_deferred_for_statement;
use o1_pickles_verifier::Vesta;
use poly_commitment::ipa::SRS;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");

#[test]
fn expand_deferred_runs_on_real_prev_evals() {
    let parsed = parse_proof_repr_json(FIXTURE).expect("parse_proof_repr_json");
    let stmt = parsed.statement;
    let parsed_prev = parsed.prev_evals;

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
