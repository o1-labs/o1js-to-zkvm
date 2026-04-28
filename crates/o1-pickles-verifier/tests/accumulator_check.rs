//! Endo-expand the wrap statement's bulletproof challenges, compute
//! the step-side (Vesta) commitment to the challenge polynomial, and
//! check it matches `messages_for_next_wrap_proof.challenge_polynomial_commitment`.
//! Out-of-circuit verification of the scalar-field deferred work that
//! a recursive step circuit would normally handle.

#![cfg(feature = "std")]

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::parse::parse_proof_repr_json;
use o1_pickles_verifier::Vesta;
use poly_commitment::ipa::SRS;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");
const STEP_IPA_ROUNDS: usize = 16;

#[test]
fn stage2_accumulator_matches() {
    let stmt = parse_proof_repr_json(FIXTURE)
        .expect("parse_proof_repr_json")
        .statement;

    let srs: SRS<Vesta> = SRS::create_parallel(1 << STEP_IPA_ROUNDS);
    assert!(accumulator_check(
        &stmt.proof_state.deferred_values.bulletproof_challenges,
        stmt.proof_state
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment,
        &srs,
    ));
}
