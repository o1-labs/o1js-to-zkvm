//! Stage 2 of pickles `verifyOne` against the Simple_chain fixture.
//!
//! Endo-expands the wrap statement's bulletproof challenges, computes the
//! step-side (Vesta) commitment to the challenge polynomial, and checks it
//! matches `messages_for_next_wrap_proof.challenge_polynomial_commitment`.
//! This is the scalar-field deferred work a recursive step circuit would
//! normally handle — verified natively here.

#![cfg(feature = "std")]

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::deferred::endo_expand_scalar;
use o1_pickles_verifier::parse::parse_wrap_statement;
use o1_pickles_verifier::wire::ProofReprWire;
use o1_pickles_verifier::{Fp, Vesta};
use poly_commitment::ipa::{endos, SRS};

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr.json");

/// Step IPA rounds for pickles (pasta); SRS depth = 2^16 = 65536.
const STEP_IPA_ROUNDS: usize = 16;

#[test]
fn simple_chain_stage2_accumulator_matches() {
    let repr: ProofReprWire =
        serde_json::from_str(FIXTURE).expect("failed to deserialize proof repr JSON");
    let stmt = parse_wrap_statement(repr.statement).expect("lowering failed");

    let (_endo_q, endo_r) = endos::<Vesta>();

    // Endo-expand the 16 raw bulletproof prechallenges from the minimal
    // statement into step-field elements.
    let chals: Vec<Fp> = stmt
        .proof_state
        .deferred_values
        .bulletproof_challenges
        .iter()
        .map(|bc| endo_expand_scalar(&bc.prechallenge, &endo_r))
        .collect();
    assert_eq!(chals.len(), STEP_IPA_ROUNDS);

    // Construct the Vesta SRS deterministically — the same Blake2b + SWU
    // construction mina uses via kimchi_bindings.
    let srs: SRS<Vesta> = SRS::create_parallel(1 << STEP_IPA_ROUNDS);

    let claimed = stmt
        .proof_state
        .messages_for_next_wrap_proof
        .challenge_polynomial_commitment;

    assert!(
        accumulator_check(&chals, claimed, &srs),
        "step accumulator check failed: recomputed sg does not match claimed challenge_polynomial_commitment"
    );
}
