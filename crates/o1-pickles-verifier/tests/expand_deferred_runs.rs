//! Run `expand_deferred` end-to-end on the Simple_chain fixture.
//!
//! This test doesn't compare outputs against OCaml — it just threads the
//! real `prev_evals` through the full pipeline (sponge replay, endo
//! expansion, `derive_plonk`, `ft_eval0`, `combined_inner_product`,
//! `compute_bp_chals_and_b`) and asserts the call returns `Ok(_)`. A
//! malformed sponge order, miscategorised field, or mismatched column
//! set in the linearization tokens would surface as either an error or
//! a panic here.
//!
//! As a cheap self-consistency ping, we also confirm that the bp
//! challenges `expand_deferred` expanded internally agree with the same
//! Stage-2 expansion we ran in `accumulator_check.rs` — and still pass
//! the accumulator check against the claimed `challenge_polynomial_commitment`.

#![cfg(feature = "std")]

use ark_ff::BigInt;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::polynomials::permutation::Shifts;
use kimchi::linearization::expr_linearization;
use mina_poseidon::pasta::fp_kimchi;

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::deferred::{endo_expand_scalar, expand_deferred, ExpandDeferredInput};
use o1_pickles_verifier::parse::{parse_prev_evals, parse_wrap_statement};
use o1_pickles_verifier::statement::{Digest, ProofsVerified};
use o1_pickles_verifier::wire::ProofReprWire;
use o1_pickles_verifier::{Fp, Vesta};
use poly_commitment::ipa::{endos, SRS};

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr.json");

const STEP_IPA_ROUNDS: usize = 16;
const ZK_ROWS: u32 = 3;
const SRS_LENGTH_LOG2: u32 = STEP_IPA_ROUNDS as u32;

/// Pack a [`Digest`]'s 4 u64 limbs (LSB-first) into an Fp element. Mirrors
/// OCaml `Digest.Constant.to_tick_field` — pickles emits the sponge digest
/// as 4 signed-int64 limbs; reinterpret as a field element.
fn digest_to_fp(d: &Digest) -> Fp {
    let bi: BigInt<4> = BigInt::new(d.0);
    Fp::from_bigint(bi).expect("sponge digest fits in Fp")
}

#[test]
fn simple_chain_expand_deferred_runs_on_real_prev_evals() {
    let repr: ProofReprWire =
        serde_json::from_str(FIXTURE).expect("failed to deserialize proof repr JSON");
    let stmt = parse_wrap_statement(repr.statement).expect("lowering statement failed");
    let parsed_prev = parse_prev_evals(repr.prev_evals).expect("lowering prev_evals failed");

    // Domain log2 for Simple_chain is 14 (assert it, since the step domain
    // is what we use to build shifts + vanishing-polynomial terms).
    assert_eq!(stmt.proof_state.deferred_values.branch_data.domain_log2, 14);
    assert!(matches!(
        stmt.proof_state.deferred_values.branch_data.proofs_verified,
        ProofsVerified::N1
    ));
    let domain_log2: u32 = u32::from(stmt.proof_state.deferred_values.branch_data.domain_log2);

    // ---- static step-side constants ------------------------------------
    let (_endo_q, endo_r) = endos::<Vesta>();
    let sponge_params = fp_kimchi::static_params();
    let mds: &'static [[Fp; 3]; 3] = &sponge_params.mds;

    let domain: Radix2EvaluationDomain<Fp> =
        Radix2EvaluationDomain::new(1 << domain_log2).expect("step domain");
    let generator = domain.group_gen;
    let shifts_obj = Shifts::<Fp>::new(&domain);
    let shifts: [Fp; 7] = *shifts_obj.shifts();

    // Simple_chain uses no optional gates/lookups — build a linearization
    // with feature_flags = None so it uses IfFeature nodes correctly, then
    // evaluate against our (flags-less) evaluations.
    let (linearization, _powers_of_alpha) = expr_linearization::<Fp>(
        Some(&FeatureFlags {
            range_check0: false,
            range_check1: false,
            foreign_field_add: false,
            foreign_field_mul: false,
            xor: false,
            rot: false,
            lookup_features: kimchi::circuits::lookup::lookups::LookupFeatures {
                patterns: kimchi::circuits::lookup::lookups::LookupPatterns {
                    xor: false,
                    lookup: false,
                    range_check: false,
                    foreign_field_mul: false,
                },
                joint_lookup_used: false,
                uses_runtime_tables: false,
            },
        }),
        true, // generic
    );

    // ---- per-proof derived inputs --------------------------------------
    // Old bp challenges (wrap-side carried = step field = Fp). Simple_chain
    // has mlmb = 1 so one inner vector of 16 raw prechallenges; endo-expand
    // element-wise into Vec<Fp>.
    let old_bp_chals: Vec<Vec<Fp>> = stmt
        .messages_for_next_step_proof
        .old_bulletproof_challenges
        .iter()
        .map(|inner| {
            inner
                .iter()
                .map(|bc| endo_expand_scalar(&bc.prechallenge, &endo_r))
                .collect()
        })
        .collect();
    assert_eq!(old_bp_chals.len(), 1);
    assert_eq!(old_bp_chals[0].len(), STEP_IPA_ROUNDS);

    // Sponge digest checkpoint: minimal-statement-carried `Fp`.
    let sponge_digest = digest_to_fp(&stmt.proof_state.sponge_digest_before_evaluations);

    // Single-chunk public input: ft_eval0's `actual_evaluation` Horner-fold
    // over 1 chunk is just the identity, so pass `[public_at_zeta]`.
    let public_input_chunks = [parsed_prev.public_evals.zeta];

    // ---- run expand_deferred -------------------------------------------
    let expanded = expand_deferred::<Fp>(ExpandDeferredInput {
        plonk_minimal: &stmt.proof_state.deferred_values.plonk,
        bulletproof_challenges: &stmt.proof_state.deferred_values.bulletproof_challenges,
        sponge_digest_before_evaluations: sponge_digest,
        evaluations: &parsed_prev.evaluations,
        public_evals: &parsed_prev.public_evals,
        ft_eval1: parsed_prev.ft_eval1,
        public_input_chunks: &public_input_chunks,
        old_bulletproof_challenges: &old_bp_chals,
        shifts,
        generator,
        domain_log2,
        zk_rows: ZK_ROWS,
        srs_length_log2: SRS_LENGTH_LOG2,
        endo: endo_r,
        linearization_endo_coefficient: endos::<o1_pickles_verifier::Pallas>().0,
        linearization_constant_term: &linearization.constant_term,
        domain,
        mds,
        sponge_params,
    })
    .expect("expand_deferred must succeed on a valid proof");

    // Sanity checks on the output shape.
    assert_eq!(expanded.new_bulletproof_challenges.len(), STEP_IPA_ROUNDS);

    // Cross-check: `expand_deferred`'s endo-expanded current-proof bp chals
    // should match the direct expansion used in Stage 2. (Both paths should
    // agree; if they don't, one of them is wrong.)
    let direct_chals: Vec<Fp> = stmt
        .proof_state
        .deferred_values
        .bulletproof_challenges
        .iter()
        .map(|bc| endo_expand_scalar(&bc.prechallenge, &endo_r))
        .collect();
    assert_eq!(
        expanded.new_bulletproof_challenges, direct_chals,
        "expand_deferred's bp challenge expansion disagrees with direct endo_expand"
    );

    // And re-run Stage 2 using the output of Stage 1: still passes.
    let srs: SRS<Vesta> = SRS::create_parallel(1 << STEP_IPA_ROUNDS);
    assert!(
        accumulator_check(
            &expanded.new_bulletproof_challenges,
            stmt.proof_state
                .messages_for_next_wrap_proof
                .challenge_polynomial_commitment,
            &srs,
        ),
        "accumulator check failed when fed expand_deferred's output"
    );
}
