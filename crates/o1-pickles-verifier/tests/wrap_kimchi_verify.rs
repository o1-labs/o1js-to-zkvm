//! Stage 3 end-to-end: parse statement + prev_evals, compute deferred
//! values + digests, pack, hand the packed `Vec<Fq>` to kimchi's wrap
//! verifier with the Simple_chain wrap proof + VI fixtures, assert
//! kimchi accepts.
//!
//! `prev_challenges` for the wrap kimchi proof is built in Rust from
//! `(dummy_sg, dummy_chals)` plus the real step-side sg + endo-expanded
//! IPA prechallenges from the statement (mirroring OCaml
//! `Wrap_hack.pad_accumulator`). The msgpack `wrap_proof_b{N}.bin`
//! fixtures carry empty `prev_challenges` — simple_chain emits
//! `[] [||]` — and we always overwrite with the Rust-built version.
//!
//! Per-iteration fixtures: `simple_chain_proof_repr_b{N}.json` +
//! `simple_chain_wrap_proof_b{N}.bin`. Wrap VI/SRS shared. Test runs
//! across the full chain b0..b3 to exercise both base-descended (b0,
//! whose prior step is itself a dummy) and recursive (b1..b3) cases.

#![cfg(feature = "std")]

use ark_ff::{BigInt, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use groupmap::GroupMap;
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};
use kimchi::circuits::polynomials::permutation::Shifts;
use kimchi::linearization::expr_linearization;
use kimchi::proof::RecursionChallenge;
use mina_poseidon::pasta::fp_kimchi;
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::{endos, SRS};

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::deferred::{endo_expand_scalar, expand_deferred, ExpandDeferredInput};
use o1_pickles_verifier::messages::{
    build_simple_chain_prev_challenges, compute_dummy_wrap_sg, hash_messages_for_next_step_proof,
    hash_messages_for_next_wrap_proof, StepPrevProof, WrapVkCommitments, STEP_IPA_ROUNDS,
    WRAP_IPA_ROUNDS,
};
use o1_pickles_verifier::pack::{assemble_wrap_main_input, AssembleInput};
use o1_pickles_verifier::parse::{parse_prev_evals, parse_wrap_statement};
use o1_pickles_verifier::statement::{Digest, WrapStatement};
use o1_pickles_verifier::wire::ProofReprWire;
use o1_pickles_verifier::{Fp, Fq, Pallas, Vesta};
use o1_verifier_lib::{load_pallas_verifier_index, PallasProof};

const WRAP_VI: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_vi.bin");
const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");

const PROOF_REPR_B0: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");
const WRAP_PROOF_B0: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b0.bin");
const PROOF_REPR_B1: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b1.json");
const WRAP_PROOF_B1: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b1.bin");
const PROOF_REPR_B2: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b2.json");
const WRAP_PROOF_B2: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b2.bin");
const PROOF_REPR_B3: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b3.json");
const WRAP_PROOF_B3: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof_b3.bin");

fn digest_to_fp(d: &Digest) -> Fp {
    let bi: BigInt<4> = BigInt::new(d.0);
    Fp::from_bigint(bi).expect("sponge digest fits in Fp")
}

fn first_chunk(c: &PolyComm<Pallas>) -> Pallas {
    assert_eq!(c.chunks.len(), 1, "expected single-chunk commitment");
    c.chunks[0]
}

fn extract_vk_commitments(
    vi: &kimchi::verifier_index::VerifierIndex<55, Pallas, SRS<Pallas>>,
) -> WrapVkCommitments {
    WrapVkCommitments {
        sigma_comm: core::array::from_fn(|i| first_chunk(&vi.sigma_comm[i])),
        coefficients_comm: core::array::from_fn(|i| first_chunk(&vi.coefficients_comm[i])),
        generic_comm: first_chunk(&vi.generic_comm),
        psm_comm: first_chunk(&vi.psm_comm),
        complete_add_comm: first_chunk(&vi.complete_add_comm),
        mul_comm: first_chunk(&vi.mul_comm),
        emul_comm: first_chunk(&vi.emul_comm),
        endomul_scalar_comm: first_chunk(&vi.endomul_scalar_comm),
    }
}

fn build_prev_challenges_rust(
    stmt: &WrapStatement,
    dummy_sg: Pallas,
) -> Vec<RecursionChallenge<Pallas>> {
    assert_eq!(
        stmt.messages_for_next_step_proof
            .challenge_polynomial_commitments
            .len(),
        1,
        "Simple_chain mlmb=N1"
    );
    assert_eq!(
        stmt.proof_state
            .messages_for_next_wrap_proof
            .old_bulletproof_challenges
            .len(),
        1
    );
    let real_sg = stmt
        .messages_for_next_step_proof
        .challenge_polynomial_commitments[0];
    let real_limbs: [[u64; 2]; WRAP_IPA_ROUNDS] = core::array::from_fn(|i| {
        stmt.proof_state
            .messages_for_next_wrap_proof
            .old_bulletproof_challenges[0][i]
            .prechallenge
            .inner
            .0
    });
    let pairs = build_simple_chain_prev_challenges(dummy_sg, real_sg, real_limbs);
    pairs
        .into_iter()
        .map(|(sg, chals)| RecursionChallenge {
            comm: PolyComm { chunks: vec![sg] },
            chals: chals.to_vec(),
        })
        .collect()
}

fn run_iteration(iter_label: &str, proof_repr_json: &str, wrap_proof_bytes: &[u8]) {
    let wrap_vi = load_pallas_verifier_index(WRAP_VI, WRAP_SRS);
    let srs_pallas: SRS<Pallas> = rmp_serde::from_slice(WRAP_SRS).expect("parse Pallas SRS");
    let dummy_sg = compute_dummy_wrap_sg(&srs_pallas);

    let repr: ProofReprWire =
        serde_json::from_str(proof_repr_json).expect("failed to deserialize proof repr JSON");
    let stmt = parse_wrap_statement(repr.statement).expect("parse statement");
    let parsed_prev = parse_prev_evals(repr.prev_evals).expect("parse prev_evals");

    let mut wrap_proof: PallasProof =
        rmp_serde::from_slice(wrap_proof_bytes).expect("parse wrap proof");
    assert_eq!(wrap_proof.proof.lr.len(), 15);
    assert_eq!(wrap_vi.public, 40, "wrap public-input length is 40");

    wrap_proof.prev_challenges = build_prev_challenges_rust(&stmt, dummy_sg);

    let domain_log2: u32 = u32::from(stmt.proof_state.deferred_values.branch_data.domain_log2);
    let (_endo_q_step, endo_r_step) = endos::<Vesta>();
    let (_endo_q_wrap, endo_r_wrap) = endos::<Pallas>();

    let sponge_params_step = fp_kimchi::static_params();
    let mds_step = &sponge_params_step.mds;
    let domain: Radix2EvaluationDomain<Fp> =
        Radix2EvaluationDomain::new(1 << domain_log2).expect("step domain");
    let generator = domain.group_gen;
    let shifts: [Fp; 7] = *Shifts::<Fp>::new(&domain).shifts();

    let (linearization, _) = expr_linearization::<Fp>(
        Some(&FeatureFlags {
            range_check0: false,
            range_check1: false,
            foreign_field_add: false,
            foreign_field_mul: false,
            xor: false,
            rot: false,
            lookup_features: LookupFeatures {
                patterns: LookupPatterns {
                    xor: false,
                    lookup: false,
                    range_check: false,
                    foreign_field_mul: false,
                },
                joint_lookup_used: false,
                uses_runtime_tables: false,
            },
        }),
        true,
    );

    let old_bp_chals_step: Vec<Vec<Fp>> = stmt
        .messages_for_next_step_proof
        .old_bulletproof_challenges
        .iter()
        .map(|inner| {
            inner
                .iter()
                .map(|bc| endo_expand_scalar(&bc.prechallenge, &endo_r_step))
                .collect()
        })
        .collect();

    let sponge_digest_fp = digest_to_fp(&stmt.proof_state.sponge_digest_before_evaluations);
    let public_input_chunks = [parsed_prev.public_evals.zeta];

    let expanded = expand_deferred::<Fp>(ExpandDeferredInput {
        plonk_minimal: &stmt.proof_state.deferred_values.plonk,
        bulletproof_challenges: &stmt.proof_state.deferred_values.bulletproof_challenges,
        sponge_digest_before_evaluations: sponge_digest_fp,
        evaluations: &parsed_prev.evaluations,
        public_evals: &parsed_prev.public_evals,
        ft_eval1: parsed_prev.ft_eval1,
        public_input_chunks: &public_input_chunks,
        old_bulletproof_challenges: &old_bp_chals_step,
        shifts,
        generator,
        domain_log2,
        zk_rows: 3,
        srs_length_log2: STEP_IPA_ROUNDS as u32,
        endo: endo_r_step,
        linearization_endo_coefficient: endos::<Pallas>().0,
        linearization_constant_term: &linearization.constant_term,
        domain,
        mds: mds_step,
        sponge_params: sponge_params_step,
    })
    .expect("expand_deferred");

    let vk_commitments = extract_vk_commitments(&wrap_vi);
    let step_prev_proofs: Vec<StepPrevProof> = stmt
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .iter()
        .zip(
            stmt.messages_for_next_step_proof
                .old_bulletproof_challenges
                .iter(),
        )
        .map(|(comm, chals)| {
            let expanded_chals: [Fp; STEP_IPA_ROUNDS] =
                core::array::from_fn(|i| endo_expand_scalar(&chals[i].prechallenge, &endo_r_step));
            StepPrevProof {
                challenge_polynomial_commitment: *comm,
                expanded_bulletproof_challenges: expanded_chals,
            }
        })
        .collect();
    let step_messages_digest_fp = hash_messages_for_next_step_proof(
        &vk_commitments,
        &stmt.messages_for_next_step_proof.app_state,
        &step_prev_proofs,
    );

    let wrap_old_bp_chals_expanded: Vec<[Fq; WRAP_IPA_ROUNDS]> = stmt
        .proof_state
        .messages_for_next_wrap_proof
        .old_bulletproof_challenges
        .iter()
        .map(|inner| {
            core::array::from_fn(|i| endo_expand_scalar(&inner[i].prechallenge, &endo_r_wrap))
        })
        .collect();
    let wrap_messages_digest_fq = hash_messages_for_next_wrap_proof(
        &stmt
            .proof_state
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment,
        &wrap_old_bp_chals_expanded,
    );

    let plonk_min = &stmt.proof_state.deferred_values.plonk;
    let packed_struct = assemble_wrap_main_input(AssembleInput {
        combined_inner_product: expanded.combined_inner_product,
        b: expanded.b,
        perm: expanded.plonk.perm.0,
        zeta_to_domain_size: expanded.plonk.zeta_to_domain_size.0,
        zeta_to_srs_length: expanded.plonk.zeta_to_srs_length.0,
        beta: &plonk_min.beta,
        gamma: &plonk_min.gamma,
        alpha: &plonk_min.alpha.inner,
        zeta: &plonk_min.zeta.inner,
        xi: &expanded.xi_raw.inner,
        sponge_digest_fp,
        messages_for_next_step_digest_fp: step_messages_digest_fp,
        messages_for_next_wrap_digest_fq: wrap_messages_digest_fq,
        bulletproof_challenges: &stmt.proof_state.deferred_values.bulletproof_challenges,
        branch_data: &stmt.proof_state.deferred_values.branch_data,
        feature_flags: [false; 8],
    });
    let packed: Vec<Fq> = packed_struct.to_fq_vec();
    assert_eq!(packed.len(), 40);

    let srs_vesta: SRS<Vesta> = SRS::create_parallel(1 << STEP_IPA_ROUNDS);
    assert!(
        accumulator_check(
            &expanded.new_bulletproof_challenges,
            stmt.proof_state
                .messages_for_next_wrap_proof
                .challenge_polynomial_commitment,
            &srs_vesta,
        ),
        "[{}] Stage 2 accumulator check failed (bug upstream of packing)",
        iter_label
    );

    let group_map = <Pallas as poly_commitment::commitment::CommitmentCurve>::Map::setup();
    let result = kimchi::verifier::verify::<
        55,
        Pallas,
        mina_poseidon::sponge::DefaultFqSponge<
            mina_curves::pasta::PallasParameters,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            55,
        >,
        mina_poseidon::sponge::DefaultFrSponge<
            Fq,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            55,
        >,
        poly_commitment::ipa::OpeningProof<Pallas, 55>,
    >(&group_map, &wrap_vi, &wrap_proof, &packed);
    assert!(
        result.is_ok(),
        "[{}] kimchi rejected the Rust-packed wrap proof: {:?}",
        iter_label,
        result
    );
}

#[test]
fn b0_wrap_proof_verifies_via_rust_packing() {
    run_iteration("b0", PROOF_REPR_B0, WRAP_PROOF_B0);
}

#[test]
fn b1_wrap_proof_verifies_via_rust_packing() {
    run_iteration("b1", PROOF_REPR_B1, WRAP_PROOF_B1);
}

#[test]
fn b2_wrap_proof_verifies_via_rust_packing() {
    run_iteration("b2", PROOF_REPR_B2, WRAP_PROOF_B2);
}

#[test]
fn b3_wrap_proof_verifies_via_rust_packing() {
    run_iteration("b3", PROOF_REPR_B3, WRAP_PROOF_B3);
}
