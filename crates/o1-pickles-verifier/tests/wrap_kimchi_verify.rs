//! Stage 3 end-to-end: parse statement + prev_evals, compute deferred
//! values + digests, pack, hand the packed `Vec<Fq>` to kimchi's wrap
//! verifier with the Simple_chain wrap proof + VI fixtures, assert
//! kimchi accepts.
//!
//! If kimchi rejects, every component upstream is suspect: `expand_deferred`,
//! `hash_messages_*`, or any leaf encoder in `pack`. The accumulator-check
//! and lib-test suites already cover most leaves; a kimchi reject here
//! most likely points at field ordering inside `WrapStatementPacked` or
//! a cross-field encoding edge case.

#![cfg(feature = "std")]

use std::str::FromStr;

use ark_ff::BigInt;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use groupmap::GroupMap;
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};
use kimchi::circuits::polynomials::permutation::Shifts;
use kimchi::linearization::expr_linearization;
use mina_poseidon::pasta::fp_kimchi;
use poly_commitment::ipa::endos;

use o1_pickles_verifier::accumulator::accumulator_check;
use o1_pickles_verifier::deferred::{endo_expand_scalar, expand_deferred, ExpandDeferredInput};
use o1_pickles_verifier::messages::{
    hash_messages_for_next_step_proof, hash_messages_for_next_wrap_proof, StepPrevProof,
    WrapVkCommitments, STEP_IPA_ROUNDS, WRAP_IPA_ROUNDS,
};
use o1_pickles_verifier::pack::{assemble_wrap_main_input, AssembleInput};
use o1_pickles_verifier::parse::{parse_prev_evals, parse_wrap_statement};
use o1_pickles_verifier::statement::Digest;
use o1_pickles_verifier::wire::ProofReprWire;
use o1_pickles_verifier::{Fp, Fq, Pallas, Vesta};
use o1_verifier_lib::{load_pallas_verifier_index, verify_pallas_kimchi_proof, PallasProof};
use poly_commitment::ipa::SRS;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr.json");
const WRAP_VI: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_vi.bin");
const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");
const WRAP_PROOF: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_proof.bin");
const PACKED_FIXTURE: &str = include_str!("../../../fixtures/simple_chain_wrap_public_input.json");

fn load_ocaml_packed_input() -> Vec<Fq> {
    let raw: Vec<String> = serde_json::from_str(PACKED_FIXTURE).expect("parse packed JSON");
    raw.into_iter()
        .map(|s| Fq::from_str(&s).expect("Fq decimal string"))
        .collect()
}

/// Pack a [`Digest`]'s 4 u64 limbs into Fp (mirrors OCaml
/// `Digest.Constant.to_tick_field`).
fn digest_to_fp(d: &Digest) -> Fp {
    let bi: BigInt<4> = BigInt::new(d.0);
    Fp::from_bigint(bi).expect("sponge digest fits in Fp")
}

/// Take the first chunk of a non-chunked `PolyComm`. Wrap-side commitments
/// in pickles are single-chunk for Simple_chain.
fn first_chunk(c: &poly_commitment::commitment::PolyComm<Pallas>) -> Pallas {
    assert_eq!(c.chunks.len(), 1, "expected single-chunk commitment");
    c.chunks[0]
}

/// Extract the 28 wrap VK commitments in pickles `index_to_field_elements`
/// order. Ports OCaml `Plonk_verification_key_evals.map ~f:(fun x -> [|x|])
/// key.commitments` for Simple_chain (all single-chunk).
fn extract_vk_commitments(
    vi: &kimchi::verifier_index::VerifierIndex<55, Pallas, SRS<Pallas>>,
) -> WrapVkCommitments {
    let sigma_comm: [Pallas; 7] = core::array::from_fn(|i| first_chunk(&vi.sigma_comm[i]));
    let coefficients_comm: [Pallas; 15] =
        core::array::from_fn(|i| first_chunk(&vi.coefficients_comm[i]));
    WrapVkCommitments {
        sigma_comm,
        coefficients_comm,
        generic_comm: first_chunk(&vi.generic_comm),
        psm_comm: first_chunk(&vi.psm_comm),
        complete_add_comm: first_chunk(&vi.complete_add_comm),
        mul_comm: first_chunk(&vi.mul_comm),
        emul_comm: first_chunk(&vi.emul_comm),
        endomul_scalar_comm: first_chunk(&vi.endomul_scalar_comm),
    }
}

#[test]
fn simple_chain_wrap_proof_verifies_via_rust_packing() {
    // ---- 1. Parse fixtures ------------------------------------------------
    let repr: ProofReprWire =
        serde_json::from_str(FIXTURE).expect("failed to deserialize proof repr JSON");
    let stmt = parse_wrap_statement(repr.statement).expect("parse statement");
    let parsed_prev = parse_prev_evals(repr.prev_evals).expect("parse prev_evals");

    let wrap_vi = load_pallas_verifier_index(WRAP_VI, WRAP_SRS);
    let wrap_proof: PallasProof = rmp_serde::from_slice(WRAP_PROOF).expect("parse wrap proof");

    // Sanity on the parsed proof shape.
    assert_eq!(wrap_proof.prev_challenges.len(), 2);
    assert_eq!(wrap_proof.proof.lr.len(), 15);
    assert_eq!(wrap_vi.public, 40, "wrap public-input length is 40");

    // Diagnostic: compare slot-0 of prev_challenges (= dummy) to our computed
    // dummy_ipa_wrap_challenges_expanded.
    let our_dummy = o1_pickles_verifier::messages::dummy_ipa_wrap_challenges_expanded();
    let proof_slot0_chals = &wrap_proof.prev_challenges[0].chals;
    let mut dummy_mismatches = 0usize;
    for i in 0..15 {
        if our_dummy[i] != proof_slot0_chals[i] {
            dummy_mismatches += 1;
            if dummy_mismatches <= 3 {
                eprintln!(
                    "  dummy chal[{}]: ours = {}, proof = {}",
                    i, our_dummy[i], proof_slot0_chals[i]
                );
            }
        }
    }
    eprintln!(
        "dummy_ipa_wrap_challenges mismatches: {}/15",
        dummy_mismatches
    );

    // ---- 2. Step-side constants for expand_deferred ----------------------
    let domain_log2: u32 = u32::from(stmt.proof_state.deferred_values.branch_data.domain_log2);
    let (_endo_q_step, endo_r_step) = endos::<Vesta>(); // step-field endo (Fp)
    let (_endo_q_wrap, endo_r_wrap) = endos::<Pallas>(); // wrap-field endo (Fq)

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

    // ---- 3. expand_deferred ----------------------------------------------
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

    // ---- 4. step-messages digest -----------------------------------------
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

    // ---- 5. wrap-messages digest -----------------------------------------
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

    // ---- 6. assemble + flatten -------------------------------------------
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

    // Sanity: Stage 2 still passes when fed expand_deferred's bp chals.
    let srs: SRS<Vesta> = SRS::create_parallel(1 << STEP_IPA_ROUNDS);
    assert!(
        accumulator_check(
            &expanded.new_bulletproof_challenges,
            stmt.proof_state
                .messages_for_next_wrap_proof
                .challenge_polynomial_commitment,
            &srs,
        ),
        "Stage 2 accumulator check failed (bug upstream of packing)"
    );

    // ---- 7. slot-by-slot compare against OCaml golden fixture ------------
    let ocaml_packed = load_ocaml_packed_input();
    assert_eq!(ocaml_packed.len(), 40);
    let labels = [
        "fp_fields[0]=cip",
        "fp_fields[1]=b",
        "fp_fields[2]=zeta_to_srs_length",
        "fp_fields[3]=zeta_to_domain_size",
        "fp_fields[4]=perm",
        "challenges[0]=beta",
        "challenges[1]=gamma",
        "scalar_challenges[0]=alpha",
        "scalar_challenges[1]=zeta",
        "scalar_challenges[2]=xi",
        "digests[0]=sponge_digest",
        "digests[1]=msgs_for_next_wrap",
        "digests[2]=msgs_for_next_step",
        "bulletproof_challenges[0]",
        "bulletproof_challenges[1]",
        "bulletproof_challenges[2]",
        "bulletproof_challenges[3]",
        "bulletproof_challenges[4]",
        "bulletproof_challenges[5]",
        "bulletproof_challenges[6]",
        "bulletproof_challenges[7]",
        "bulletproof_challenges[8]",
        "bulletproof_challenges[9]",
        "bulletproof_challenges[10]",
        "bulletproof_challenges[11]",
        "bulletproof_challenges[12]",
        "bulletproof_challenges[13]",
        "bulletproof_challenges[14]",
        "bulletproof_challenges[15]",
        "branch_data",
        "feature_flags[0]",
        "feature_flags[1]",
        "feature_flags[2]",
        "feature_flags[3]",
        "feature_flags[4]",
        "feature_flags[5]",
        "feature_flags[6]",
        "feature_flags[7]",
        "lookup_opt_flag",
        "lookup_opt_scalar_challenge",
    ];
    let mut mismatches: Vec<String> = Vec::new();
    for i in 0..40 {
        if packed[i] != ocaml_packed[i] {
            mismatches.push(format!(
                "  slot {:>2} ({}): rust = {}, ocaml = {}",
                i, labels[i], packed[i], ocaml_packed[i]
            ));
        }
    }
    if !mismatches.is_empty() {
        // Sanity: kimchi accepts the OCaml-packed input — confirms fixtures
        // are good and isolates the failure to our packing code.
        let ocaml_accepted = verify_pallas_kimchi_proof(&wrap_vi, &wrap_proof, &ocaml_packed);
        let header = format!(
            "Rust-packed input differs from OCaml golden in {} slots (kimchi accepts OCaml packing: {}):\n{}",
            mismatches.len(), ocaml_accepted, mismatches.join("\n")
        );
        panic!("{}", header);
    }

    // ---- 8. kimchi wrap verify with Rust-packed input --------------------
    let group_map =
        <o1_pickles_verifier::Pallas as poly_commitment::commitment::CommitmentCurve>::Map::setup();
    let result = kimchi::verifier::verify::<
        55,
        o1_pickles_verifier::Pallas,
        mina_poseidon::sponge::DefaultFqSponge<
            mina_curves::pasta::PallasParameters,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            55,
        >,
        mina_poseidon::sponge::DefaultFrSponge<
            o1_pickles_verifier::Fq,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            55,
        >,
        poly_commitment::ipa::OpeningProof<o1_pickles_verifier::Pallas, 55>,
    >(&group_map, &wrap_vi, &wrap_proof, &packed);
    assert!(
        result.is_ok(),
        "kimchi rejected the Rust-packed wrap proof: {:?}",
        result
    );
    let _ = verify_pallas_kimchi_proof; // silence unused-import warning
}
