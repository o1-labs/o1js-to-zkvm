//! Compare every intermediate between our Rust pipeline (`expand_deferred`,
//! `hash_messages_*`, the `Shifted_value.Type1.of_field` shift) and the
//! OCaml-dumped golden values from `simple_chain_wrap_debug_intermediates.json`.
//!
//! This test runs in milliseconds (no kimchi verify, no SRS construction)
//! and gives per-component pass/fail signals — much easier to localize a
//! bug than the all-or-nothing kimchi-accept/reject in `wrap_kimchi_verify`.

#![cfg(feature = "std")]

use std::collections::HashMap;
use std::str::FromStr;

use ark_ff::BigInt;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};
use kimchi::circuits::polynomials::permutation::Shifts;
use kimchi::linearization::expr_linearization;
use mina_poseidon::pasta::fp_kimchi;
use poly_commitment::ipa::{endos, SRS};

use o1_pickles_verifier::deferred::{endo_expand_scalar, expand_deferred, ExpandDeferredInput};
use o1_pickles_verifier::messages::{
    hash_messages_for_next_step_proof, hash_messages_for_next_wrap_proof, StepPrevProof,
    WrapVkCommitments, STEP_IPA_ROUNDS, WRAP_IPA_ROUNDS,
};
use o1_pickles_verifier::pack::shifted_value_type1_of_field;
use o1_pickles_verifier::parse::{parse_prev_evals, parse_wrap_statement};
use o1_pickles_verifier::statement::Digest;
use o1_pickles_verifier::wire::ProofReprWire;
use o1_pickles_verifier::{Fp, Fq, Pallas, Vesta};
use o1_verifier_lib::load_pallas_verifier_index;

const FIXTURE: &str = include_str!("../../../fixtures/simple_chain_proof_repr.json");
const WRAP_VI: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_vi.bin");
const WRAP_SRS: &[u8] = include_bytes!("../../../fixtures/simple_chain_wrap_srs.bin");
const DEBUG: &str = include_str!("../../../fixtures/simple_chain_wrap_debug_intermediates.json");

fn digest_to_fp(d: &Digest) -> Fp {
    Fp::from_bigint(BigInt::<4>::new(d.0)).expect("digest fits in Fp")
}

fn first_chunk(c: &poly_commitment::commitment::PolyComm<Pallas>) -> Pallas {
    assert_eq!(c.chunks.len(), 1);
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

#[test]
fn rust_intermediates_match_ocaml_golden() {
    // ---- Parse fixtures ----
    let repr: ProofReprWire = serde_json::from_str(FIXTURE).expect("parse repr");
    let stmt = parse_wrap_statement(repr.statement).expect("parse statement");
    let parsed_prev = parse_prev_evals(repr.prev_evals).expect("parse prev_evals");
    let wrap_vi = load_pallas_verifier_index(WRAP_VI, WRAP_SRS);
    let golden: HashMap<String, String> = serde_json::from_str(DEBUG).expect("parse debug JSON");

    // ---- Domain constants ----
    let domain_log2: u32 = u32::from(stmt.proof_state.deferred_values.branch_data.domain_log2);
    let (_endo_q_step, endo_r_step) = endos::<Vesta>();
    let (_endo_q_wrap, endo_r_wrap) = endos::<Pallas>();
    let sponge_params_step = fp_kimchi::static_params();
    let mds_step = &sponge_params_step.mds;
    let domain: Radix2EvaluationDomain<Fp> =
        Radix2EvaluationDomain::new(1 << domain_log2).expect("domain");
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

    // ---- Run our expand_deferred ----
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

    // ---- Run our hash_messages_for_next_*_proof ----
    let vk_comms = extract_vk_commitments(&wrap_vi);
    let step_prev_proofs: Vec<StepPrevProof> = stmt
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .iter()
        .zip(
            stmt.messages_for_next_step_proof
                .old_bulletproof_challenges
                .iter(),
        )
        .map(|(comm, chals)| StepPrevProof {
            challenge_polynomial_commitment: *comm,
            expanded_bulletproof_challenges: core::array::from_fn(|i| {
                endo_expand_scalar(&chals[i].prechallenge, &endo_r_step)
            }),
        })
        .collect();
    let step_digest_rust = hash_messages_for_next_step_proof(
        &vk_comms,
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
    let wrap_digest_rust = hash_messages_for_next_wrap_proof(
        &stmt
            .proof_state
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment,
        &wrap_old_bp_chals_expanded,
    );

    // ---- Compare every intermediate ----
    let parse_fp = |s: &str| Fp::from_str(s).expect("Fp decimal");
    let parse_fq = |s: &str| Fq::from_str(s).expect("Fq decimal");

    // Apply our shift to expand_deferred's unshifted outputs.
    let cip_shifted_rust = shifted_value_type1_of_field::<Fp>(expanded.combined_inner_product);
    let b_shifted_rust = shifted_value_type1_of_field::<Fp>(expanded.b);
    let perm_shifted_rust = shifted_value_type1_of_field::<Fp>(expanded.plonk.perm.0);
    let zeta_to_domain_size_shifted_rust =
        shifted_value_type1_of_field::<Fp>(expanded.plonk.zeta_to_domain_size.0);
    let zeta_to_srs_length_shifted_rust =
        shifted_value_type1_of_field::<Fp>(expanded.plonk.zeta_to_srs_length.0);

    let fp_checks: [(&str, Fp); 7] = [
        ("cip_shifted_fp", cip_shifted_rust),
        ("b_shifted_fp", b_shifted_rust),
        ("perm_shifted_fp", perm_shifted_rust),
        (
            "zeta_to_domain_size_shifted_fp",
            zeta_to_domain_size_shifted_rust,
        ),
        (
            "zeta_to_srs_length_shifted_fp",
            zeta_to_srs_length_shifted_rust,
        ),
        ("step_messages_digest_fp", step_digest_rust),
        ("ft_eval0_fp", expanded.ft_eval0),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (key, ours) in fp_checks {
        let theirs = parse_fp(&golden[key]);
        if ours != theirs {
            failures.push(format!(
                "  {} (Fp):\n    rust   = {}\n    ocaml  = {}",
                key, ours, theirs
            ));
        }
    }
    let theirs_wrap = parse_fq(&golden["wrap_messages_digest_fq"]);
    if wrap_digest_rust != theirs_wrap {
        failures.push(format!(
            "  wrap_messages_digest_fq (Fq):\n    rust   = {}\n    ocaml  = {}",
            wrap_digest_rust, theirs_wrap
        ));
    }

    if !failures.is_empty() {
        panic!(
            "{} of 8 intermediates differ from OCaml golden:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
