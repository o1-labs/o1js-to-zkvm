//! Produce the inputs kimchi needs to verify a wrap proof from a
//! parsed [`crate::statement::WrapStatement`].
//!
//! Kimchi's `verify` takes three pieces:
//! 1. The kimchi `ProverProof` — for our wrap proof, this needs its
//!    `prev_challenges` field populated from the statement
//!    ([`host_populate_prev_challenges`]).
//! 2. The 40-element `Vec<Fq>` public input
//!    ([`assemble_kimchi_public_input`]).
//! 3. A `VerifierIndex` (loaded by `o1-verifier-lib`).
//!
//! Producing (2) requires the deferred-values expansion pipeline
//! (Polish-token interpreter, `derive_plonk`, `combined_inner_product`,
//! `compute_bp_chals_and_b`) plus two Poseidon digests over the
//! "messages-for-next-*" records carried in the statement. The host
//! runs the expensive Polish-token interpreter once (in std-land) via
//! [`host_precompute`], producing a [`HostPrecomputed`] that the SP1
//! guest plugs into [`assemble_kimchi_public_input`]. The
//! `app_state`-binding step-side digest is the only Poseidon that
//! must run inside the zkVM, so it stays inside
//! `assemble_kimchi_public_input`.
//!
//! The submodules ([`deferred`], [`messages`], [`pack`],
//! [`prev_challenges`]) are private — only the orchestrators below
//! are exposed.

extern crate alloc;

use alloc::vec::Vec;

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};
use kimchi::circuits::polynomials::permutation::Shifts;
use kimchi::linearization::expr_linearization;
use kimchi::proof::RecursionChallenge;
use mina_poseidon::pasta::fp_kimchi;
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::endos;
use serde::{Deserialize, Serialize};

use o1_verifier_lib::PallasProof;

use crate::parse::ParsedPrevEvals;
use crate::statement::{Challenge, ScalarChallenge, WrapStatement};
use crate::{Fp, Fq, Pallas, Vesta};

mod deferred;
mod messages;
mod pack;
mod prev_challenges;

pub use messages::WrapVkCommitments;
pub use prev_challenges::compute_dummy_wrap_sg;

const ZK_ROWS: u32 = 3;

/// Output of `expand_deferred` plus the wrap-side messages digest, as
/// the host hands them to the guest. Every value here is also derived
/// internally by the wrap circuit, so the guest doesn't need to verify
/// them — kimchi rejection catches any lie.
#[derive(Serialize, Deserialize)]
pub struct HostPrecomputed {
    /// Unshifted `combined_inner_product` from `expand_deferred`.
    #[serde(with = "crate::serde_compat::ark")]
    pub combined_inner_product: Fp,
    /// Unshifted `b` (challenge polynomial evaluated at zeta).
    #[serde(with = "crate::serde_compat::ark")]
    pub b: Fp,
    /// Unshifted permutation scalar.
    #[serde(with = "crate::serde_compat::ark")]
    pub perm: Fp,
    /// Unshifted `zeta^domain_size`.
    #[serde(with = "crate::serde_compat::ark")]
    pub zeta_to_domain_size: Fp,
    /// Unshifted `zeta^(2^srs_length_log2)`.
    #[serde(with = "crate::serde_compat::ark")]
    pub zeta_to_srs_length: Fp,
    /// Raw 128-bit `xi` prechallenge (two u64 limbs).
    pub xi_limbs: [u64; 2],
    /// Wrap-side messages digest (Poseidon over Fq).
    #[serde(with = "crate::serde_compat::ark")]
    pub wrap_messages_digest_fq: Fq,
}

/// Run `expand_deferred` plus the wrap-side messages Poseidon on the
/// host, producing the [`HostPrecomputed`] blob the guest consumes.
pub fn host_precompute(stmt: &WrapStatement, prev: &ParsedPrevEvals) -> HostPrecomputed {
    let expanded = run_expand_deferred(stmt, prev);

    let (_endo_q_wrap, endo_r_wrap) = endos::<Pallas>();
    let wrap_old_bp_chals_expanded: Vec<[Fq; messages::WRAP_IPA_ROUNDS]> = stmt
        .proof_state
        .messages_for_next_wrap_proof
        .old_bulletproof_challenges
        .iter()
        .map(|inner| {
            core::array::from_fn(|i| {
                deferred::endo_expand_scalar(&inner[i].prechallenge, &endo_r_wrap)
            })
        })
        .collect();
    let wrap_messages_digest_fq = messages::hash_messages_for_next_wrap_proof(
        &stmt
            .proof_state
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment,
        &wrap_old_bp_chals_expanded,
    );

    HostPrecomputed {
        combined_inner_product: expanded.combined_inner_product,
        b: expanded.b,
        perm: expanded.plonk.perm.0,
        zeta_to_domain_size: expanded.plonk.zeta_to_domain_size.0,
        zeta_to_srs_length: expanded.plonk.zeta_to_srs_length.0,
        xi_limbs: expanded.xi_raw.inner.0,
        wrap_messages_digest_fq,
    }
}

/// Populate a wrap proof's `prev_challenges` from the statement, so
/// the host can ship the proof bytes with that field already filled
/// in. Mirrors `Wrap_hack.pad_accumulator`.
pub fn host_populate_prev_challenges(
    proof: &mut PallasProof,
    stmt: &WrapStatement,
    dummy_sg: Pallas,
) {
    proof.prev_challenges = build_prev_challenges(stmt, dummy_sg);
}

/// Produce the 40-element `Vec<Fq>` kimchi public input for a wrap
/// proof. Combines the statement's raw challenges, the host-supplied
/// expanded values + wrap-side messages digest, and the in-zkVM
/// step-side messages digest (Poseidon over `app_state` — the binding
/// hop that must stay in the guest).
pub fn assemble_kimchi_public_input(
    stmt: &WrapStatement,
    vk: &WrapVkCommitments,
    precomputed: &HostPrecomputed,
) -> Vec<Fq> {
    let (_endo_q_step, endo_r_step) = endos::<Vesta>();
    let sponge_digest_fp = stmt.proof_state.sponge_digest_before_evaluations.to_fp();

    let step_prev_proofs: Vec<messages::StepPrevProof> = stmt
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .iter()
        .zip(
            stmt.messages_for_next_step_proof
                .old_bulletproof_challenges
                .iter(),
        )
        .map(|(comm, chals)| {
            let expanded_chals: [Fp; messages::STEP_IPA_ROUNDS] = core::array::from_fn(|i| {
                deferred::endo_expand_scalar(&chals[i].prechallenge, &endo_r_step)
            });
            messages::StepPrevProof {
                challenge_polynomial_commitment: *comm,
                expanded_bulletproof_challenges: expanded_chals,
            }
        })
        .collect();
    let step_messages_digest_fp = messages::hash_messages_for_next_step_proof(
        vk,
        &stmt.messages_for_next_step_proof.app_state,
        &step_prev_proofs,
    );

    let xi_sc = ScalarChallenge {
        inner: Challenge(precomputed.xi_limbs),
    };
    let plonk_min = &stmt.proof_state.deferred_values.plonk;

    pack::assemble_wrap_main_input(pack::AssembleInput {
        combined_inner_product: precomputed.combined_inner_product,
        b: precomputed.b,
        perm: precomputed.perm,
        zeta_to_domain_size: precomputed.zeta_to_domain_size,
        zeta_to_srs_length: precomputed.zeta_to_srs_length,
        beta: &plonk_min.beta,
        gamma: &plonk_min.gamma,
        alpha: &plonk_min.alpha.inner,
        zeta: &plonk_min.zeta.inner,
        xi: &xi_sc.inner,
        sponge_digest_fp,
        messages_for_next_step_digest_fp: step_messages_digest_fp,
        messages_for_next_wrap_digest_fq: precomputed.wrap_messages_digest_fq,
        bulletproof_challenges: &stmt.proof_state.deferred_values.bulletproof_challenges,
        branch_data: &stmt.proof_state.deferred_values.branch_data,
        feature_flags: [false; 8],
    })
    .to_fq_vec()
}

fn run_expand_deferred(
    stmt: &WrapStatement,
    prev: &ParsedPrevEvals,
) -> deferred::ExpandedDeferred<Fp> {
    let domain_log2: u32 = u32::from(stmt.proof_state.deferred_values.branch_data.domain_log2);
    let (_endo_q_step, endo_r_step) = endos::<Vesta>();

    let sponge_params_step = fp_kimchi::static_params();
    let mds_step = &sponge_params_step.mds;
    let domain: Radix2EvaluationDomain<Fp> =
        Radix2EvaluationDomain::new(1 << domain_log2).expect("step domain build");
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
                .map(|bc| deferred::endo_expand_scalar(&bc.prechallenge, &endo_r_step))
                .collect()
        })
        .collect();

    let sponge_digest_fp = stmt.proof_state.sponge_digest_before_evaluations.to_fp();
    let public_input_chunks = [prev.public_evals.zeta];

    deferred::expand_deferred::<Fp>(deferred::ExpandDeferredInput {
        plonk_minimal: &stmt.proof_state.deferred_values.plonk,
        bulletproof_challenges: &stmt.proof_state.deferred_values.bulletproof_challenges,
        sponge_digest_before_evaluations: sponge_digest_fp,
        evaluations: &prev.evaluations,
        public_evals: &prev.public_evals,
        ft_eval1: prev.ft_eval1,
        public_input_chunks: &public_input_chunks,
        old_bulletproof_challenges: &old_bp_chals_step,
        shifts,
        generator,
        domain_log2,
        zk_rows: ZK_ROWS,
        srs_length_log2: messages::STEP_IPA_ROUNDS as u32,
        endo: endo_r_step,
        linearization_endo_coefficient: endos::<Pallas>().0,
        linearization_constant_term: &linearization.constant_term,
        domain,
        mds: mds_step,
        sponge_params: sponge_params_step,
    })
    .expect("expand_deferred")
}

fn build_prev_challenges(
    stmt: &WrapStatement,
    dummy_sg: Pallas,
) -> Vec<RecursionChallenge<Pallas>> {
    debug_assert_eq!(
        stmt.messages_for_next_step_proof
            .challenge_polynomial_commitments
            .len(),
        1
    );
    let real_sg = stmt
        .messages_for_next_step_proof
        .challenge_polynomial_commitments[0];
    let real_limbs: [[u64; 2]; messages::WRAP_IPA_ROUNDS] = core::array::from_fn(|i| {
        stmt.proof_state
            .messages_for_next_wrap_proof
            .old_bulletproof_challenges[0][i]
            .prechallenge
            .inner
            .0
    });
    let pairs = prev_challenges::build_prev_challenges_max_one(dummy_sg, real_sg, real_limbs);
    pairs
        .into_iter()
        .map(|(sg, chals)| RecursionChallenge {
            comm: PolyComm {
                chunks: alloc::vec![sg],
            },
            chals: chals.to_vec(),
        })
        .collect()
}
