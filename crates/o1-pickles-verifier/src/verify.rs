//! End-to-end Simple_chain wrap-proof verification pipeline, packaged
//! for invocation from a constrained no_std environment (the SP1 zkVM
//! guest). All inputs are msgpack-encoded byte slices:
//!
//! * `wrap_vi_bytes` / `wrap_srs_bytes` — the wrap-circuit Pallas
//!   `VerifierIndex` and its `SRS<Pallas>`. Build into the guest via
//!   `include_bytes!`.
//! * `proof_repr_msgpack` — `ProofReprWire` round-tripped through
//!   rmp-serde. The host reads the OCaml-emitted JSON, decodes via
//!   `serde_json::from_str::<ProofReprWire>`, then re-encodes via
//!   `rmp_serde::to_vec` for the guest. Avoids JSON parsing inside
//!   the zkVM.
//! * `wrap_proof_bytes` — kimchi `ProverProof` msgpack as emitted by
//!   `simple_chain.exe`'s `caml_pasta_fq_plonk_proof_write`. The
//!   `prev_challenges` field is empty in this format; we override it
//!   with one constructed from the statement plus
//!   `Wrap_hack.pad_accumulator`'s dummy front-pad.
//!
//! Returns `Ok(())` if kimchi accepts the wrap proof against the
//! Rust-packed public input, else `Err` with a short tag.
//!
//! No accumulator-check (`SRS<Vesta>` reconstruction would dominate
//! cycles); the host can run that separately if needed.
//!
//! Linearization is constructed inline against the `none_bool` feature
//! flags Simple_chain uses. If a future caller needs different flags,
//! lift this to an input.

extern crate alloc;

use alloc::vec::Vec;

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

use o1_verifier_lib::{load_pallas_verifier_index, PallasProof};

use crate::deferred::{endo_expand_scalar, expand_deferred, ExpandDeferredInput};
use crate::messages::{
    build_simple_chain_prev_challenges, compute_dummy_wrap_sg, hash_messages_for_next_step_proof,
    hash_messages_for_next_wrap_proof, StepPrevProof, WrapVkCommitments, STEP_IPA_ROUNDS,
    WRAP_IPA_ROUNDS,
};
use crate::pack::{assemble_wrap_main_input, AssembleInput};
use crate::parse::{parse_prev_evals, parse_wrap_statement};
use crate::statement::{Digest, WrapStatement};
use crate::wire::ProofReprWire;
use crate::{Fp, Fq, Pallas, Vesta};

#[derive(Debug)]
pub enum VerifyError {
    DecodeProofRepr,
    DecodeWrapProof,
    DecodePallasSrs,
    LowerStatement,
    LowerPrevEvals,
    BuildDomain,
    ExpandDeferred,
    KimchiReject,
}

fn digest_to_fp(d: &Digest) -> Fp {
    let bi: BigInt<4> = BigInt::new(d.0);
    Fp::from_bigint(bi).expect("sponge digest fits in Fp")
}

fn first_chunk(c: &PolyComm<Pallas>) -> Pallas {
    debug_assert_eq!(c.chunks.len(), 1);
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
            comm: PolyComm {
                chunks: alloc::vec![sg],
            },
            chals: chals.to_vec(),
        })
        .collect()
}

/// Run the full Stage 3 pipeline against one Simple_chain wrap proof
/// and return whether kimchi accepts.
pub fn verify_wrap_proof(
    wrap_vi_bytes: &[u8],
    wrap_srs_bytes: &[u8],
    proof_repr_msgpack: &[u8],
    wrap_proof_bytes: &[u8],
) -> Result<(), VerifyError> {
    let repr: ProofReprWire =
        rmp_serde::from_slice(proof_repr_msgpack).map_err(|_| VerifyError::DecodeProofRepr)?;
    let stmt = parse_wrap_statement(repr.statement).map_err(|_| VerifyError::LowerStatement)?;
    let parsed_prev = parse_prev_evals(repr.prev_evals).map_err(|_| VerifyError::LowerPrevEvals)?;

    let wrap_vi = load_pallas_verifier_index(wrap_vi_bytes, wrap_srs_bytes);
    let srs_pallas: SRS<Pallas> =
        rmp_serde::from_slice(wrap_srs_bytes).map_err(|_| VerifyError::DecodePallasSrs)?;
    let dummy_sg = compute_dummy_wrap_sg(&srs_pallas);

    let mut wrap_proof: PallasProof =
        rmp_serde::from_slice(wrap_proof_bytes).map_err(|_| VerifyError::DecodeWrapProof)?;
    wrap_proof.prev_challenges = build_prev_challenges(&stmt, dummy_sg);

    let domain_log2: u32 = u32::from(stmt.proof_state.deferred_values.branch_data.domain_log2);
    let (_endo_q_step, endo_r_step) = endos::<Vesta>();
    let (_endo_q_wrap, endo_r_wrap) = endos::<Pallas>();

    let sponge_params_step = fp_kimchi::static_params();
    let mds_step = &sponge_params_step.mds;
    let domain: Radix2EvaluationDomain<Fp> =
        Radix2EvaluationDomain::new(1 << domain_log2).ok_or(VerifyError::BuildDomain)?;
    let generator = domain.group_gen;
    let shifts: [Fp; 7] = *Shifts::<Fp>::new(&domain).shifts();

    // Simple_chain uses Plonk_types.Features.none_bool — every
    // optional gate disabled, no lookups.
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
    .map_err(|_| VerifyError::ExpandDeferred)?;

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

    let group_map = <Pallas as poly_commitment::commitment::CommitmentCurve>::Map::setup();
    kimchi::verifier::verify::<
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
    >(&group_map, &wrap_vi, &wrap_proof, &packed)
    .map_err(|_| VerifyError::KimchiReject)?;
    Ok(())
}
