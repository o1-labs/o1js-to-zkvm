//! Slim wrap-proof verification pipeline for the SP1 guest. The
//! expensive `expand_deferred` walk plus the wrap-side messages digest
//! live on the host (see [`host_precompute`]); the guest only does what
//! is load-bearing for binding `app_state`:
//!
//! 1. Hash the input statement bytes (so the end-verifier can
//!    recognize "this exact serialized statement was attested to").
//! 2. Compute `step_messages_digest_fp` over `app_state` + the baked
//!    `vk_commitments` + the prior step proof's accumulator data.
//!    This is the only piece that *must* stay in-zkVM, because it's
//!    what threads `app_state` into the kimchi public input.
//! 3. Pack the wrap public input using host-supplied `expanded` /
//!    `wrap_messages_digest_fq` values. Wrong values → kimchi rejects.
//! 4. `kimchi::verifier::verify`.
//! 5. Commit `(valid, app_state, statement_digest)`.
//!
//! Soundness note: the wrap circuit constrains every value in its
//! public input internally. So lying about any host-supplied piece
//! (cip, b, perm, zeta_to_*, wrap-side digest) makes the wrap circuit's
//! own `expand_deferred` re-derivation disagree with our packed input,
//! and kimchi rejects. The host can't forge anything kimchi accepts.
//!
//! See `docs/ARCHITECTURE.md` for the bigger picture.

extern crate alloc;

use alloc::vec::Vec;

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use groupmap::GroupMap;
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};
use kimchi::circuits::polynomials::permutation::Shifts;
use kimchi::linearization::expr_linearization;
use kimchi::proof::RecursionChallenge;
use mina_poseidon::pasta::{fp_kimchi, FULL_ROUNDS};
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::endos;
use sha2::{Digest as Sha2Digest, Sha256};

use o1_verifier_lib::{load_pallas_verifier_index, PallasProof};
use serde::{Deserialize, Serialize};

use crate::deferred::{endo_expand_scalar, expand_deferred, ExpandDeferredInput};
use crate::messages::{
    build_prev_challenges_max_one, hash_messages_for_next_step_proof,
    hash_messages_for_next_wrap_proof, StepPrevProof, WrapVkCommitments, STEP_IPA_ROUNDS,
    WRAP_IPA_ROUNDS,
};
use crate::pack::{assemble_wrap_main_input, AssembleInput};
use crate::parse::{parse_proof_repr_msgpack, ParsedPrevEvals};
use crate::statement::{Challenge, ScalarChallenge, WrapStatement};
use crate::{Fp, Fq, Pallas, Vesta};

#[derive(Debug)]
pub enum VerifyError {
    DecodeProofRepr,
    KimchiReject,
}

/// What the SP1 guest commits as its public output:
///
/// * `valid`: whether kimchi accepted.
/// * `app_state`: the application circuit's public input as a flat
///   `Vec<Fp>`. Bound into the wrap public input via Poseidon, so a
///   kimchi-accepted run means the guest's `app_state` matches what
///   the wrap circuit was committed against.
/// * `statement_digest`: SHA-256 over the statement msgpack bytes the
///   guest was fed. Lets a holder of the original serialized statement
///   verify "the SP1 proof attests to *my* statement, not just one
///   with matching `app_state`."
///
/// Both `valid=false` and decode failures yield empty `app_state`
/// and a zero `statement_digest`.
#[derive(Serialize, Deserialize)]
pub struct CommitOutput {
    pub valid: bool,
    #[serde(with = "crate::serde_compat::ark")]
    pub app_state: Vec<Fp>,
    pub statement_digest: [u8; 32],
}

/// Constants fixed by the wrap circuit — everything we can precompute
/// once at SP1 build time and bake into the guest.
pub struct WrapVerifySetup<'a> {
    /// 28 single-chunk wrap-VK commitments, in
    /// `index_to_field_elements` order. Constant per circuit.
    pub vk_commitments: &'a WrapVkCommitments,
}

/// Everything the host hands the SP1 guest in one shot.
///
/// `proof_repr_msgpack` is the canonical msgpack of the statement + prev_evals
/// (`parse::canonical_proof_repr_msgpack`'s output). The guest hashes it to
/// produce `statement_digest`, then parses it for the wrap statement.
/// `wrap_proof` is the kimchi `ProverProof` with `prev_challenges` already
/// populated by the host (mirroring `Wrap_hack.pad_accumulator`).
/// `host_precomputed` carries the values from `host_precompute` so the
/// guest can skip `expand_deferred` and the wrap-messages Poseidon.
#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    pub proof_repr_msgpack: Vec<u8>,
    pub wrap_proof: PallasProof,
    pub host_precomputed: HostPrecomputed,
}

/// Output of `expand_deferred` + the wrap-side messages digest, as
/// the host hands them to the guest. Everything here is something the
/// wrap circuit *also* derives internally, so the guest doesn't need
/// to verify the values directly — kimchi rejection catches any lie.
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
    /// Raw 128-bit `xi` prechallenge (two u64 limbs). Comes out of
    /// `expand_deferred` as a `ScalarChallenge`; we serialize the
    /// limbs directly because they ride through serde natively.
    pub xi_limbs: [u64; 2],
    /// Wrap-side messages digest (Poseidon over Fq). Doesn't bind
    /// `app_state` (only `step_messages_digest_fp` does), so safe to
    /// have the host compute.
    #[serde(with = "crate::serde_compat::ark")]
    pub wrap_messages_digest_fq: Fq,
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
    let pairs = build_prev_challenges_max_one(dummy_sg, real_sg, real_limbs);
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

/// Slim guest pipeline. Consumes host-precomputed values for everything
/// kimchi *binds anyway*, and only does the `app_state`-binding step
/// digest itself plus the SHA-256 of the input statement bytes.
///
/// `wrap_vi_bytes` and `wrap_srs_bytes` are separate because kimchi's
/// `VerifierIndex` serialization marks `srs` as `#[serde(skip)]` (the
/// SRS is large and shared across many circuits, so it lives in its
/// own blob). [`load_pallas_verifier_index`] stitches them together
/// into `vi.srs`.
pub fn verify_wrap_proof_precomputed(
    setup: &WrapVerifySetup<'_>,
    wrap_vi_bytes: &[u8],
    wrap_srs_bytes: &[u8],
    input: GuestInput,
) -> Result<(Vec<Fp>, [u8; 32]), VerifyError> {
    let GuestInput {
        proof_repr_msgpack,
        wrap_proof,
        host_precomputed: precomp,
    } = input;

    let statement_digest: [u8; 32] = Sha256::digest(&proof_repr_msgpack).into();

    let parsed =
        parse_proof_repr_msgpack(&proof_repr_msgpack).map_err(|_| VerifyError::DecodeProofRepr)?;
    let stmt = parsed.statement;

    let wrap_vi = load_pallas_verifier_index(wrap_vi_bytes, wrap_srs_bytes);

    let (_endo_q_step, endo_r_step) = endos::<Vesta>();
    let sponge_digest_fp = stmt.proof_state.sponge_digest_before_evaluations.to_fp();

    // Step-side messages digest — the binding hop for `app_state`.
    // Stays in-guest so the SP1 attestation links `app_state` to the
    // wrap proof's public input.
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
        setup.vk_commitments,
        &stmt.messages_for_next_step_proof.app_state,
        &step_prev_proofs,
    );

    // Reconstruct the `xi` `ScalarChallenge` from raw limbs so it
    // round-trips through `assemble_wrap_main_input`'s expected shape.
    let xi_sc = ScalarChallenge {
        inner: Challenge(precomp.xi_limbs),
    };

    let plonk_min = &stmt.proof_state.deferred_values.plonk;
    let packed_struct = assemble_wrap_main_input(AssembleInput {
        combined_inner_product: precomp.combined_inner_product,
        b: precomp.b,
        perm: precomp.perm,
        zeta_to_domain_size: precomp.zeta_to_domain_size,
        zeta_to_srs_length: precomp.zeta_to_srs_length,
        beta: &plonk_min.beta,
        gamma: &plonk_min.gamma,
        alpha: &plonk_min.alpha.inner,
        zeta: &plonk_min.zeta.inner,
        xi: &xi_sc.inner,
        sponge_digest_fp,
        messages_for_next_step_digest_fp: step_messages_digest_fp,
        messages_for_next_wrap_digest_fq: precomp.wrap_messages_digest_fq,
        bulletproof_challenges: &stmt.proof_state.deferred_values.bulletproof_challenges,
        branch_data: &stmt.proof_state.deferred_values.branch_data,
        feature_flags: [false; 8],
    });
    let packed: Vec<Fq> = packed_struct.to_fq_vec();

    // `Map::setup()` does 1 square root + 2 modular inverses over the
    // Pallas base field — non-trivial in the SP1 zkVM since we don't
    // have a Pasta-curve precompile. Worth baking via build.rs as a
    // follow-up; for now we just call it.
    let group_map = <Pallas as poly_commitment::commitment::CommitmentCurve>::Map::setup();
    kimchi::verifier::verify::<
        FULL_ROUNDS,
        Pallas,
        mina_poseidon::sponge::DefaultFqSponge<
            mina_curves::pasta::PallasParameters,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            FULL_ROUNDS,
        >,
        mina_poseidon::sponge::DefaultFrSponge<
            Fq,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            FULL_ROUNDS,
        >,
        poly_commitment::ipa::OpeningProof<Pallas, FULL_ROUNDS>,
    >(&group_map, &wrap_vi, &wrap_proof, &packed)
    .map_err(|_| VerifyError::KimchiReject)?;

    Ok((
        stmt.messages_for_next_step_proof.app_state,
        statement_digest,
    ))
}

/// Standard pickles zk-rows count.
pub const ZK_ROWS: u32 = 3;

/// Run `expand_deferred` over a parsed `(WrapStatement, ParsedPrevEvals)`
/// pair. Encapsulates the step-domain / linearization / endo-expansion
/// plumbing that's the same for every pickles verifier call. Returns the
/// full `ExpandedDeferred` so callers can pull whatever they need.
pub fn expand_deferred_for_statement(
    stmt: &WrapStatement,
    prev: &ParsedPrevEvals,
) -> crate::deferred::ExpandedDeferred<Fp> {
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
                .map(|bc| endo_expand_scalar(&bc.prechallenge, &endo_r_step))
                .collect()
        })
        .collect();

    let sponge_digest_fp = stmt.proof_state.sponge_digest_before_evaluations.to_fp();
    let public_input_chunks = [prev.public_evals.zeta];

    expand_deferred::<Fp>(ExpandDeferredInput {
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
        srs_length_log2: STEP_IPA_ROUNDS as u32,
        endo: endo_r_step,
        linearization_endo_coefficient: endos::<Pallas>().0,
        linearization_constant_term: &linearization.constant_term,
        domain,
        mds: mds_step,
        sponge_params: sponge_params_step,
    })
    .expect("expand_deferred")
}

/// Run `expand_deferred` + the wrap-side messages digest on the host,
/// producing the [`HostPrecomputed`] blob the guest consumes.
pub fn host_precompute(stmt: &WrapStatement, prev: &ParsedPrevEvals) -> HostPrecomputed {
    let expanded = expand_deferred_for_statement(stmt, prev);

    let (_endo_q_wrap, endo_r_wrap) = endos::<Pallas>();
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

/// Populate a wrap proof's `prev_challenges` from the statement, so the
/// host can ship the proof bytes with that field already filled in.
/// Mirrors what's in `Wrap_hack.pad_accumulator`.
pub fn host_populate_prev_challenges(
    proof: &mut PallasProof,
    stmt: &WrapStatement,
    dummy_sg: Pallas,
) {
    proof.prev_challenges = build_prev_challenges(stmt, dummy_sg);
}
