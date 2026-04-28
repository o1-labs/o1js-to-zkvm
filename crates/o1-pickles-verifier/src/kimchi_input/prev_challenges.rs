//! Helpers for the wrap kimchi proof's `prev_challenges` field —
//! `Wrap_hack.pad_accumulator` mirror plus the dummy IPA accumulator
//! commitment that fills the front-pad slot.

extern crate alloc;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use mina_poseidon::sponge::ScalarChallenge as PoseidonScalarChallenge;
use poly_commitment::commitment::b_poly_coefficients;
use poly_commitment::ipa::{endos, SRS};

use super::messages::{
    dummy_ipa_wrap_challenges_expanded, WRAP_HACK_PADDED_LENGTH, WRAP_IPA_ROUNDS,
};
use crate::{Fq, Pallas};

/// Compute `Dummy.Ipa.Wrap.sg`: the IPA accumulator commitment for
/// the wrap-side dummy challenges — an MSM of `b_poly_coefficients(chals)`
/// scalars across the SRS's first 2^k generators, where k = 15.
///
/// Pickles uses this Pallas point as the front-pad in
/// `Wrap_hack.pad_accumulator`, so it appears as `prev_challenges[0].comm`
/// on every wrap proof with `Max_proofs_verified = N1` regardless of
/// base-vs-recursive.
pub fn compute_dummy_wrap_sg(srs: &SRS<Pallas>) -> Pallas {
    let chals = dummy_ipa_wrap_challenges_expanded();
    let coeffs = b_poly_coefficients(&chals);
    assert_eq!(coeffs.len(), 1usize << WRAP_IPA_ROUNDS);
    assert!(srs.g.len() >= coeffs.len(), "SRS too small for dummy_sg");
    <Pallas as AffineRepr>::Group::msm(&srs.g[..coeffs.len()], &coeffs)
        .expect("MSM length mismatch")
        .into_affine()
}

/// Build the wrap kimchi proof's `prev_challenges` for a wrap proof
/// with `Max_proofs_verified = N1`, mirroring `Wrap_hack.pad_accumulator`
/// (wrap_hack.ml:35) applied to the length-1 `(commitment, challenges)`
/// vector that pickles assembles from
/// `messages_for_next_step_proof.challenge_polynomial_commitments` and
/// `messages_for_next_wrap_proof.old_bulletproof_challenges`.
///
/// `dummy_sg` should be precomputed once via [`compute_dummy_wrap_sg`].
/// `real_step_sg` is the single element of
/// `messages_for_next_step_proof.challenge_polynomial_commitments`.
/// `real_wrap_old_prechal_limbs` gives the 15 raw 128-bit prechallenge
/// limbs from
/// `messages_for_next_wrap_proof.old_bulletproof_challenges[0]`.
pub fn build_prev_challenges_max_one(
    dummy_sg: Pallas,
    real_step_sg: Pallas,
    real_wrap_old_prechal_limbs: [[u64; 2]; WRAP_IPA_ROUNDS],
) -> [(Pallas, [Fq; WRAP_IPA_ROUNDS]); WRAP_HACK_PADDED_LENGTH] {
    let dummy_chals = dummy_ipa_wrap_challenges_expanded();
    let real_chals: [Fq; WRAP_IPA_ROUNDS] =
        core::array::from_fn(|i| expand_wrap_prechallenge(real_wrap_old_prechal_limbs[i]));
    [(dummy_sg, dummy_chals), (real_step_sg, real_chals)]
}

/// Endo-expand a 128-bit prechallenge to a wrap-side scalar (Fq), the
/// same way `Ipa.Wrap.compute_challenges` does in OCaml.
fn expand_wrap_prechallenge(limbs: [u64; 2]) -> Fq {
    let (_endo_q, endo_r) = endos::<Pallas>();
    PoseidonScalarChallenge::<Fq>::from_limbs(limbs).to_field(&endo_r)
}
