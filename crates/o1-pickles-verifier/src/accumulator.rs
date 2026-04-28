//! IPA step accumulator check.
//!
//! Port of OCaml `Ipa.Step.accumulator_check`
//! (mina/src/lib/crypto/pickles/common.ml:154-167). The scalar-field
//! work that a recursive step circuit would normally verify in-circuit
//! via endo-tricks; as a terminal out-of-circuit verifier we do it
//! natively.
//!
//! Given the step proof's endo-expanded bulletproof challenges and the
//! claimed `challenge_polynomial_commitment` from the wrap statement,
//! we recompute the commitment to
//!
//! ```text
//!   b(X) = ∏_{i=0}^{k-1} (1 + u_{k-1-i} · X^{2^i})
//! ```
//!
//! by MSM against the first `2^k` generators of the step-side (Vesta) SRS
//! and compare for point equality.

extern crate alloc;

use alloc::vec::Vec;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use mina_poseidon::sponge::ScalarChallenge as PoseidonScalarChallenge;
use poly_commitment::commitment::b_poly_coefficients;
use poly_commitment::ipa::{endos, SRS};

use crate::statement::BulletproofChallenge;
use crate::{Fp, Vesta};

/// Step-accumulator check: verify the claimed challenge-polynomial
/// commitment matches the one recomputed from `raw_chals` by MSM
/// against the first `2^raw_chals.len()` generators of `srs`. Endo-expands
/// each prechallenge internally; matches OCaml
/// `Ipa.Step.accumulator_check` (common.ml:154-167) for the
/// single-proof case. Panics if the SRS is too small.
pub fn accumulator_check(
    raw_chals: &[BulletproofChallenge],
    claimed: Vesta,
    srs: &SRS<Vesta>,
) -> bool {
    let (_endo_q, endo_r) = endos::<Vesta>();
    let chals: Vec<Fp> = raw_chals
        .iter()
        .map(|bc| {
            PoseidonScalarChallenge::<Fp>::from_limbs(bc.prechallenge.inner.0).to_field(&endo_r)
        })
        .collect();

    let coeffs = b_poly_coefficients(&chals);
    assert!(
        coeffs.len() <= srs.g.len(),
        "SRS too small: need {} generators, have {}",
        coeffs.len(),
        srs.g.len()
    );
    let bases = &srs.g[..coeffs.len()];
    let scalars: Vec<_> = coeffs.iter().map(|c| c.into_bigint()).collect();
    let recomputed = <Vesta as AffineRepr>::Group::msm_bigint(bases, &scalars).into_affine();
    recomputed == claimed
}
