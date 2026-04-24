//! IPA step accumulator check — stage 2 of `verifyOne`.
//!
//! Port of OCaml `Ipa.Step.accumulator_check`
//! (mina/src/lib/crypto/pickles/common.ml:154-167) / PS `Pickles.Verify`
//! stage 2 (`accumulatorOk`). This is the scalar-field work that a recursive
//! step circuit would normally verify in-circuit via endo-tricks; as a
//! terminal out-of-circuit verifier we do it natively.
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
use poly_commitment::commitment::b_poly_coefficients;
use poly_commitment::ipa::SRS;

use crate::{Fp, Vesta};

/// Compute `sg = <b_poly_coefficients(chals), srs.g>` — the Vesta-side
/// commitment to the IPA challenge polynomial.
///
/// `chals` holds the endo-expanded step-field bulletproof challenges (16
/// elements for Simple_chain / any standard pickles step IPA), and `srs`
/// must have at least `2^chals.len()` generators. Panics if the SRS is too
/// small.
///
/// Mirrors OCaml `Ipa.Step.compute_sg` (common.ml:146-152), which FFIs into
/// `kimchi_bindings::SRS::Fp::b_poly_commitment` and returns
/// `comm.unshifted[0]` (a single chunk, asserted finite).
pub fn compute_sg(chals: &[Fp], srs: &SRS<Vesta>) -> Vesta {
    let coeffs = b_poly_coefficients(chals);
    assert!(
        coeffs.len() <= srs.g.len(),
        "SRS too small: need {} generators, have {}",
        coeffs.len(),
        srs.g.len()
    );
    let bases = &srs.g[..coeffs.len()];
    let scalars: Vec<_> = coeffs.iter().map(|c| c.into_bigint()).collect();
    <Vesta as AffineRepr>::Group::msm_bigint(bases, &scalars).into_affine()
}

/// Step-accumulator check: verify the claimed challenge-polynomial
/// commitment matches the one recomputed from `chals`.
///
/// Mirrors OCaml `Ipa.Step.accumulator_check` (common.ml:154-167) for the
/// single-proof case — we don't batch because a one-proof terminal verifier
/// has no reason to.
pub fn accumulator_check(chals: &[Fp], claimed: Vesta, srs: &SRS<Vesta>) -> bool {
    compute_sg(chals, srs) == claimed
}
