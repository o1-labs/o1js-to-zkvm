//! Pickles deferred-values expansion + run-checks.
//!
//! Mirror of OCaml `Wrap_deferred_values.expand_deferred` + `run_checks`
//! (mina/src/lib/crypto/pickles/wrap_deferred_values.ml), leaning on
//! proof-systems primitives for the heavy lifting. Cross-referenced against
//! the cleaner PureScript port at
//! `l-adic/snarky/packages/pickles/src/Pickles/Prove/Pure/{Common,Verify}.purs`.
//!
//! This module grows top-down:
//! 1. Pure algebraic helpers (`actual_evaluation`, `endo_expand`,
//!    `compute_bp_chals_and_b`).
//! 2. Bigger derivations (`derive_plonk`, `ft_eval0`,
//!    `combined_inner_product`) — port of `Plonk_checks.derive_plonk` and
//!    `Plonk_checks.ft_eval0` from pickles.
//! 3. Orchestrator (`expand_deferred`) + assertions (`run_checks`).
//!
//! Only (1) is implemented for now.

extern crate alloc;

use alloc::vec::Vec;

use ark_ff::{Field, PrimeField};
use mina_poseidon::sponge::ScalarChallenge as PoseidonScalarChallenge;
use poly_commitment::commitment::b_poly;

use crate::statement::{BulletproofChallenge, Challenge, ScalarChallenge};

// ---- pure algebraic helpers ----------------------------------------------

/// Horner-fold-combine a chunked evaluation `evals` at a point `pt`, with
/// chunk base `pt^(2^rounds)`:
///
/// ```text
/// evals[0] + pt_N * evals[1] + pt_N^2 * evals[2] + ... + pt_N^(n-1) * evals[n-1]
/// ```
///
/// Mirrors OCaml's `Plonk_checks.actual_evaluation` (plonk_checks.ml:90-100)
/// and PS's `actualEvaluation` in `Prove/Pure/Common.purs:90`. Returns zero
/// for an empty input.
pub fn actual_evaluation<F: Field>(rounds: u32, pt: F, evals: &[F]) -> F {
    let pt_n = pow2_pow(rounds, pt);
    evals.iter().rev().fold(F::zero(), |acc, &e| e + pt_n * acc)
}

/// `x^(2^n)` via repeated squaring. Tracks OCaml's local `pt_n` loop at
/// `plonk_checks.ml:92-94`.
fn pow2_pow<F: Field>(n: u32, mut x: F) -> F {
    for _ in 0..n {
        x.square_in_place();
    }
    x
}

/// Endo-expand a 128-bit challenge into a field element `f` such that
/// `[f]P = [challenge]P` under the curve's endomorphism, matching
/// `Snarky.Circuit.Kimchi.EndoScalar.toFieldPure` (PS) / OCaml's
/// `Scalar_challenge.to_field`.
///
/// Thin wrapper around `mina_poseidon::sponge::ScalarChallenge::to_field`
/// — converts our `Challenge([u64; 2])` into the form the proof-systems
/// sponge layer already knows how to handle.
pub fn endo_expand<F: PrimeField>(c: &Challenge, endo: &F) -> F {
    PoseidonScalarChallenge::<F>::from_limbs(c.0).to_field(endo)
}

/// Same for `ScalarChallenge` (which is just a wrapper around `Challenge`).
pub fn endo_expand_scalar<F: PrimeField>(c: &ScalarChallenge, endo: &F) -> F {
    endo_expand(&c.inner, endo)
}

/// Output of [`compute_bp_chals_and_b`].
pub struct BpChalsAndB<F> {
    /// Endo-expanded, field-level bulletproof challenges.
    pub chals: Vec<F>,
    /// `b_poly(chals, zeta) + r * b_poly(chals, zetaw)`.
    pub b: F,
}

/// Port of OCaml `step.ml:359-379` / PS `Prove/Pure/Common.computeBpChalsAndB`.
///
/// Given raw 128-bit IPA prechallenges, the curve endo coefficient, and a
/// pair of evaluation points `(zeta, zetaw)` together with the batching
/// challenge `r`, produce:
/// 1. the endo-expanded field challenges, and
/// 2. `b = b_poly(chals, zeta) + r * b_poly(chals, zetaw)`.
///
/// `b_poly` is the standard IPA challenge polynomial; we call into
/// `poly_commitment::commitment::b_poly` rather than re-implementing it.
pub fn compute_bp_chals_and_b<F: PrimeField>(
    raw_prechallenges: &[BulletproofChallenge],
    endo: &F,
    zeta: F,
    zetaw: F,
    r: F,
) -> BpChalsAndB<F> {
    let chals: Vec<F> = raw_prechallenges
        .iter()
        .map(|bc| endo_expand_scalar(&bc.prechallenge, endo))
        .collect();
    let b = b_poly(&chals, zeta) + r * b_poly(&chals, zetaw);
    BpChalsAndB { chals, b }
}

// ---- tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use mina_curves::pasta::Fp;

    use crate::statement::{BulletproofChallenge, Challenge, ScalarChallenge};

    #[test]
    fn actual_evaluation_empty_is_zero() {
        let pt = Fp::from(7u64);
        assert_eq!(actual_evaluation(3, pt, &[]), Fp::zero());
    }

    #[test]
    fn actual_evaluation_single_chunk_is_that_chunk() {
        let pt = Fp::from(7u64);
        let e = Fp::from(42u64);
        // With one chunk, the fold reduces to `e + pt_n * 0 = e`.
        assert_eq!(actual_evaluation(3, pt, &[e]), e);
    }

    #[test]
    fn actual_evaluation_horner_matches_definition() {
        // pt_n = 2^(2^0) = 2, chunks = [3, 5, 7]
        // expected: 3 + 2*5 + 4*7 = 3 + 10 + 28 = 41
        let pt = Fp::from(2u64);
        let chunks = [Fp::from(3u64), Fp::from(5u64), Fp::from(7u64)];
        assert_eq!(actual_evaluation(0, pt, &chunks), Fp::from(41u64));
    }

    #[test]
    fn pow2_pow_matches_manual() {
        let x = Fp::from(3u64);
        // 3^(2^0) = 3, 3^(2^1) = 9, 3^(2^2) = 81, 3^(2^3) = 6561
        assert_eq!(pow2_pow(0, x), Fp::from(3u64));
        assert_eq!(pow2_pow(1, x), Fp::from(9u64));
        assert_eq!(pow2_pow(2, x), Fp::from(81u64));
        assert_eq!(pow2_pow(3, x), Fp::from(6561u64));
    }

    /// Exercises the endo-expansion + `b_poly` plumbing end-to-end with
    /// structurally-valid inputs. We're not testing `compute_bp_chals_and_b`'s
    /// algebraic correctness here — that comes from `b_poly`'s own test
    /// suite in proof-systems and from an eventual golden-value test
    /// against OCaml pickles. This is a wiring sanity check.
    #[test]
    fn compute_bp_chals_and_b_runs_end_to_end() {
        let raw: Vec<BulletproofChallenge> = (0..16)
            .map(|i| BulletproofChallenge {
                prechallenge: ScalarChallenge {
                    inner: Challenge([i as u64, (i + 1) as u64]),
                },
            })
            .collect();
        // The endo coefficient for Fp (Pallas scalar field). Using a
        // placeholder value here is fine for a wiring test — correctness
        // requires the actual endo from the curve, which `mina_poseidon`
        // exposes elsewhere; we'll thread it through from the verifier
        // once `expand_deferred` is wired up.
        let endo = Fp::from(5u64);
        let zeta = Fp::from(11u64);
        let zetaw = Fp::from(13u64);
        let r = Fp::from(17u64);
        let out = compute_bp_chals_and_b::<Fp>(&raw, &endo, zeta, zetaw, r);
        assert_eq!(out.chals.len(), 16);
        // b_poly evaluates to a nonzero element for these inputs.
        assert_ne!(out.b, Fp::zero());
    }
}
