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

// ---- derive_plonk --------------------------------------------------------

/// Endo-expanded form of [`PlonkMinimal`]'s scalar challenges. `beta` and
/// `gamma` are carried in their raw 128-bit form by pickles but usually
/// converted to field elements at the call site; we expose both here.
pub struct ExpandedPlonkChallenges<F> {
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    pub zeta: F,
}

/// Endo-expand [`PlonkMinimal`]'s challenges into field elements. OCaml
/// `Plonk_checks.expand_minimal` / PS inline in `derivePlonk`.
///
/// Mirrors pickles' convention: `alpha`/`zeta` go through the scalar-challenge
/// endo (128-bit → full field), `beta`/`gamma` are the plain `Challenge`
/// bit-pattern reinterpreted as a field element (since `endo` isn't applied
/// to them).
pub fn expand_plonk_minimal<F: PrimeField>(
    minimal: &crate::statement::PlonkMinimal,
    endo: &F,
) -> ExpandedPlonkChallenges<F> {
    let alpha = endo_expand_scalar(&minimal.alpha, endo);
    let zeta = endo_expand_scalar(&minimal.zeta, endo);
    let beta = PoseidonScalarChallenge::<F>::from_limbs(minimal.beta.0).inner();
    let gamma = PoseidonScalarChallenge::<F>::from_limbs(minimal.gamma.0).inner();
    ExpandedPlonkChallenges {
        alpha,
        beta,
        gamma,
        zeta,
    }
}

/// Input to [`perm_scalar`] / [`perm_contribution`] — all values in the
/// native field the permutation check runs over (step field for wrap-side
/// derivation, wrap field for step-side).
pub struct PermutationInput<F> {
    /// First 7 witness-column evaluations at zeta.
    pub w: [F; 7],
    /// Sigma-polynomial evaluations at zeta (6 columns = `PERMUTS - 1`).
    pub sigma: [F; 6],
    /// Permutation polynomial z evaluated at (zeta, zeta·omega).
    pub z_zeta: F,
    pub z_omega_times_zeta: F,
    /// Domain shift values (7, one per permutation column).
    pub shifts: [F; 7],
    /// Expanded plonk challenges in their field-element form.
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    /// Pre-computed `(zeta - omega^{-1}) * (zeta - omega^{-2}) * (zeta - omega^{-zk_rows})`.
    pub zk_polynomial: F,
    /// `zeta^n - 1` (domain vanishing at zeta).
    pub zeta_to_n_minus_1: F,
    /// `omega^{-zk_rows}`.
    pub omega_to_minus_zk_rows: F,
    /// The evaluation point itself.
    pub zeta: F,
}

/// Offset of alpha powers for the permutation argument.
/// Matches `kimchi/src/index.rs` / PS `Pickles.PlonkChecks.Permutation.permAlpha0`.
pub const PERM_ALPHA_0: u64 = 21;

/// Port of PS `Pickles.PlonkChecks.Permutation.permScalar`
/// / OCaml `Plonk_checks.derive_plonk` permutation block.
///
/// ```text
/// perm = -(z(zeta·omega) · beta · alpha^21 · zk_polynomial
///          · ∏_{i=0}^{5} (gamma + beta·sigma_i + w_i))
/// ```
pub fn perm_scalar<F: PrimeField>(input: &PermutationInput<F>) -> F {
    let alpha_pow_21 = input.alpha.pow([PERM_ALPHA_0]);
    let init = input.z_omega_times_zeta * input.beta * alpha_pow_21 * input.zk_polynomial;
    let product = input
        .w
        .iter()
        .take(6)
        .zip(input.sigma.iter())
        .fold(init, |acc, (w_i, s_i)| {
            acc * (input.gamma + input.beta * s_i + w_i)
        });
    -product
}

/// Input to [`derive_plonk`].
pub struct DerivePlonkInput<'a, F> {
    /// Raw 128-bit challenges as they appear in the statement.
    pub plonk_minimal: &'a crate::statement::PlonkMinimal,
    /// First 7 witness evaluations at zeta.
    pub w: [F; 7],
    /// Sigma evaluations at zeta.
    pub sigma: [F; 6],
    /// Permutation z-evaluations at zeta, zeta·omega.
    pub z_zeta: F,
    pub z_omega_times_zeta: F,
    /// Domain permutation shifts (7 values).
    pub shifts: [F; 7],
    /// Domain generator ω.
    pub generator: F,
    /// log2 of the domain size.
    pub domain_log2: u32,
    /// zk-row count (standard kimchi: 3).
    pub zk_rows: u32,
    /// log2 of the SRS length (= step IPA rounds, 16).
    pub srs_length_log2: u32,
    /// Curve endo coefficient for the field `F`.
    pub endo: F,
}

/// Derived plonk scalars for the in-circuit form. The 128-bit challenges
/// are carried through unchanged from the minimal input; the derived
/// scalars (`perm`, `zeta_to_domain_size`, `zeta_to_srs_length`) are
/// wrapped in [`ShiftedValue`] as pickles' `Shifted_value.Type1`.
pub struct DerivedPlonk<F> {
    pub alpha: crate::statement::ScalarChallenge,
    pub beta: Challenge,
    pub gamma: Challenge,
    pub zeta: crate::statement::ScalarChallenge,
    pub perm: crate::statement::ShiftedValue<F>,
    pub zeta_to_domain_size: crate::statement::ShiftedValue<F>,
    pub zeta_to_srs_length: crate::statement::ShiftedValue<F>,
}

/// Port of OCaml `Plonk_checks.derive_plonk` (plonk_checks.ml:403-441)
/// / PS `Prove/Pure/Common.derivePlonk`.
///
/// Given minimal challenges + field evaluations from the proof, produces
/// the full set of plonk scalars the wrap-circuit public input commits to.
/// The 128-bit challenges (`alpha` / `beta` / `gamma` / `zeta`) are carried
/// forward unchanged; only `perm`, `zeta_to_domain_size`, and
/// `zeta_to_srs_length` are newly derived.
pub fn derive_plonk<F: PrimeField>(input: DerivePlonkInput<'_, F>) -> DerivedPlonk<F> {
    let expanded = expand_plonk_minimal(input.plonk_minimal, &input.endo);

    let omega_inv = F::one() / input.generator;
    let omega_to_minus_zk_rows = omega_inv.pow([u64::from(input.zk_rows)]);
    let omega_to_minus_zk_plus_1 = omega_inv.pow([u64::from(input.zk_rows - 1)]);

    let zk_polynomial = (expanded.zeta - omega_inv)
        * (expanded.zeta - omega_to_minus_zk_plus_1)
        * (expanded.zeta - omega_to_minus_zk_rows);

    let zeta_to_n_minus_1 = expanded.zeta.pow([1u64 << input.domain_log2]) - F::one();
    let zeta_to_srs_length = expanded.zeta.pow([1u64 << input.srs_length_log2]);

    let perm_raw = perm_scalar(&PermutationInput {
        w: input.w,
        sigma: input.sigma,
        z_zeta: input.z_zeta,
        z_omega_times_zeta: input.z_omega_times_zeta,
        shifts: input.shifts,
        alpha: expanded.alpha,
        beta: expanded.beta,
        gamma: expanded.gamma,
        zk_polynomial,
        zeta_to_n_minus_1,
        omega_to_minus_zk_rows,
        zeta: expanded.zeta,
    });

    DerivedPlonk {
        alpha: input.plonk_minimal.alpha.clone(),
        beta: input.plonk_minimal.beta.clone(),
        gamma: input.plonk_minimal.gamma.clone(),
        zeta: input.plonk_minimal.zeta.clone(),
        perm: crate::statement::ShiftedValue(perm_raw),
        zeta_to_domain_size: crate::statement::ShiftedValue(zeta_to_n_minus_1 + F::one()),
        zeta_to_srs_length: crate::statement::ShiftedValue(zeta_to_srs_length),
    }
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

    /// `perm_scalar` on synthetic inputs, computed by hand against the
    /// formula documented in the function's doc.
    #[test]
    fn perm_scalar_matches_hand_computation() {
        let alpha = Fp::from(2u64);
        let beta = Fp::from(3u64);
        let gamma = Fp::from(5u64);
        let zk_polynomial = Fp::from(7u64);
        let z_omega_times_zeta = Fp::from(11u64);
        let w = [Fp::from(13u64); 7];
        let sigma = [Fp::from(17u64); 6];
        let shifts = [Fp::zero(); 7];

        let input = PermutationInput {
            w,
            sigma,
            z_zeta: Fp::zero(),
            z_omega_times_zeta,
            shifts,
            alpha,
            beta,
            gamma,
            zk_polynomial,
            zeta_to_n_minus_1: Fp::zero(),
            omega_to_minus_zk_rows: Fp::zero(),
            zeta: Fp::zero(),
        };

        // init = 11 * 3 * 2^21 * 7
        // fold: acc_{i+1} = acc_i * (5 + 3*17 + 13) = acc_i * 69  (6 times)
        // perm = -(init * 69^6)
        let alpha_pow_21 = alpha.pow([PERM_ALPHA_0]);
        let init = z_omega_times_zeta * beta * alpha_pow_21 * zk_polynomial;
        let factor = gamma + beta * sigma[0] + w[0]; // 69
        let expected = -(init * factor.pow([6u64]));

        assert_eq!(perm_scalar(&input), expected);
    }

    /// Wiring test for `derive_plonk`: confirms it runs to completion and
    /// carries the challenges forward unchanged, with the derived scalars
    /// structurally present. Full algebraic correctness is verified by a
    /// later golden-value test against OCaml/PS output.
    #[test]
    fn derive_plonk_carries_challenges_and_runs_end_to_end() {
        use crate::statement::{FeatureFlags, PlonkMinimal};
        use kimchi::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};

        let plonk_minimal = PlonkMinimal {
            alpha: ScalarChallenge {
                inner: Challenge([1, 2]),
            },
            beta: Challenge([3, 4]),
            gamma: Challenge([5, 6]),
            zeta: ScalarChallenge {
                inner: Challenge([7, 8]),
            },
            joint_combiner: None,
            feature_flags: FeatureFlags {
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
            },
        };

        let derived = derive_plonk(DerivePlonkInput::<Fp> {
            plonk_minimal: &plonk_minimal,
            w: [Fp::from(1u64); 7],
            sigma: [Fp::from(2u64); 6],
            z_zeta: Fp::from(3u64),
            z_omega_times_zeta: Fp::from(4u64),
            shifts: [Fp::from(5u64); 7],
            generator: Fp::from(9u64),
            domain_log2: 14,
            zk_rows: 3,
            srs_length_log2: 16,
            endo: Fp::from(11u64),
        });

        // Challenges carried forward unchanged.
        assert_eq!(derived.alpha.inner.0, plonk_minimal.alpha.inner.0);
        assert_eq!(derived.beta.0, plonk_minimal.beta.0);
        assert_eq!(derived.gamma.0, plonk_minimal.gamma.0);
        assert_eq!(derived.zeta.inner.0, plonk_minimal.zeta.inner.0);
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
