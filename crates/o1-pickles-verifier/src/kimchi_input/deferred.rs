//! Pickles deferred-values expansion + run-checks.
//!
//! Mirror of OCaml `Wrap_deferred_values.expand_deferred` + `run_checks`
//! (mina/src/lib/crypto/pickles/wrap_deferred_values.ml).

extern crate alloc;

use alloc::vec::Vec;

use ark_ff::{Field, PrimeField};
use mina_poseidon::sponge::ScalarChallenge as PoseidonScalarChallenge;
use poly_commitment::commitment::b_poly;

use crate::statement::{BulletproofChallenge, Challenge, ScalarChallenge};

/// Horner-fold-combine a chunked evaluation `evals` at a point `pt`, with
/// chunk base `pt^(2^rounds)`:
///
/// ```text
/// evals[0] + pt_N * evals[1] + pt_N^2 * evals[2] + ... + pt_N^(n-1) * evals[n-1]
/// ```
///
/// Mirrors OCaml's `Plonk_checks.actual_evaluation` (plonk_checks.ml:90-100).
/// Returns zero for an empty input.
pub fn horner_fold<F: Field>(rounds: u32, pt: F, evals: &[F]) -> F {
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

/// Endo-expand a 128-bit `ScalarChallenge` into a field element `f`
/// such that `[f]P = [challenge]P` under the curve's endomorphism.
/// Matches OCaml's `Scalar_challenge.to_field`.
pub fn endo_expand_scalar<F: PrimeField>(c: &ScalarChallenge, endo: &F) -> F {
    PoseidonScalarChallenge::<F>::from_limbs(c.inner.0).to_field(endo)
}

/// Output of [`compute_bp_chals_and_b`].
pub struct BpChalsAndB<F> {
    /// Endo-expanded, field-level bulletproof challenges.
    pub chals: Vec<F>,
    /// `b_poly(chals, zeta) + r * b_poly(chals, zetaw)`.
    pub b: F,
}

/// Port of OCaml `step.ml:359-379`.
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
/// `Plonk_checks.expand_minimal`.
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

/// Offset where `ArgumentType::Permutation` registers in the kimchi
/// `Alphas` table — the power of `alpha` the permutation argument
/// uses. Kimchi assigns offsets dynamically (see
/// `kimchi/src/linearization.rs`), but for the standard gate set with
/// no optional gates it lands at 21. To avoid duplicating it here we
/// could call `Alphas::register` in the same order kimchi does and
/// read back `get_alphas(ArgumentType::Permutation, ...)`, but the
/// constant is fixed for our wrap circuit so we hard-code it.
pub const PERM_ALPHA_0: u64 = 21;

/// Port of OCaml `Plonk_checks.derive_plonk` permutation block.
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

/// Port of OCaml `Plonk_checks.ft_eval0` permutation block.
///
/// Returns `term1 - term2 + boundary`:
/// - `term1 = (w_6 + gamma) · z(zeta·omega) · alpha^21 · zk_poly
///     · ∏_{i=0}^{5} (beta · sigma_i + w_i + gamma)`
/// - `term2 = alpha^21 · zk_poly · z(zeta)
///     · ∏_{i=0}^{6} (gamma + beta · zeta · shift_i + w_i)`
/// - `boundary = (zeta^n - 1) · (1 - z(zeta)) ·
///     (alpha^22 · (zeta - omega^{-zk_rows}) + alpha^23 · (zeta - 1))
///     / ((zeta - omega^{-zk_rows}) · (zeta - 1))`
///
/// Uses division so the caller must ensure the denominator is nonzero
/// (both `zeta - omega^{-zk_rows}` and `zeta - 1` are expected non-zero
/// when evaluating the plonk protocol away from zero-knowledge rows).
pub fn perm_contribution<F: PrimeField>(input: &PermutationInput<F>) -> F {
    let alpha_pow_21 = input.alpha.pow([PERM_ALPHA_0]);
    let alpha_pow_22 = alpha_pow_21 * input.alpha;
    let alpha_pow_23 = alpha_pow_22 * input.alpha;

    // term1
    let w6 = input.w[6];
    let term1_init =
        (w6 + input.gamma) * input.z_omega_times_zeta * alpha_pow_21 * input.zk_polynomial;
    let term1 = input
        .w
        .iter()
        .take(6)
        .zip(input.sigma.iter())
        .fold(term1_init, |acc, (w_i, s_i)| {
            (input.beta * s_i + w_i + input.gamma) * acc
        });

    // term2
    let term2_init = alpha_pow_21 * input.zk_polynomial * input.z_zeta;
    let term2 = input
        .w
        .iter()
        .zip(input.shifts.iter())
        .fold(term2_init, |acc, (w_i, s_i)| {
            acc * (input.gamma + input.beta * input.zeta * s_i + w_i)
        });

    // boundary
    let zeta_minus_omega = input.zeta - input.omega_to_minus_zk_rows;
    let zeta_minus_1 = input.zeta - F::one();
    let numerator = (input.zeta_to_n_minus_1 * alpha_pow_22 * zeta_minus_omega
        + input.zeta_to_n_minus_1 * alpha_pow_23 * zeta_minus_1)
        * (F::one() - input.z_zeta);
    let denominator = zeta_minus_omega * zeta_minus_1;
    let boundary = numerator / denominator;

    term1 - term2 + boundary
}

/// Input to [`combined_inner_product`].
pub struct CombinedInnerProductInput<'a, F> {
    /// The step proof's polynomial evaluations (pulled out of the wrap
    /// proof's `prev_evals`). We reuse kimchi's own `ProofEvaluations`
    /// shape instead of maintaining a parallel `AllEvals` type.
    pub evaluations: &'a kimchi::proof::ProofEvaluations<kimchi::proof::PointEvaluations<F>>,
    /// Public-input polynomial evaluations at `(zeta, zeta·omega)`. Pickles
    /// computes these by Horner-folding the public-input chunks
    /// (see [`horner_fold`]) rather than pulling from
    /// `evaluations.public`, so we take them as a separate input.
    pub public_evals: &'a kimchi::proof::PointEvaluations<F>,
    /// ft-polynomial evaluation at `zeta·omega`, carried on the proof itself
    /// (not in `ProofEvaluations`).
    pub ft_eval1: F,
    /// `ft_eval0`, computed externally by the verifier via [`ft_eval0`].
    pub ft_eval0: F,
    /// Previous proofs' bp-challenge vectors, already endo-expanded. Each
    /// inner vector feeds one `b_poly` into the batch.
    pub old_bulletproof_challenges: &'a [Vec<F>],
    /// The pickles batching challenge `xi` (distinct from kimchi's `v`).
    pub xi: F,
    /// The pickles point-combining challenge `r` (distinct from kimchi's `u`).
    pub r: F,
    pub zeta: F,
    pub zetaw: F,
}

/// Port of OCaml's pickles `combined_inner_product` helper
/// (wrap.ml:22-62 for the step-field side, step.ml:464-496 for the
/// wrap-field side).
///
/// Batches evaluations in the order pickles fixes:
/// `b_polys (n), public_input, ft, z, index (6), witness (15),
/// coefficient (15), sigma (6)`, folding through
/// `result += scale · (eval.zeta + r · eval.zeta_omega)` with
/// `scale *= xi` each step (starting `scale = 1`).
///
/// The six `index` selectors appear in pickles' fixed order:
/// `generic, poseidon, complete_add, mul, emul, endomul_scalar`.
/// Optional gate/lookup selectors are not included — pickles wrap
/// circuits don't use them.
pub fn combined_inner_product<F: PrimeField>(input: CombinedInnerProductInput<'_, F>) -> F {
    use kimchi::proof::PointEvaluations;

    let pe = input.evaluations;
    let selectors: [&PointEvaluations<F>; 6] = [
        &pe.generic_selector,
        &pe.poseidon_selector,
        &pe.complete_add_selector,
        &pe.mul_selector,
        &pe.emul_selector,
        &pe.endomul_scalar_selector,
    ];

    let bp_point_evals = input
        .old_bulletproof_challenges
        .iter()
        .map(|chals| (b_poly(chals, input.zeta), b_poly(chals, input.zetaw)));

    let rest = core::iter::once((input.public_evals.zeta, input.public_evals.zeta_omega))
        .chain(core::iter::once((input.ft_eval0, input.ft_eval1)))
        .chain(core::iter::once((pe.z.zeta, pe.z.zeta_omega)))
        .chain(selectors.iter().map(|s| (s.zeta, s.zeta_omega)))
        .chain(pe.w.iter().map(|w| (w.zeta, w.zeta_omega)))
        .chain(pe.coefficients.iter().map(|c| (c.zeta, c.zeta_omega)))
        .chain(pe.s.iter().map(|s| (s.zeta, s.zeta_omega)));

    let (result, _) = bp_point_evals.chain(rest).fold(
        (F::zero(), F::one()),
        |(result, scale), (at_zeta, at_zetaw)| {
            let term = at_zeta + input.r * at_zetaw;
            (result + scale * term, scale * input.xi)
        },
    );
    result
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
#[allow(dead_code)]
pub struct DerivedPlonk<F> {
    pub alpha: crate::statement::ScalarChallenge,
    pub beta: Challenge,
    pub gamma: Challenge,
    pub zeta: crate::statement::ScalarChallenge,
    pub perm: crate::statement::ShiftedValue<F>,
    pub zeta_to_domain_size: crate::statement::ShiftedValue<F>,
    pub zeta_to_srs_length: crate::statement::ShiftedValue<F>,
}

/// Port of OCaml `Plonk_checks.derive_plonk` (plonk_checks.ml:403-441).
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

/// Evaluate the linearization polynomial's constant term at `zeta` via
/// kimchi's Polish-token interpreter.
///
/// The token stream comes from `kimchi::linearization::expr_linearization`;
/// the caller supplies proof evaluations, Berkeley challenges, domain
/// constants, and the domain itself. Thin wrapper over
/// [`kimchi::circuits::expr::PolishToken::evaluate`] with the standard
/// Berkeley instantiation.
pub fn evaluate_linearization_constant_term<F: ark_ff::FftField>(
    tokens: &[kimchi::circuits::expr::PolishToken<
        F,
        kimchi::circuits::berkeley_columns::Column,
        kimchi::circuits::berkeley_columns::BerkeleyChallengeTerm,
    >],
    domain: ark_poly::Radix2EvaluationDomain<F>,
    zeta: F,
    evals: &kimchi::proof::ProofEvaluations<kimchi::proof::PointEvaluations<F>>,
    constants: &kimchi::circuits::expr::Constants<F>,
    challenges: &kimchi::circuits::berkeley_columns::BerkeleyChallenges<F>,
) -> Result<F, kimchi::circuits::expr::ExprError<kimchi::circuits::berkeley_columns::Column>> {
    kimchi::circuits::expr::PolishToken::evaluate(
        tokens, domain, zeta, evals, constants, challenges,
    )
}

/// Input to [`ft_eval0`].
pub struct FtEval0Input<'a, F: ark_ff::FftField> {
    /// Raw 128-bit plonk challenges from the statement.
    pub plonk_minimal: &'a crate::statement::PlonkMinimal,
    /// ProofEvaluations carried by the wrap proof's `prev_evals` — the
    /// step proof's polynomial evaluations at `(zeta, zeta·omega)`.
    pub evaluations: &'a kimchi::proof::ProofEvaluations<kimchi::proof::PointEvaluations<F>>,
    /// Chunked evaluations of the public-input polynomial at zeta;
    /// folded via [`horner_fold`].
    pub public_input_chunks: &'a [F],
    /// Permutation shift constants (7 values).
    pub shifts: [F; 7],
    /// Domain generator ω.
    pub generator: F,
    /// log2 of the domain size.
    pub domain_log2: u32,
    /// zk-row count (standard kimchi: 3).
    pub zk_rows: u32,
    /// log2 of the SRS length.
    pub srs_length_log2: u32,
    /// Scalar endo for the step inner curve (Vesta scalar endo, λ_Vesta in
    /// Fp). Used by `expand_plonk_minimal` and for `joint_combiner`'s
    /// endo expansion.
    pub endo: F,
    /// `endo_coefficient` constant for the linearization Constants record
    /// (Pallas base endo, ξ_Pallas in Fp). DIFFERENT from `endo` above —
    /// see OCaml `Endo.Step_inner_curve.base`.
    pub linearization_endo_coefficient: F,
    /// Linearization-polynomial constant-term token stream, from
    /// `kimchi::linearization::expr_linearization`.
    pub linearization_constant_term: &'a [kimchi::circuits::expr::PolishToken<
        F,
        kimchi::circuits::berkeley_columns::Column,
        kimchi::circuits::berkeley_columns::BerkeleyChallengeTerm,
    >],
    /// Plonk domain for token-stream evaluation.
    pub domain: ark_poly::Radix2EvaluationDomain<F>,
    /// MDS matrix for the Poseidon gate's constant-term evaluation.
    pub mds: &'static [[F; 3]; 3],
}

/// Port of OCaml `Plonk_checks.ft_eval0` (plonk_checks.ml:350-400).
///
/// Returns `perm_contribution - p_eval0_folded - constant_term`, where:
/// - `perm_contribution` mirrors [`perm_contribution`] on the witness /
///   sigma / z-polynomial evaluations pulled out of `evaluations`.
/// - `p_eval0_folded = horner_fold(srs_length_log2, zeta, public_input_chunks)`.
/// - `constant_term` is the linearization polynomial's constant term at
///   zeta, via [`evaluate_linearization_constant_term`].
pub fn ft_eval0<F: ark_ff::FftField + PrimeField>(
    input: FtEval0Input<'_, F>,
) -> Result<F, kimchi::circuits::expr::ExprError<kimchi::circuits::berkeley_columns::Column>> {
    let expanded = expand_plonk_minimal(input.plonk_minimal, &input.endo);

    let omega_inv = F::one() / input.generator;
    let omega_to_minus_zk_rows = omega_inv.pow([u64::from(input.zk_rows)]);
    let omega_to_minus_zk_plus_1 = omega_inv.pow([u64::from(input.zk_rows - 1)]);
    let zk_polynomial = (expanded.zeta - omega_inv)
        * (expanded.zeta - omega_to_minus_zk_plus_1)
        * (expanded.zeta - omega_to_minus_zk_rows);
    let zeta_to_n_minus_1 = expanded.zeta.pow([1u64 << input.domain_log2]) - F::one();

    let p_eval0_folded = horner_fold(
        input.srs_length_log2,
        expanded.zeta,
        input.public_input_chunks,
    );

    // First 7 witness + 6 sigma evaluations at zeta feed the permutation
    // contribution. z-poly values at zeta and zeta·omega likewise.
    let mut w = [F::zero(); 7];
    for (i, slot) in w.iter_mut().enumerate() {
        *slot = input.evaluations.w[i].zeta;
    }
    let mut sigma = [F::zero(); 6];
    for (i, slot) in sigma.iter_mut().enumerate() {
        *slot = input.evaluations.s[i].zeta;
    }
    let perm = perm_contribution(&PermutationInput {
        w,
        sigma,
        z_zeta: input.evaluations.z.zeta,
        z_omega_times_zeta: input.evaluations.z.zeta_omega,
        shifts: input.shifts,
        alpha: expanded.alpha,
        beta: expanded.beta,
        gamma: expanded.gamma,
        zk_polynomial,
        zeta_to_n_minus_1,
        omega_to_minus_zk_rows,
        zeta: expanded.zeta,
    });

    let constants = kimchi::circuits::expr::Constants {
        endo_coefficient: input.linearization_endo_coefficient,
        mds: input.mds,
        zk_rows: u64::from(input.zk_rows),
    };
    let challenges = kimchi::circuits::berkeley_columns::BerkeleyChallenges {
        alpha: expanded.alpha,
        beta: expanded.beta,
        gamma: expanded.gamma,
        joint_combiner: input
            .plonk_minimal
            .joint_combiner
            .as_ref()
            .map(|sc| endo_expand_scalar(sc, &input.endo))
            .unwrap_or_else(F::zero),
    };
    let constant_term = evaluate_linearization_constant_term(
        input.linearization_constant_term,
        input.domain,
        expanded.zeta,
        input.evaluations,
        &constants,
        &challenges,
    )?;

    Ok(perm - p_eval0_folded - constant_term)
}

pub use mina_poseidon::pasta::FULL_ROUNDS;

/// Alias for the kimchi-constants sponge params over field `F`.
pub type SpongeParams<F> = mina_poseidon::poseidon::ArithmeticSpongeParams<F, FULL_ROUNDS>;

type FrSpongeKimchi<F> = mina_poseidon::sponge::DefaultFrSponge<
    F,
    mina_poseidon::constants::PlonkSpongeConstantsKimchi,
    FULL_ROUNDS,
>;

type ArithmeticSpongeKimchi<F> = mina_poseidon::poseidon::ArithmeticSponge<
    F,
    mina_poseidon::constants::PlonkSpongeConstantsKimchi,
    FULL_ROUNDS,
>;

/// Input to [`expand_deferred`].
///
/// Splits into three groups:
///
/// 1. **Carried minimal statement fields** (`plonk_minimal`,
///    `bulletproof_challenges`, `sponge_digest_before_evaluations`) — pulled
///    verbatim from the wrap proof's `proof_state`.
/// 2. **Previous-proof evaluations + challenges** (`evaluations`,
///    `public_evals`, `ft_eval1`, `public_input_chunks`,
///    `old_bulletproof_challenges`) — the inner step proof's data, carried
///    by the wrap proof's `prev_evals`.
/// 3. **Static step-domain / SRS metadata** (`shifts`, `generator`,
///    `domain_log2`, `zk_rows`, `srs_length_log2`, `endo`,
///    `linearization_constant_term`, `domain`, `mds`, `sponge_params`) —
///    verifier constants, read from the step verifier index.
pub struct ExpandDeferredInput<'a, F: ark_ff::FftField + PrimeField> {
    pub plonk_minimal: &'a crate::statement::PlonkMinimal,
    pub bulletproof_challenges: &'a [BulletproofChallenge],
    pub sponge_digest_before_evaluations: F,

    pub evaluations: &'a kimchi::proof::ProofEvaluations<kimchi::proof::PointEvaluations<F>>,
    pub public_evals: &'a kimchi::proof::PointEvaluations<F>,
    pub ft_eval1: F,
    pub public_input_chunks: &'a [F],
    /// Already endo-expanded (step-field), one vector per previous proof.
    pub old_bulletproof_challenges: &'a [Vec<F>],

    pub shifts: [F; 7],
    pub generator: F,
    pub domain_log2: u32,
    pub zk_rows: u32,
    pub srs_length_log2: u32,
    /// Scalar endo for the step inner curve (Vesta's scalar endo, λ_Vesta in
    /// Fp). Used for endo-expanding scalar challenges (alpha, zeta, xi, r,
    /// bp_chals). Mirrors OCaml `Endo.Wrap_inner_curve.scalar`.
    pub endo: F,
    /// Linearization Constants `endo_coefficient` — the cube root of unity
    /// in the step inner curve's BASE field (Pallas's base endo, ξ_Pallas
    /// in Fp). DIFFERENT from `endo` above. Mirrors OCaml
    /// `Endo.Step_inner_curve.base`.
    pub linearization_endo_coefficient: F,

    pub linearization_constant_term: &'a [kimchi::circuits::expr::PolishToken<
        F,
        kimchi::circuits::berkeley_columns::Column,
        kimchi::circuits::berkeley_columns::BerkeleyChallengeTerm,
    >],
    pub domain: ark_poly::Radix2EvaluationDomain<F>,
    pub mds: &'static [[F; 3]; 3],

    pub sponge_params: &'static SpongeParams<F>,
}

/// Output of [`expand_deferred`] — the set of derived scalars the wrap
/// statement commits to, plus the newly sampled challenges and auxiliary
/// values `run_checks` asserts against the carried claims.
#[allow(dead_code)]
pub struct ExpandedDeferred<F> {
    pub plonk: DerivedPlonk<F>,
    pub combined_inner_product: F,
    /// Raw 128-bit form of the sampled batching challenge `xi`, carried
    /// through `expand_deferred` to match the wrap statement's shape.
    pub xi_raw: crate::statement::ScalarChallenge,
    /// Endo-expanded `xi` used in CIP batching.
    pub xi_field: F,
    /// Endo-expanded `r` (the pickles point-combining challenge).
    pub r_field: F,
    /// Endo-expanded `zeta` (from `plonk_minimal.zeta`).
    pub zeta_field: F,
    /// `zeta * generator` — the second evaluation point.
    pub zetaw: F,
    /// `ft_eval0` computed via [`ft_eval0`].
    pub ft_eval0: F,
    /// `b = b_poly(new_bp_chals, zeta) + r * b_poly(new_bp_chals, zetaw)`.
    pub b: F,
    /// Endo-expanded bp challenges for the current proof.
    pub new_bulletproof_challenges: Vec<F>,
}

fn scalar_challenge_to_limbs<F: PrimeField>(c: &PoseidonScalarChallenge<F>) -> [u64; 2] {
    let bigint = c.inner().into_bigint();
    let limbs = bigint.as_ref();
    [limbs[0], limbs[1]]
}

/// Sub-sponge that digests all expanded previous-proof bp challenges into
/// one field element. Mirrors OCaml `wrap_deferred_values.ml:128-137` — a
/// fresh kimchi sponge absorbs every challenge (outer × inner) then
/// squeezes one element.
fn challenges_digest<F: PrimeField>(
    old_bulletproof_challenges: &[Vec<F>],
    params: &'static SpongeParams<F>,
) -> F {
    use mina_poseidon::poseidon::Sponge;
    let mut s = <ArithmeticSpongeKimchi<F> as Sponge<F, F, FULL_ROUNDS>>::new(params);
    for inner in old_bulletproof_challenges {
        s.absorb(inner);
    }
    s.squeeze()
}

/// Port of OCaml `Wrap_deferred_values.expand_deferred`
/// (`mina/src/lib/crypto/pickles/wrap_deferred_values.ml:17-193`).
///
/// Replays the Fiat–Shamir sponge from the carried
/// `sponge_digest_before_evaluations` checkpoint to recover `xi` and `r`,
/// then composes [`derive_plonk`], [`ft_eval0`], [`combined_inner_product`],
/// and [`compute_bp_chals_and_b`] to produce the full
/// [`ExpandedDeferred`] that `run_checks` will compare against the
/// statement's claimed values.
pub fn expand_deferred<F: ark_ff::FftField + PrimeField>(
    input: ExpandDeferredInput<'_, F>,
) -> Result<
    ExpandedDeferred<F>,
    kimchi::circuits::expr::ExprError<kimchi::circuits::berkeley_columns::Column>,
> {
    use kimchi::plonk_sponge::FrSponge as _;

    // 1. Endo-expand zeta and derive zetaw.
    let zeta_field = endo_expand_scalar(&input.plonk_minimal.zeta, &input.endo);
    let zetaw = zeta_field * input.generator;

    // 2. Sub-sponge: digest previous bp challenges.
    let prev_chals_digest =
        challenges_digest(input.old_bulletproof_challenges, input.sponge_params);

    // 3. Main sponge replay to sample xi and r.
    let mut fr_sponge = FrSpongeKimchi::<F>::from(input.sponge_params);
    fr_sponge.absorb(&input.sponge_digest_before_evaluations);
    fr_sponge.absorb(&prev_chals_digest);
    fr_sponge.absorb(&input.ft_eval1);
    fr_sponge.absorb(&input.public_evals.zeta);
    fr_sponge.absorb(&input.public_evals.zeta_omega);

    let pe = input.evaluations;
    // Absorption order matches kimchi's `FrSponge::absorb_evaluations`
    // (plonk_sponge.rs:55): z, 6 selectors, 15 witness, 15 coefficients,
    // 6 sigma. Each point: zeta then zeta_omega.
    let ordered: [&kimchi::proof::PointEvaluations<F>; 7] = [
        &pe.z,
        &pe.generic_selector,
        &pe.poseidon_selector,
        &pe.complete_add_selector,
        &pe.mul_selector,
        &pe.emul_selector,
        &pe.endomul_scalar_selector,
    ];
    for p in ordered
        .iter()
        .copied()
        .chain(pe.w.iter())
        .chain(pe.coefficients.iter())
        .chain(pe.s.iter())
    {
        fr_sponge.absorb(&p.zeta);
        fr_sponge.absorb(&p.zeta_omega);
    }

    let xi_sc = fr_sponge.challenge();
    let r_sc = fr_sponge.challenge();
    let xi_limbs = scalar_challenge_to_limbs(&xi_sc);
    let xi_field = xi_sc.to_field(&input.endo);
    let r_field = r_sc.to_field(&input.endo);

    // 4. derive_plonk.
    let mut w_arr = [F::zero(); 7];
    for (i, slot) in w_arr.iter_mut().enumerate() {
        *slot = pe.w[i].zeta;
    }
    let mut sigma_arr = [F::zero(); 6];
    for (i, slot) in sigma_arr.iter_mut().enumerate() {
        *slot = pe.s[i].zeta;
    }
    let plonk = derive_plonk(DerivePlonkInput {
        plonk_minimal: input.plonk_minimal,
        w: w_arr,
        sigma: sigma_arr,
        z_zeta: pe.z.zeta,
        z_omega_times_zeta: pe.z.zeta_omega,
        shifts: input.shifts,
        generator: input.generator,
        domain_log2: input.domain_log2,
        zk_rows: input.zk_rows,
        srs_length_log2: input.srs_length_log2,
        endo: input.endo,
    });

    // 5. ft_eval0.
    let ft_eval0_val = ft_eval0(FtEval0Input {
        plonk_minimal: input.plonk_minimal,
        evaluations: input.evaluations,
        public_input_chunks: input.public_input_chunks,
        shifts: input.shifts,
        generator: input.generator,
        domain_log2: input.domain_log2,
        zk_rows: input.zk_rows,
        srs_length_log2: input.srs_length_log2,
        endo: input.endo,
        linearization_endo_coefficient: input.linearization_endo_coefficient,
        linearization_constant_term: input.linearization_constant_term,
        domain: input.domain,
        mds: input.mds,
    })?;

    // 6. combined_inner_product.
    let cip = combined_inner_product(CombinedInnerProductInput {
        evaluations: input.evaluations,
        public_evals: input.public_evals,
        ft_eval1: input.ft_eval1,
        ft_eval0: ft_eval0_val,
        old_bulletproof_challenges: input.old_bulletproof_challenges,
        xi: xi_field,
        r: r_field,
        zeta: zeta_field,
        zetaw,
    });

    // 7. Current proof's bulletproof challenges + b.
    let bp = compute_bp_chals_and_b(
        input.bulletproof_challenges,
        &input.endo,
        zeta_field,
        zetaw,
        r_field,
    );

    Ok(ExpandedDeferred {
        plonk,
        combined_inner_product: cip,
        xi_raw: crate::statement::ScalarChallenge {
            inner: Challenge(xi_limbs),
        },
        xi_field,
        r_field,
        zeta_field,
        zetaw,
        ft_eval0: ft_eval0_val,
        b: bp.b,
        new_bulletproof_challenges: bp.chals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use mina_curves::pasta::Fp;

    #[test]
    fn horner_fold_empty_is_zero() {
        let pt = Fp::from(7u64);
        assert_eq!(horner_fold(3, pt, &[]), Fp::zero());
    }

    #[test]
    fn horner_fold_single_chunk_is_that_chunk() {
        let pt = Fp::from(7u64);
        let e = Fp::from(42u64);
        // With one chunk, the fold reduces to `e + pt_n * 0 = e`.
        assert_eq!(horner_fold(3, pt, &[e]), e);
    }

    #[test]
    fn horner_fold_horner_matches_definition() {
        // pt_n = 2^(2^0) = 2, chunks = [3, 5, 7]
        // expected: 3 + 2*5 + 4*7 = 3 + 10 + 28 = 41
        let pt = Fp::from(2u64);
        let chunks = [Fp::from(3u64), Fp::from(5u64), Fp::from(7u64)];
        assert_eq!(horner_fold(0, pt, &chunks), Fp::from(41u64));
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
}
