//! Pack the wrap statement into the kimchi public-input `Vec<Fq>`.
//!
//! Stage 3 of `verifyOne`. Port of OCaml
//! `Common.tock_unpadded_public_input_of_statement` via PureScript
//! `Pickles.Prove.Pure.Wrap.{assembleWrapMainInput, packBranchDataWrap}`.
//!
//! Inputs (all step-side / Fp values from `expand_deferred` + helpers):
//! * 5 unshifted "real" values: `cip, b, perm, zeta_to_domain_size,
//!   zeta_to_srs_length`. We apply `Shifted_value.Type1.of_field` here
//!   (our `expand_deferred` returns unshifted values) and then
//!   cross-field embed Fp → Fq.
//! * 5 raw 128-bit challenges: `beta, gamma, alpha, zeta, xi`.
//! * 3 digests: `sponge_digest_before_evaluations` (Fp),
//!   `messages_for_next_step_proof` digest (Fp),
//!   `messages_for_next_wrap_proof` digest (Fq).
//! * 16 raw 128-bit step-IPA bulletproof prechallenges.
//! * `BranchData` (proofs_verified_mask + domain_log2).
//! * `feature_flags` (8 booleans, all zero for Simple_chain).
//!
//! Cross-references:
//! * OCaml: `mina/src/lib/crypto/plonkish_prelude/shifted_value.ml`
//! * PS: `l-adic/snarky/packages/pickles/src/Pickles/Prove/Pure/Wrap.purs`
//!   lines 390-470 (the leaf encoders) and 495-569 (`assembleWrapMainInput`).

extern crate alloc;

use alloc::vec::Vec;

use ark_ff::PrimeField;

use crate::statement::{BranchData, BulletproofChallenge, Challenge, ProofsVerified};
use crate::{Fp, Fq};

// ---- shift constants ----------------------------------------------------

/// `Shifted_value.Type1.Shift.c` for Fp: `2^Fp::MODULUS_BIT_SIZE + 1` mod p.
fn shift1_c<F: PrimeField>() -> F {
    F::from(2u64).pow([u64::from(F::MODULUS_BIT_SIZE)]) + F::one()
}

/// `Shifted_value.Type1.Shift.scale` for any prime field: `1/2`.
fn shift1_scale<F: PrimeField>() -> F {
    F::from(2u64)
        .inverse()
        .expect("2 is invertible in any prime field")
}

/// OCaml `Shifted_value.Type1.of_field shift s = (s - c) * scale`.
/// Maps a "real" field value to its Type1 shifted form.
pub fn shifted_value_type1_of_field<F: PrimeField>(real: F) -> F {
    (real - shift1_c::<F>()) * shift1_scale::<F>()
}

// ---- cross-field encoders -----------------------------------------------

/// Reinterpret an Fp value as Fq via bigint. Used for digests, Type1
/// values, and Sized128 challenges. The `_mod_order` reduction handles
/// Fp values that happen to exceed the Fq modulus (rare: only the top
/// ~2^126 of values, since Fp and Fq differ by < 2^126 for Pasta).
pub fn cross_field_step_to_wrap(v: Fp) -> Fq {
    let bigint = v.into_bigint();
    let bytes = ark_ff::BigInteger::to_bytes_le(&bigint);
    Fq::from_le_bytes_mod_order(&bytes)
}

/// Embed a 128-bit raw challenge into Fq directly (no cross-field needed
/// because 128 bits fit in any Pasta field). Mirrors PS
/// `crossFieldSized128`: bigint round-trip, equivalent to `Fq::from(u128)`.
pub fn pack_sized128(c: &Challenge) -> Fq {
    let lo = c.0[0] as u128;
    let hi = c.0[1] as u128;
    Fq::from(lo | (hi << 64))
}

/// `pack_type1_step real_fp = cross_field(of_field(real_fp))`.
///
/// Step-side `derive_plonk` and `expand_deferred` produce **unshifted**
/// "real" Fp values (`cip, b, perm, zeta_to_*`). For the wrap circuit's
/// public input we apply `Shifted_value.Type1.of_field` first (yielding
/// the Type1 inner Fp), then cross-field embed into Fq. Mirrors PS
/// `crossFieldType1Step` after algebraic simplification — see
/// `Pickles/Prove/Pure/Wrap.purs:400-402` and the same-/cross-field
/// `Shifted` instances in
/// `Snarky/Types/Shifted.purs:217-248`.
pub fn pack_type1_step(real_fp: Fp) -> Fq {
    cross_field_step_to_wrap(shifted_value_type1_of_field::<Fp>(real_fp))
}

// ---- branch_data --------------------------------------------------------

/// Pack `BranchData` into a single Fq.
///
/// PS `Pickles/Prove/Pure/Wrap.purs:447-470`. Encoding:
/// `4 · domain_log2 + mask[0] + 2 · mask[1]`, where `mask` is the
/// length-2 reversed ones-vector encoding `proofs_verified_mask` (i.e.,
/// for `proofs_verified ∈ {N0, N1, N2}` → mask ∈ {[F,F], [F,T], [T,T]}).
pub fn pack_branch_data_wrap(bd: &BranchData) -> Fq {
    // mask[i] = (i >= MASK_WIDTH - most_recent_width). With MASK_WIDTH = 2:
    //   N0 → most_recent_width = 0 → mask = [false, false]
    //   N1 → most_recent_width = 1 → mask = [false, true]
    //   N2 → most_recent_width = 2 → mask = [true,  true]
    let (m0, m1): (u64, u64) = match bd.proofs_verified {
        ProofsVerified::N0 => (0, 0),
        ProofsVerified::N1 => (0, 1),
        ProofsVerified::N2 => (1, 1),
    };
    let log2 = u64::from(bd.domain_log2);
    Fq::from(4u64 * log2 + m0 + 2 * m1)
}

// ---- packed structure + flatten ----------------------------------------

/// Cross-references:
/// PS `WrapStatementPacked` (l-adic/snarky/.../Pickles/Types.purs)
/// instantiated as `WrapStatementPacked StepIPARounds (Type1 (F WrapField))
/// (F WrapField) Boolean`. We flatten directly to `Vec<Fq>` matching the
/// OCaml `to_data` order used by `tock_unpadded_public_input_of_statement`.
pub struct WrapStatementPacked {
    /// 5 Type1 cross-field shifted Fq values:
    /// `[cip, b, zeta_to_srs_length, zeta_to_domain_size, perm]`.
    pub fp_fields: [Fq; 5],
    /// 2 raw 128-bit challenges: `[beta, gamma]`.
    pub challenges: [Fq; 2],
    /// 3 raw 128-bit scalar challenges: `[alpha, zeta, xi]`.
    pub scalar_challenges: [Fq; 3],
    /// 3 digests: `[sponge_digest, messages_for_next_wrap, messages_for_next_step]`.
    pub digests: [Fq; 3],
    /// 16 raw 128-bit step-IPA prechallenges.
    pub bulletproof_challenges: [Fq; 16],
    pub branch_data: Fq,
    /// 8 feature flags as Fq (all zero for Simple_chain).
    pub feature_flags: [Fq; 8],
    /// Lookup-feature-flag slot (zero for Simple_chain).
    pub lookup_opt_flag: Fq,
    /// Lookup scalar challenge slot (zero for Simple_chain).
    pub lookup_opt_scalar_challenge: Fq,
}

impl WrapStatementPacked {
    /// Flatten to the kimchi public-input `Vec<Fq>` in OCaml `to_data`
    /// order. Total length: 5 + 2 + 3 + 3 + 16 + 1 + 8 + 2 = 40.
    pub fn to_fq_vec(&self) -> Vec<Fq> {
        let mut v: Vec<Fq> = Vec::with_capacity(40);
        v.extend_from_slice(&self.fp_fields);
        v.extend_from_slice(&self.challenges);
        v.extend_from_slice(&self.scalar_challenges);
        v.extend_from_slice(&self.digests);
        v.extend_from_slice(&self.bulletproof_challenges);
        v.push(self.branch_data);
        v.extend_from_slice(&self.feature_flags);
        v.push(self.lookup_opt_flag);
        v.push(self.lookup_opt_scalar_challenge);
        v
    }
}

// ---- assembly -----------------------------------------------------------

/// Inputs to [`assemble_wrap_main_input`]. Mirrors PS
/// `AssembleWrapMainInputInput` (the `WrapDeferredValuesOutput` plus the
/// two precomputed message digests), unpacked into the individual fields
/// our `ExpandedDeferred` carries.
pub struct AssembleInput<'a> {
    /// Unshifted CIP from `expand_deferred`.
    pub combined_inner_product: Fp,
    /// Unshifted b from `expand_deferred`.
    pub b: Fp,
    /// Unshifted permutation scalar from `derive_plonk`.
    pub perm: Fp,
    /// Unshifted `zeta^domain_size` from `derive_plonk`.
    pub zeta_to_domain_size: Fp,
    /// Unshifted `zeta^(2^srs_length_log2)` from `derive_plonk`.
    pub zeta_to_srs_length: Fp,
    /// Raw 128-bit `[beta, gamma]` (`PlonkMinimal` plain challenges).
    pub beta: &'a Challenge,
    pub gamma: &'a Challenge,
    /// Raw 128-bit `[alpha, zeta, xi]` (`PlonkMinimal` scalar challenges +
    /// the sponge-sampled xi).
    pub alpha: &'a Challenge,
    pub zeta: &'a Challenge,
    pub xi: &'a Challenge,
    /// `sponge_digest_before_evaluations` carried by the wrap statement.
    pub sponge_digest_fp: Fp,
    /// `Common.hash_messages_for_next_step_proof` output (Fp).
    pub messages_for_next_step_digest_fp: Fp,
    /// `Wrap_hack.hash_messages_for_next_wrap_proof` output (Fq).
    pub messages_for_next_wrap_digest_fq: Fq,
    /// 16 step-IPA prechallenges from `deferred_values.bulletproof_challenges`.
    pub bulletproof_challenges: &'a [BulletproofChallenge; 16],
    pub branch_data: &'a BranchData,
    /// Wrap-circuit feature flags. For Simple_chain (no optional gates,
    /// no lookups), all 8 are `false`.
    pub feature_flags: [bool; 8],
}

pub fn assemble_wrap_main_input(input: AssembleInput<'_>) -> WrapStatementPacked {
    let fp_fields = [
        pack_type1_step(input.combined_inner_product),
        pack_type1_step(input.b),
        pack_type1_step(input.zeta_to_srs_length),
        pack_type1_step(input.zeta_to_domain_size),
        pack_type1_step(input.perm),
    ];

    let challenges = [pack_sized128(input.beta), pack_sized128(input.gamma)];

    let scalar_challenges = [
        pack_sized128(input.alpha),
        pack_sized128(input.zeta),
        pack_sized128(input.xi),
    ];

    let digests = [
        cross_field_step_to_wrap(input.sponge_digest_fp),
        input.messages_for_next_wrap_digest_fq,
        cross_field_step_to_wrap(input.messages_for_next_step_digest_fp),
    ];

    let mut bulletproof_challenges = [Fq::from(0u64); 16];
    for (slot, bc) in bulletproof_challenges
        .iter_mut()
        .zip(input.bulletproof_challenges.iter())
    {
        *slot = pack_sized128(&bc.prechallenge.inner);
    }

    let branch_data = pack_branch_data_wrap(input.branch_data);

    let feature_flags: [Fq; 8] = core::array::from_fn(|i| {
        if input.feature_flags[i] {
            Fq::from(1u64)
        } else {
            Fq::from(0u64)
        }
    });

    WrapStatementPacked {
        fp_fields,
        challenges,
        scalar_challenges,
        digests,
        bulletproof_challenges,
        branch_data,
        feature_flags,
        lookup_opt_flag: Fq::from(0u64),
        lookup_opt_scalar_challenge: Fq::from(0u64),
    }
}

// ---- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn shift_constants_round_trip() {
        // of_field(real) followed by Shifted_value.Type1.to_field should
        // recover real: to_field(t) = 2t + c, of_field(s) = (s - c)/2.
        let real = Fp::from(123456789u64);
        let shifted = shifted_value_type1_of_field::<Fp>(real);
        let back = shifted + shifted + shift1_c::<Fp>();
        assert_eq!(back, real);
    }

    #[test]
    fn pack_sized128_matches_u128() {
        let c = Challenge([0xDEADBEEF_DEADBEEFu64, 0x1234_5678_9ABC_DEF0u64]);
        let got = pack_sized128(&c);
        let expected = Fq::from(0xDEADBEEF_DEADBEEFu128 | (0x1234_5678_9ABC_DEF0u128 << 64));
        assert_eq!(got, expected);
    }

    #[test]
    fn pack_branch_data_simple_chain() {
        // Simple_chain: proofs_verified = N1, domain_log2 = 14.
        // Mask for N1 is [false, true] → m0=0, m1=1.
        // Packed = 4*14 + 0 + 2*1 = 58.
        let bd = BranchData {
            proofs_verified: ProofsVerified::N1,
            domain_log2: 14,
        };
        assert_eq!(pack_branch_data_wrap(&bd), Fq::from(58u64));
    }

    #[test]
    fn pack_branch_data_n0_n2_masks() {
        // N0: mask = [false, false] → 0
        let bd0 = BranchData {
            proofs_verified: ProofsVerified::N0,
            domain_log2: 0,
        };
        assert_eq!(pack_branch_data_wrap(&bd0), Fq::from(0u64));
        // N2: mask = [true, true] → m0=1, m1=2; with log2=10 → 4*10 + 1 + 2 = 43
        let bd2 = BranchData {
            proofs_verified: ProofsVerified::N2,
            domain_log2: 10,
        };
        assert_eq!(pack_branch_data_wrap(&bd2), Fq::from(43u64));
    }

    #[test]
    fn cross_field_zero_is_zero() {
        assert_eq!(cross_field_step_to_wrap(Fp::zero()), Fq::zero());
    }

    #[test]
    fn cross_field_small_values_are_identity() {
        // Values < min(p, q) round-trip cleanly.
        let v = Fp::from(42u64);
        let w = cross_field_step_to_wrap(v);
        assert_eq!(w, Fq::from(42u64));
    }

    #[test]
    fn pallas_scalar_endo_and_vesta_base_endo_are_distinct() {
        // Symmetric to the Vesta-scalar/Pallas-base test below: this is the
        // pair relevant for the WRAP verifier index (kimchi proof on Pallas).
        // OCaml's kimchi-stubs sets a Pallas VI's `vi.endo` to
        // `endos::<Vesta>().0` (Vesta BaseField cube root, in Fq), NOT
        // `endos::<Pallas>().1` (Pallas ScalarField endo via orientation
        // check, also in Fq). When these differ, our generic loader's
        // `G::endos().1` produces the wrong wrap-VI endo.
        let pallas_scalar_endo = poly_commitment::ipa::endos::<crate::Pallas>().1;
        let vesta_base_endo = poly_commitment::ipa::endos::<crate::Vesta>().0;
        assert_ne!(pallas_scalar_endo, vesta_base_endo);
    }

    #[test]
    fn vesta_scalar_endo_and_pallas_base_endo_are_distinct() {
        // Symmetric pair for the STEP verifier index (kimchi proof on
        // Vesta). OCaml's kimchi-stubs sets a Vesta VI's `vi.endo` to
        // `endos::<Pallas>().0` (Pallas BaseField cube root, in Fp), NOT
        // `endos::<Vesta>().1`. If these values differ, our generic
        // `load_vesta_verifier_index` (which uses `G::endos().1`) has
        // the same latent bug as the Pallas one before we patched it.
        //
        // It also matters for the step-side deferred-values pipeline:
        // * `Endo.Wrap_inner_curve.scalar = Vesta.endo_scalar()` is used
        //   for endo-expanding step-side scalar challenges (sc).
        // * `Endo.Step_inner_curve.base = Pallas.endo_base()` is used
        //   for the `endo_coefficient` constant inside the step
        //   linearization Constants.
        let vesta_scalar_endo = poly_commitment::ipa::endos::<crate::Vesta>().1;
        let pallas_base_endo = poly_commitment::ipa::endos::<crate::Pallas>().0;
        assert_ne!(vesta_scalar_endo, pallas_base_endo);
    }

    #[test]
    fn flatten_length_is_40() {
        let zero_fq = Fq::zero();
        let packed = WrapStatementPacked {
            fp_fields: [zero_fq; 5],
            challenges: [zero_fq; 2],
            scalar_challenges: [zero_fq; 3],
            digests: [zero_fq; 3],
            bulletproof_challenges: [zero_fq; 16],
            branch_data: zero_fq,
            feature_flags: [zero_fq; 8],
            lookup_opt_flag: zero_fq,
            lookup_opt_scalar_challenge: zero_fq,
        };
        assert_eq!(packed.to_fq_vec().len(), 40);
    }
}
