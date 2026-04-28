//! Pack the wrap statement into the kimchi public-input `Vec<Fq>`.
//!
//! Port of OCaml `Common.tock_unpadded_public_input_of_statement`
//! (cross-reference: `mina/src/lib/crypto/plonkish_prelude/shifted_value.ml`).
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
//! * `feature_flags` (8 booleans, none used by typical wrap circuits).

extern crate alloc;

use alloc::vec::Vec;

use ark_ff::PrimeField;

use crate::statement::{BranchData, BulletproofChallenge, Challenge, ProofsVerified};
use crate::{Fp, Fq};

/// OCaml `Shifted_value.Type1.of_field shift s = (s - c) * scale`,
/// where `c = 2^MODULUS_BIT_SIZE + 1` and `scale = 1/2`. Maps a "real"
/// field value to its Type1 shifted form. Generic over any Pasta prime
/// field.
pub fn shifted_value_type1_of_field<F: PrimeField>(real: F) -> F {
    let c = F::from(2u64).pow([u64::from(F::MODULUS_BIT_SIZE)]) + F::one();
    let half = F::from(2u64)
        .inverse()
        .expect("2 is invertible in any prime field");
    (real - c) * half
}

/// Reinterpret an Fp value as Fq via little-endian bytes.
///
/// For Pasta, |Fp| < |Fq|, so every Fp value already fits in Fq and the
/// `_mod_order` reduction never fires — this is an injection. Used for
/// the three contexts this module produces: digests (where we just need
/// a stable bit-pattern in Fq, no algebraic meaning), Sized128 values
/// (128 bits fits in any Pasta field), and Type1 shifted values (whose
/// algebraic meaning is fixed by the wrap circuit's public-input
/// contract — we mirror exactly what the circuit's prover did when
/// producing the public input bytes).
pub fn cross_field_step_to_wrap(v: Fp) -> Fq {
    let bigint = v.into_bigint();
    let bytes = ark_ff::BigInteger::to_bytes_le(&bigint);
    Fq::from_le_bytes_mod_order(&bytes)
}

/// Embed a 128-bit raw challenge into Fq directly (no cross-field needed
/// because 128 bits fits in any Pasta field): bigint round-trip,
/// equivalent to `Fq::from(u128)`.
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
/// the Type1 inner Fp), then cross-field embed into Fq.
pub fn pack_type1_step(real_fp: Fp) -> Fq {
    cross_field_step_to_wrap(shifted_value_type1_of_field::<Fp>(real_fp))
}

/// Pack `BranchData` into a single Fq.
///
/// Encoding: `4 · domain_log2 + mask[0] + 2 · mask[1]`, where `mask` is
/// the length-2 reversed ones-vector encoding `proofs_verified_mask`
/// (i.e., for `proofs_verified ∈ {N0, N1, N2}` → mask ∈ {[F,F], [F,T],
/// [T,T]}).
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

/// Flat representation of `tock_unpadded_public_input_of_statement`'s
/// output, in OCaml `to_data` order.
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
    /// 8 feature flags as Fq.
    pub feature_flags: [Fq; 8],
    pub lookup_opt_flag: Fq,
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

/// Inputs to [`assemble_wrap_main_input`]: the `expand_deferred` output
/// plus the two precomputed message digests, unpacked into the
/// individual fields our `ExpandedDeferred` carries.
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
    /// Wrap-circuit feature flags (8 booleans, one per optional gate or
    /// lookup feature).
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn pack_branch_data_n1() {
        // proofs_verified = N1, domain_log2 = 14.
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
}
