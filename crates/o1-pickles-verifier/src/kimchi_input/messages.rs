//! Poseidon digests of the two messages-for-next-* records carried by
//! the wrap statement.
//!
//! These digests sit in the wrap circuit's public input (packed by
//! `tock_unpadded_public_input_of_statement`). The wrap circuit commits
//! to them, so if a verifier feeds kimchi the wrong digest, the proof
//! won't verify.
//!
//! Ports:
//! * [`hash_messages_for_next_step_proof`] — OCaml
//!   `Common.hash_messages_for_next_step_proof`
//!   (`mina/src/lib/crypto/pickles/common.ml:45-52`). Fp (step field).
//! * [`hash_messages_for_next_wrap_proof`] — OCaml
//!   `Wrap_hack.hash_messages_for_next_wrap_proof`
//!   (`mina/src/lib/crypto/pickles/wrap_hack.ml:46-59`). Fq (wrap field),
//!   with front-padding via deterministic dummy challenges.

extern crate alloc;

use alloc::vec::Vec;

use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s256, Digest};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::{fp_kimchi, fq_kimchi, FULL_ROUNDS};
use mina_poseidon::poseidon::{ArithmeticSponge, Sponge};
use mina_poseidon::sponge::ScalarChallenge as PoseidonScalarChallenge;
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::{endos, SRS};

use crate::{Fp, Fq, Pallas, Vesta};

type FpSponge = ArithmeticSponge<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
type FqSponge = ArithmeticSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;

/// Pickles' fixed wrap-hack padding length — every proof's outer
/// `old_bulletproof_challenges` is padded to length 2 by prepending
/// dummies (`Wrap_hack.Padded_length.n = 2`).
pub const WRAP_HACK_PADDED_LENGTH: usize = 2;

/// Step-side IPA rounds = Tick.Rounds.n = 16.
pub const STEP_IPA_ROUNDS: usize = 16;

/// Wrap-side IPA rounds = Tock.Rounds.n = 15.
pub const WRAP_IPA_ROUNDS: usize = 15;

/// Verification-key commitments from the wrap VK. Fed into the step-side
/// digest in kimchi-fixed order (`index_to_field_elements` in
/// `pickles_base/side_loaded_verification_key.ml:154-178`).
///
/// `CanonicalSerialize`/`Deserialize` lets us bake the extracted
/// commitments into the SP1 guest's read-only memory at build time
/// (see `crates/o1-verifier/build.rs`) instead of recomputing the
/// per-Pallas-point chunking on every guest run.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct WrapVkCommitments {
    /// 7 sigma commitments (`PERMUTS = 7`).
    pub sigma_comm: [Pallas; 7],
    /// 15 coefficient-polynomial commitments (`COLUMNS = 15`).
    pub coefficients_comm: [Pallas; 15],
    pub generic_comm: Pallas,
    pub psm_comm: Pallas,
    pub complete_add_comm: Pallas,
    pub mul_comm: Pallas,
    pub emul_comm: Pallas,
    pub endomul_scalar_comm: Pallas,
}

impl WrapVkCommitments {
    /// Pull the 28 single-chunk wrap-VK commitments out of a kimchi
    /// `VerifierIndex` in pickles `index_to_field_elements` order.
    /// Single-chunk: standard pickles wrap circuits are non-chunked.
    pub fn extract(
        vi: &kimchi::verifier_index::VerifierIndex<FULL_ROUNDS, Pallas, SRS<Pallas>>,
    ) -> Self {
        fn first_chunk(c: &PolyComm<Pallas>) -> Pallas {
            assert_eq!(c.chunks.len(), 1, "expected single-chunk commitment");
            c.chunks[0]
        }
        Self {
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
}

/// One previous proof's contribution to the step-side digest: its
/// challenge-polynomial commitment (Pallas, wrap-side) plus its
/// endo-expanded step-field bulletproof challenges.
pub struct StepPrevProof {
    pub challenge_polynomial_commitment: Pallas,
    pub expanded_bulletproof_challenges: [Fp; STEP_IPA_ROUNDS],
}

/// Poseidon digest over the step proof's `messages_for_next_step_proof`.
///
/// Absorption order (Fp, kimchi sponge params):
/// 1. VK commitments in `index_to_field_elements` order:
///    `sigma_comm[0..7]`, `coefficients_comm[0..15]`, then
///    `generic, psm, complete_add, mul, emul, endomul_scalar`.
///    Each point absorbs as `(x, y)`.
/// 2. `app_state` fields (already reduced to Fp by the caller).
/// 3. For each previous proof: `(sg.x, sg.y)` then the 16
///    endo-expanded bp challenges.
///
/// Squeezes one Fp.
pub fn hash_messages_for_next_step_proof(
    vk: &WrapVkCommitments,
    app_state: &[Fp],
    prev_proofs: &[StepPrevProof],
) -> Fp {
    let mut sponge: FpSponge =
        <FpSponge as Sponge<Fp, Fp, FULL_ROUNDS>>::new(fp_kimchi::static_params());

    // VK commitments (28 points × 2 coords = 56 Fp).
    for p in &vk.sigma_comm {
        absorb_pallas(&mut sponge, p);
    }
    for p in &vk.coefficients_comm {
        absorb_pallas(&mut sponge, p);
    }
    for p in [
        &vk.generic_comm,
        &vk.psm_comm,
        &vk.complete_add_comm,
        &vk.mul_comm,
        &vk.emul_comm,
        &vk.endomul_scalar_comm,
    ] {
        absorb_pallas(&mut sponge, p);
    }

    // App state.
    sponge.absorb(app_state);

    // Per-proof (sg, expanded bp chals).
    for prev in prev_proofs {
        absorb_pallas(&mut sponge, &prev.challenge_polynomial_commitment);
        sponge.absorb(&prev.expanded_bulletproof_challenges);
    }

    sponge.squeeze()
}

/// Poseidon digest over the wrap proof's `messages_for_next_wrap_proof`,
/// with front-padding to [`WRAP_HACK_PADDED_LENGTH`] via deterministic
/// dummy challenges.
///
/// Inputs:
/// * `challenge_polynomial_commitment`: Vesta point (coords in Fq).
/// * `expanded_old_bulletproof_challenges`: outer length ≤ 2; each inner
///   is 15 already-endo-expanded Fq challenges (wrap IPA rounds).
///
/// Absorption order (Fq):
/// 1. Padding dummies up to outer length 2 — 15 Fq per dummy vector.
/// 2. Real expanded challenges (15 Fq per vector).
/// 3. `(sg.x, sg.y)` — 2 Fq.
///
/// Squeezes one Fq.
pub fn hash_messages_for_next_wrap_proof(
    challenge_polynomial_commitment: &Vesta,
    expanded_old_bulletproof_challenges: &[[Fq; WRAP_IPA_ROUNDS]],
) -> Fq {
    assert!(
        expanded_old_bulletproof_challenges.len() <= WRAP_HACK_PADDED_LENGTH,
        "outer len must be ≤ Wrap_hack.Padded_length.n = {}",
        WRAP_HACK_PADDED_LENGTH
    );

    let mut sponge: FqSponge =
        <FqSponge as Sponge<Fq, Fq, FULL_ROUNDS>>::new(fq_kimchi::static_params());

    let dummy = dummy_ipa_wrap_challenges_expanded();
    let pad_n = WRAP_HACK_PADDED_LENGTH - expanded_old_bulletproof_challenges.len();
    for _ in 0..pad_n {
        sponge.absorb(&dummy);
    }
    for chals in expanded_old_bulletproof_challenges {
        sponge.absorb(chals);
    }

    let (x, y) = challenge_polynomial_commitment
        .xy()
        .expect("wrap proof's challenge_polynomial_commitment must not be infinity");
    sponge.absorb(&[x, y]);

    sponge.squeeze()
}

fn absorb_pallas(sponge: &mut FpSponge, p: &Pallas) {
    let (x, y) = p
        .xy()
        .expect("wrap VK / prev-proof commitment must not be infinity");
    sponge.absorb(&[x, y]);
}

/// Deterministic 15 wrap-side IPA dummy challenges, already endo-expanded
/// to Fq. Matches OCaml `Dummy.Ipa.Wrap.challenges_computed` (via the
/// shared `Ro.chal` Blake2s oracle).
///
/// `Vector.init` in OCaml evaluates right-to-left so index 0 gets the
/// last-drawn challenge (counter = 15) and index 14 the first-drawn
/// (counter = 1). Callers absorb in storage order, which is what this
/// function returns.
pub fn dummy_ipa_wrap_challenges_expanded() -> [Fq; WRAP_IPA_ROUNDS] {
    let (_endo_q, endo_r) = endos::<Pallas>();
    let mut out = [Fq::from(0u64); WRAP_IPA_ROUNDS];
    for (i, slot) in out.iter_mut().enumerate() {
        // position 0 → chal_15, …, position 14 → chal_1
        let counter = WRAP_IPA_ROUNDS - i;
        let limbs = chal_oracle_limbs(counter);
        *slot = PoseidonScalarChallenge::<Fq>::from_limbs(limbs).to_field(&endo_r);
    }
    out
}

/// Produce the 128-bit challenge for `Ro.chal` counter `n`, returned as
/// two u64 limbs (LSB-first). Mirrors OCaml
/// `Ro.chal = ro "chal" 128 of_bits`: blake2s-256 of `"chal_<n>"`, take
/// first 128 bits LSB-first per byte, pack into `[low, high]`.
fn chal_oracle_limbs(n: usize) -> [u64; 2] {
    use alloc::format;
    let mut hasher = Blake2s256::new();
    hasher.update(format!("chal_{}", n).as_bytes());
    let bytes = hasher.finalize();

    // Take first 128 bits, LSB-first within each byte (`(c >> i) & 1`),
    // bytes in natural order — same as OCaml's `bits_random_oracle`.
    let mut limbs = [0u64; 2];
    for bit_idx in 0..128 {
        let byte = bytes[bit_idx / 8];
        let bit = (byte >> (bit_idx % 8)) & 1 == 1;
        if bit {
            limbs[bit_idx / 64] |= 1u64 << (bit_idx % 64);
        }
    }
    limbs
}
