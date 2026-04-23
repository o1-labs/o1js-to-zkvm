//! Pickles wrap statement — the structured input to a pickles verifier.
//!
//! Mirrors the OCaml type
//! `Composition_types.Wrap.Statement.Minimal.t`
//! (mina/src/lib/crypto/pickles/composition_types/composition_types.ml:671)
//! specialized to the concrete type parameters used by pickles' wrap proof
//! record (mina/src/lib/crypto/pickles/proof.mli:72-84).
//!
//! The application's public input is carried opaquely as `Vec<Fp>`; we never
//! parse app-specific structure, only consume the array for hashing via
//! Poseidon during prepared-statement packing.
//!
//! Cross-reference: the PureScript port in
//! `l-adic/snarky/packages/pickles/src/Pickles/Types.purs` defines the same
//! layout with explicit OCaml line citations.

use alloc::vec::Vec;
use mina_curves::pasta::{Fp, Pallas, Vesta};

pub use kimchi::circuits::constraints::FeatureFlags;

/// A 128-bit constant challenge.
///
/// OCaml: `Import.Challenge.Constant.t =
///   Pickles_base.Limb_vector.Constant.t Pickles_types.Nat.N2`.
/// Two big-endian u64 limbs.
#[derive(Clone, Debug)]
pub struct Challenge(pub [u64; 2]);

/// A 256-bit constant digest (used for the sponge digest carried alongside
/// the wrap proof statement).
///
/// OCaml: `Import.Digest.Constant.t =
///   Pickles_base.Limb_vector.Constant.t Pickles_types.Nat.N4`.
#[derive(Clone, Debug)]
pub struct Digest(pub [u64; 4]);

/// A challenge tagged as "scalar" form — a plain wrapper used by pickles to
/// distinguish a challenge-as-field from a challenge-as-curve-endo scalar.
///
/// OCaml: `Import.Scalar_challenge.t = { inner : 'challenge }`
/// (see `mina/src/lib/crypto/kimchi_backend/common/scalar_challenge.ml`).
#[derive(Clone, Debug)]
pub struct ScalarChallenge {
    pub inner: Challenge,
}

/// A bulletproof round challenge.
///
/// OCaml: `Composition_types.Bulletproof_challenge.t = { prechallenge : 'c }`
/// (mina/src/lib/crypto/pickles/composition_types/bulletproof_challenge.ml).
#[derive(Clone, Debug)]
pub struct BulletproofChallenge {
    pub prechallenge: ScalarChallenge,
}

/// A shifted field value — the single-constructor variant pickles uses to
/// mark "this Fp element has been through the `two_to_the` shift."
///
/// OCaml: `Plonkish_prelude.Shifted_value.Type1.t = Shifted_value of 'f`
/// (mina/src/lib/crypto/plonkish_prelude/shifted_value.ml:102).
#[derive(Clone, Debug)]
pub struct ShiftedValue<F>(pub F);

/// Upper bound on how many previous proofs a rule can verify.
///
/// OCaml: `Pickles_base.Proofs_verified.t`
/// (mina/src/lib/pickles/common/nat.ml, exposed via
/// `pickles_base/proofs_verified.ml`).
#[derive(Clone, Copy, Debug)]
pub enum ProofsVerified {
    N0,
    N1,
    N2,
}

/// Branch-selector data packed into a single field element by pickles'
/// circuit.
///
/// OCaml: `Composition_types.Branch_data.t = { proofs_verified; domain_log2 }`
/// where `domain_log2 : char` is a single byte.
/// (mina/src/lib/crypto/pickles/composition_types/branch_data.ml:48-51)
#[derive(Clone, Debug)]
pub struct BranchData {
    pub proofs_verified: ProofsVerified,
    pub domain_log2: u8,
}

/// Plonk challenges, minimal form (in-circuit form unfolds these into
/// derived scalars; the minimal form is what the statement carries).
///
/// OCaml: `Composition_types.Wrap.Proof_state.Deferred_values.Plonk.Minimal.t`
/// (mina/src/lib/crypto/pickles/composition_types/composition_types.ml:35).
#[derive(Clone, Debug)]
pub struct PlonkMinimal {
    pub alpha: ScalarChallenge,
    pub beta: Challenge,
    pub gamma: Challenge,
    pub zeta: ScalarChallenge,
    pub joint_combiner: Option<ScalarChallenge>,
    pub feature_flags: FeatureFlags,
}

/// Deferred values attached to a wrap statement.
///
/// OCaml: `Composition_types.Wrap.Proof_state.Deferred_values.Minimal.t`
/// (mina/src/lib/crypto/pickles/composition_types/composition_types.ml:247).
///
/// The bulletproof challenges are `Step_bp_vec.t` = `Tick.Rounds.n` = 16,
/// because the deferred IPA challenges belong to the **step** proof being
/// wrapped (step proofs live on Vesta, whose rounds count is 16).
#[derive(Clone, Debug)]
pub struct DeferredValues {
    pub plonk: PlonkMinimal,
    pub bulletproof_challenges: [BulletproofChallenge; 16],
    pub branch_data: BranchData,
}

/// Wrap proof state (the first half of the wrap statement).
///
/// OCaml: `Composition_types.Wrap.Proof_state.Minimal.t`
/// (mina/src/lib/crypto/pickles/composition_types/composition_types.ml:439).
#[derive(Clone, Debug)]
pub struct ProofState {
    pub deferred_values: DeferredValues,
    pub sponge_digest_before_evaluations: Digest,
    pub messages_for_next_wrap_proof: MessagesForNextWrapProof,
}

/// Messages produced by this wrap proof for consumption by the next wrap
/// proof in the chain.
///
/// OCaml: `Reduced_messages_for_next_proof_over_same_field.Wrap.t`
/// (mina/src/lib/crypto/pickles/reduced_messages_for_next_proof_over_same_field.mli:89).
///
/// The commitment lives on `Backend.Tock.Inner_curve` = **Vesta** — it's
/// the challenge polynomial over the step side of the pasta cycle, deferred
/// to be verified natively by the next step circuit.
///
/// Each inner `old_bulletproof_challenges` vector has `Wrap_bp_vec.t` =
/// `Tock.Rounds.n` = 15 elements. The outer length equals `mlmb` (the
/// proof's type parameter) — for Simple_chain that's `N1` = 1.
#[derive(Clone, Debug)]
pub struct MessagesForNextWrapProof {
    pub challenge_polynomial_commitment: Vesta,
    pub old_bulletproof_challenges: Vec<[BulletproofChallenge; 15]>,
}

/// Messages produced by the step proof beneath this wrap, for consumption
/// by the next step proof in the chain.
///
/// OCaml: `Reduced_messages_for_next_proof_over_same_field.Step.t`
/// (mina/src/lib/crypto/pickles/reduced_messages_for_next_proof_over_same_field.mli:5-20).
///
/// `app_state` is kept as a flat `Vec<Fp>` — whatever `Typ.value_to_fields`
/// produced OCaml-side. Callers who want a typed view must map indices to
/// fields themselves (e.g., for Simple_chain, `[0] = initial`, `[1] =
/// current`).
///
/// The commitments live on `Backend.Tock.Curve` = **Pallas** — they're the
/// challenge polynomials over the wrap side, deferred to be verified
/// natively by the next wrap circuit.
///
/// Each inner `old_bulletproof_challenges` vector has `Step_bp_vec.t` =
/// `Tick.Rounds.n` = 16 elements. The outer lengths (for commitments and
/// for old-bp) both equal the wrapping proof's `most_recent_width`.
#[derive(Clone, Debug)]
pub struct MessagesForNextStepProof {
    pub app_state: Vec<Fp>,
    pub challenge_polynomial_commitments: Vec<Pallas>,
    pub old_bulletproof_challenges: Vec<[BulletproofChallenge; 16]>,
}

/// Top-level wrap statement, minimal form.
///
/// OCaml: `Composition_types.Wrap.Statement.Minimal.t`
/// (mina/src/lib/crypto/pickles/composition_types/composition_types.ml:671),
/// with the abstract type parameters specialized to the shapes used by the
/// pickles proof record at
/// mina/src/lib/crypto/pickles/proof.mli:72-84.
#[derive(Clone, Debug)]
pub struct WrapStatement {
    pub proof_state: ProofState,
    pub messages_for_next_step_proof: MessagesForNextStepProof,
}
