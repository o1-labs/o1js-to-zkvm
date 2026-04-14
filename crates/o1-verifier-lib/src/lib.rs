extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ark_serialize::CanonicalDeserialize;
use groupmap::GroupMap;
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::curve::KimchiCurve;
use kimchi::linearization::expr_linearization;
use kimchi::proof::ProverProof;
use kimchi::verifier::verify_with_rng;
use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::FULL_ROUNDS;
use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use poly_commitment::commitment::CommitmentCurve;
use poly_commitment::ipa::{OpeningProof, SRS};

pub mod pickles_error;
pub mod pickles_lowering;
#[cfg(feature = "std")]
pub mod pickles_parse;
pub mod pickles_types;
pub mod pickles_verify;
pub use pickles_lowering::*;
pub use pickles_verify::*;

pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;
pub type VestaVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, SRS<Vesta>>;
pub type VestaProof = ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS>;

pub fn deserialize_public_inputs(bytes: &[u8]) -> Vec<Fp> {
    assert!(
        bytes.len().is_multiple_of(32),
        "public input bytes must be a multiple of 32"
    );
    bytes
        .chunks_exact(32)
        .map(|chunk| Fp::deserialize_compressed(chunk).expect("invalid Fp element"))
        .collect()
}

/// Reconstruct FeatureFlags from the VerifierIndex optional commitment fields.
pub fn feature_flags_from_vi(vi: &VestaVerifierIndex) -> FeatureFlags {
    let lookup_features = vi
        .lookup_index
        .as_ref()
        .map(|li| li.lookup_info.features)
        .unwrap_or_default();

    FeatureFlags {
        range_check0: vi.range_check0_comm.is_some(),
        range_check1: vi.range_check1_comm.is_some(),
        foreign_field_add: vi.foreign_field_add_comm.is_some(),
        foreign_field_mul: vi.foreign_field_mul_comm.is_some(),
        xor: vi.xor_comm.is_some(),
        rot: vi.rot_comm.is_some(),
        lookup_features,
    }
}

/// Deserialize a VerifierIndex + SRS from msgpack bytes and reconstruct
/// all #[serde(skip)] fields needed for verification.
pub fn load_verifier_index(vi_bytes: &[u8], srs_bytes: &[u8]) -> VestaVerifierIndex {
    let mut vi: VestaVerifierIndex =
        rmp_serde::from_slice(vi_bytes).expect("failed to deserialize VerifierIndex");
    let srs: SRS<Vesta> = rmp_serde::from_slice(srs_bytes).expect("failed to deserialize SRS");
    vi.srs = Arc::new(srs);

    let (_, endo) = Vesta::endos();
    vi.endo = *endo;
    let feature_flags = feature_flags_from_vi(&vi);
    let (linearization, powers_of_alpha) = expr_linearization::<Fp>(Some(&feature_flags), true);
    vi.linearization = linearization;
    vi.powers_of_alpha = powers_of_alpha;

    vi
}

/// Verify a Kimchi proof against a VerifierIndex.
pub fn verify_kimchi_proof<R: rand::RngCore + rand::CryptoRng>(
    vi: &VestaVerifierIndex,
    proof: &VestaProof,
    public_input: &[Fp],
    rng: &mut R,
) -> bool {
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    verify_with_rng::<
        FULL_ROUNDS,
        Vesta,
        BaseSponge,
        ScalarSponge,
        OpeningProof<Vesta, FULL_ROUNDS>,
        _,
    >(&group_map, vi, proof, public_input, rng)
    .is_ok()
}

// --- std-only: circuit JSON parsing ---

#[cfg(feature = "std")]
mod parse;
#[cfg(feature = "std")]
pub use parse::*;
#[cfg(feature = "std")]
pub use pickles_parse::*;
