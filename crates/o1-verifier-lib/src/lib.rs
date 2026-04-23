extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ark_ff::PrimeField;
use groupmap::GroupMap;
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::curve::KimchiCurve;
use kimchi::linearization::expr_linearization;
use kimchi::proof::ProverProof;
use kimchi::verifier::verify;
use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::FULL_ROUNDS;
use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use poly_commitment::commitment::CommitmentCurve;
use poly_commitment::ipa::{OpeningProof, SRS};
use serde::de::DeserializeOwned;

pub type SpongeParams = PlonkSpongeConstantsKimchi;

// Vesta side (scalar field Fp).
pub type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
pub type VestaScalarSponge = DefaultFrSponge<mina_curves::pasta::Fp, SpongeParams, FULL_ROUNDS>;
pub type VestaVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, SRS<Vesta>>;
pub type VestaProof = ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS>;

// Pallas side (scalar field Fq).
pub type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams, FULL_ROUNDS>;
pub type PallasScalarSponge = DefaultFrSponge<mina_curves::pasta::Fq, SpongeParams, FULL_ROUNDS>;
pub type PallasVerifierIndex = VerifierIndex<FULL_ROUNDS, Pallas, SRS<Pallas>>;
pub type PallasProof = ProverProof<Pallas, OpeningProof<Pallas, FULL_ROUNDS>, FULL_ROUNDS>;

/// Deserialize a concatenation of 32-byte canonical field-element chunks. Both
/// Pasta fields fit in 32 bytes.
pub fn deserialize_public_inputs<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    const ELEMENT_SIZE: usize = 32;
    assert!(
        bytes.len().is_multiple_of(ELEMENT_SIZE),
        "public input bytes must be a multiple of 32"
    );
    bytes
        .chunks_exact(ELEMENT_SIZE)
        .map(|chunk| F::deserialize_compressed(chunk).expect("invalid field element"))
        .collect()
}

/// Reconstruct FeatureFlags from the VerifierIndex's optional commitment
/// fields. Works for any curve.
pub fn feature_flags_from_vi<G>(vi: &VerifierIndex<FULL_ROUNDS, G, SRS<G>>) -> FeatureFlags
where
    G: KimchiCurve<FULL_ROUNDS>,
{
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

/// Deserialize a VerifierIndex + SRS from msgpack bytes and reconstruct every
/// `#[serde(skip)]` field needed for verification. Generic in the curve.
pub fn load_verifier_index_generic<G>(
    vi_bytes: &[u8],
    srs_bytes: &[u8],
) -> VerifierIndex<FULL_ROUNDS, G, SRS<G>>
where
    G: KimchiCurve<FULL_ROUNDS>,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    SRS<G>: DeserializeOwned,
    VerifierIndex<FULL_ROUNDS, G, SRS<G>>: DeserializeOwned,
{
    let mut vi: VerifierIndex<FULL_ROUNDS, G, SRS<G>> =
        rmp_serde::from_slice(vi_bytes).expect("failed to deserialize VerifierIndex");
    let srs: SRS<G> = rmp_serde::from_slice(srs_bytes).expect("failed to deserialize SRS");
    vi.srs = Arc::new(srs);

    let (_, endo) = G::endos();
    vi.endo = *endo;
    let feature_flags = feature_flags_from_vi(&vi);
    let (linearization, powers_of_alpha) =
        expr_linearization::<G::ScalarField>(Some(&feature_flags), true);
    vi.linearization = linearization;
    vi.powers_of_alpha = powers_of_alpha;

    vi
}

pub fn load_vesta_verifier_index(vi_bytes: &[u8], srs_bytes: &[u8]) -> VestaVerifierIndex {
    load_verifier_index_generic::<Vesta>(vi_bytes, srs_bytes)
}

pub fn load_pallas_verifier_index(vi_bytes: &[u8], srs_bytes: &[u8]) -> PallasVerifierIndex {
    load_verifier_index_generic::<Pallas>(vi_bytes, srs_bytes)
}

pub fn verify_vesta_kimchi_proof(
    vi: &VestaVerifierIndex,
    proof: &VestaProof,
    public_input: &[mina_curves::pasta::Fp],
) -> bool {
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    verify::<
        FULL_ROUNDS,
        Vesta,
        VestaBaseSponge,
        VestaScalarSponge,
        OpeningProof<Vesta, FULL_ROUNDS>,
    >(&group_map, vi, proof, public_input)
    .is_ok()
}

pub fn verify_pallas_kimchi_proof(
    vi: &PallasVerifierIndex,
    proof: &PallasProof,
    public_input: &[mina_curves::pasta::Fq],
) -> bool {
    let group_map = <Pallas as CommitmentCurve>::Map::setup();
    verify::<
        FULL_ROUNDS,
        Pallas,
        PallasBaseSponge,
        PallasScalarSponge,
        OpeningProof<Pallas, FULL_ROUNDS>,
    >(&group_map, vi, proof, public_input)
    .is_ok()
}

// --- std-only: circuit JSON parsing ---

#[cfg(feature = "std")]
mod parse;
#[cfg(feature = "std")]
pub use parse::*;
