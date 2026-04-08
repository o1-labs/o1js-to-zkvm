#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::sync::Arc;

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

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;
type VestaVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, SRS<Vesta>>;
type VestaProof = ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS>;

// VerifierIndex.srs is #[serde(skip)], so they are embedded separately.
static VI_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/verifier_index.bin"));
static SRS_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/srs.bin"));

fn deserialize_public_inputs(bytes: &[u8]) -> alloc::vec::Vec<Fp> {
    assert!(
        bytes.len() % 32 == 0,
        "public input bytes must be a multiple of 32"
    );
    bytes
        .chunks_exact(32)
        .map(|chunk| Fp::deserialize_compressed(chunk).expect("invalid Fp element"))
        .collect()
}

/// Reconstruct FeatureFlags from the VerifierIndex optional commitment fields.
fn feature_flags_from_vi(vi: &VestaVerifierIndex) -> FeatureFlags {
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

pub fn main() {
    // Deserialize the baked-in verifier index and SRS
    let mut vi: VestaVerifierIndex =
        rmp_serde::from_slice(VI_BYTES).expect("failed to deserialize VerifierIndex");
    let srs: SRS<Vesta> =
        rmp_serde::from_slice(SRS_BYTES).expect("failed to deserialize SRS");
    vi.srs = Arc::new(srs);

    // Reconstruct #[serde(skip)] fields
    let (_, endo) = Vesta::endos();
    vi.endo = *endo;
    let feature_flags = feature_flags_from_vi(&vi);
    let (linearization, powers_of_alpha) =
        expr_linearization::<Fp>(Some(&feature_flags), true);
    vi.linearization = linearization;
    vi.powers_of_alpha = powers_of_alpha;

    // Read proof and public inputs from SP1 stdin
    let proof_bytes: Vec<u8> = sp1_zkvm::io::read();
    let public_input_bytes: Vec<u8> = sp1_zkvm::io::read();

    let proof: VestaProof =
        rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");
    let public_input = deserialize_public_inputs(&public_input_bytes);

    // Verify the Kimchi proof
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let mut rng = rand::rngs::OsRng;
    let valid = verify_with_rng::<
        FULL_ROUNDS,
        Vesta,
        BaseSponge,
        ScalarSponge,
        OpeningProof<Vesta, FULL_ROUNDS>,
        _,
    >(&group_map, &vi, &proof, &public_input, &mut rng)
    .is_ok();

    sp1_zkvm::io::commit(&valid);
}
