#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;
use groupmap::GroupMap;
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

static VK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/verifier_index.bin"));

/// Deserialize public inputs from a flat byte buffer.
/// Each Fp element is 32 bytes (little-endian canonical form).
fn deserialize_public_inputs(bytes: &[u8]) -> Vec<Fp> {
    assert!(bytes.len() % 32 == 0, "public input bytes must be a multiple of 32");
    bytes
        .chunks_exact(32)
        .map(|chunk| Fp::deserialize_compressed(chunk).expect("invalid Fp element"))
        .collect()
}

pub fn main() {
    let vi: VestaVerifierIndex =
        rmp_serde::from_slice(VK_BYTES).expect("failed to deserialize VerifierIndex");

    // Read proof as msgpack bytes, public input as raw canonical bytes
    let proof_bytes: Vec<u8> = sp1_zkvm::io::read();
    let public_input_bytes: Vec<u8> = sp1_zkvm::io::read();

    let proof: VestaProof =
        rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");

    let public_input = deserialize_public_inputs(&public_input_bytes);

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let mut rng = rand::rngs::OsRng;
    verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>, _>(
        &group_map,
        &vi,
        &proof,
        &public_input,
        &mut rng,
    )
    .expect("kimchi proof verification failed");

    sp1_zkvm::io::commit(&true);
}
