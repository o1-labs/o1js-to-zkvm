#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::sync::Arc;

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

// VerifierIndex.srs is #[serde(skip)], so they are embedded separately.
static VI_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/verifier_index.bin"));
static SRS_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/srs.bin"));

fn deserialize_public_inputs(bytes: &[u8]) -> Vec<Fp> {
    assert!(
        bytes.len() % 32 == 0,
        "public input bytes must be a multiple of 32"
    );
    bytes
        .chunks_exact(32)
        .map(|chunk| Fp::deserialize_compressed(chunk).expect("invalid Fp element"))
        .collect()
}

pub fn main() {
    let mut vi: VestaVerifierIndex =
        rmp_serde::from_slice(VI_BYTES).expect("failed to deserialize VerifierIndex");
    let srs: SRS<Vesta> =
        rmp_serde::from_slice(SRS_BYTES).expect("failed to deserialize SRS");
    vi.srs = Arc::new(srs);

    let proof_bytes: Vec<u8> = sp1_zkvm::io::read();
    let public_input_bytes: Vec<u8> = sp1_zkvm::io::read();

    let proof: VestaProof =
        rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");
    let public_input = deserialize_public_inputs(&public_input_bytes);

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
