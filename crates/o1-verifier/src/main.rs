#![no_main]
sp1_zkvm::entrypoint!(main);

use o1_verifier_lib::{deserialize_public_inputs, load_verifier_index, verify_kimchi_proof};

static VI_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/verifier_index.bin"));
static SRS_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/srs.bin"));

pub fn main() {
    let vi = load_verifier_index(VI_BYTES, SRS_BYTES);

    let proof_bytes: Vec<u8> = sp1_zkvm::io::read();
    let public_input_bytes: Vec<u8> = sp1_zkvm::io::read();

    let proof = rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");
    let public_input = deserialize_public_inputs(&public_input_bytes);

    let mut rng = rand::rngs::OsRng;
    let valid = verify_kimchi_proof(&vi, &proof, &public_input, &mut rng);

    sp1_zkvm::io::commit(&valid);
}
