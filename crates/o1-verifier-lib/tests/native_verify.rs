use std::fs;

use o1_verifier_lib::{
    deserialize_public_inputs, load_verifier_index, parse_circuit_json, parse_proof_json,
    verify_kimchi_proof, VestaProof,
};

#[test]
fn test_native_verify() {
    let circuit_path =
        std::env::var("CIRCUIT_JSON").expect("set CIRCUIT_JSON to the circuit description JSON");
    let proof_path =
        std::env::var("PROOF_JSON").expect("set PROOF_JSON to the proof JSON");

    let circuit_json = fs::read_to_string(&circuit_path).unwrap();
    let proof_json = fs::read_to_string(&proof_path).unwrap();

    let (vi_bytes, srs_bytes) = parse_circuit_json(&circuit_json);
    let vi = load_verifier_index(&vi_bytes, &srs_bytes);

    let (proof_bytes, public_input_bytes) = parse_proof_json(&proof_json);
    let proof: VestaProof =
        rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");
    let public_input = deserialize_public_inputs(&public_input_bytes);

    let mut rng = rand::rngs::OsRng;
    let valid = verify_kimchi_proof(&vi, &proof, &public_input, &mut rng);
    assert!(valid, "Kimchi proof verification failed");
}
