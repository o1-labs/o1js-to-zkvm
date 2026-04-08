use o1_verifier_lib::{
    deserialize_public_inputs, load_verifier_index, parse_circuit_json, parse_proof_json,
    verify_kimchi_proof, VestaProof,
};

const CIRCUIT_JSON: &str = include_str!("../../../fixtures/circuit.json");
const PROOF_JSON: &str = include_str!("../../../fixtures/proof.json");

#[test]
fn test_native_verify() {
    let (vi_bytes, srs_bytes) = parse_circuit_json(CIRCUIT_JSON);
    let vi = load_verifier_index(&vi_bytes, &srs_bytes);

    let (proof_bytes, public_input_bytes) = parse_proof_json(PROOF_JSON);
    let proof: VestaProof =
        rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");
    let public_input = deserialize_public_inputs(&public_input_bytes);

    let mut rng = rand::rngs::OsRng;
    let valid = verify_kimchi_proof(&vi, &proof, &public_input, &mut rng);
    assert!(valid, "Kimchi proof verification failed");
}
