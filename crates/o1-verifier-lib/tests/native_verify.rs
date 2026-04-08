//! Native integration test: verifies a Kimchi proof without the SP1 VM.
//!
//! Requires CIRCUIT_JSON and PROOF_JSON env vars pointing to the outputs
//! of the TS CLI `compile` and `prove` commands respectively.

use std::fs;
use std::str::FromStr;

use ark_serialize::CanonicalSerialize;
use mina_curves::pasta::{Fq, Fp, Vesta};
use poly_commitment::ipa::SRS;

use o1_verifier_lib::{
    deserialize_public_inputs, load_verifier_index, verify_kimchi_proof, VestaProof,
};

#[derive(serde::Deserialize)]
struct CircuitDescription {
    #[serde(rename = "verificationKey")]
    verification_key: String,
    srs: Vec<SrsPoint>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum SrsPoint {
    Infinity(()),
    Point { x: String, y: String },
}

#[derive(serde::Deserialize)]
struct ProofOutput {
    proof: ProofJson,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofJson {
    proof: String,
    public_input_fields: Vec<String>,
}

/// Reproduce what the build script does: parse circuit.json → msgpack bytes.
fn build_vi_and_srs_bytes(circuit_path: &str) -> (Vec<u8>, Vec<u8>) {
    let circuit_json = fs::read_to_string(circuit_path)
        .unwrap_or_else(|e| panic!("failed to read {circuit_path}: {e}"));
    let circuit: CircuitDescription =
        serde_json::from_str(&circuit_json).expect("failed to parse circuit JSON");

    let vk_json = String::from_utf8(
        base64::decode(&circuit.verification_key).expect("invalid base64"),
    )
    .expect("invalid UTF-8");

    let vi: o1_verifier_lib::VestaVerifierIndex =
        serde_json::from_str(&vk_json).expect("failed to deserialize VerifierIndex");
    let vi_bytes = rmp_serde::to_vec(&vi).expect("failed to serialize VI");

    let parse_point = |p: &SrsPoint| -> Vesta {
        match p {
            SrsPoint::Infinity(()) => Vesta::default(),
            SrsPoint::Point { x, y } => {
                let x = Fq::from_str(x).expect("invalid x");
                let y = Fq::from_str(y).expect("invalid y");
                Vesta::new_unchecked(x, y)
            }
        }
    };

    let h = parse_point(&circuit.srs[0]);
    let g: Vec<Vesta> = circuit.srs[1..].iter().map(parse_point).collect();
    let mut srs = SRS::<Vesta>::default();
    srs.h = h;
    srs.g = g;
    let srs_bytes = rmp_serde::to_vec(&srs).expect("failed to serialize SRS");

    (vi_bytes, srs_bytes)
}

fn load_proof(proof_path: &str) -> (Vec<u8>, Vec<u8>) {
    let raw = fs::read_to_string(proof_path)
        .unwrap_or_else(|e| panic!("failed to read {proof_path}: {e}"));
    let output: ProofOutput = serde_json::from_str(&raw).expect("failed to parse proof JSON");

    let proof_bytes = base64::decode(&output.proof.proof).expect("invalid base64 in proof");

    let public_input: Vec<Fp> = output
        .proof
        .public_input_fields
        .iter()
        .map(|s| Fp::from_str(s).expect("invalid Fp"))
        .collect();

    let mut pub_bytes = Vec::with_capacity(public_input.len() * 32);
    for f in &public_input {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf).unwrap();
        pub_bytes.extend_from_slice(&buf);
    }

    (proof_bytes, pub_bytes)
}

#[test]
fn test_native_verify() {
    let circuit_path =
        std::env::var("CIRCUIT_JSON").expect("set CIRCUIT_JSON to the circuit description JSON");
    let proof_path =
        std::env::var("PROOF_JSON").expect("set PROOF_JSON to the proof JSON");

    let (vi_bytes, srs_bytes) = build_vi_and_srs_bytes(&circuit_path);
    let vi = load_verifier_index(&vi_bytes, &srs_bytes);

    let (proof_bytes, public_input_bytes) = load_proof(&proof_path);
    let proof: VestaProof =
        rmp_serde::from_slice(&proof_bytes).expect("failed to deserialize proof");
    let public_input = deserialize_public_inputs(&public_input_bytes);

    let mut rng = rand::rngs::OsRng;
    let valid = verify_kimchi_proof(&vi, &proof, &public_input, &mut rng);
    assert!(valid, "Kimchi proof verification failed");
}
