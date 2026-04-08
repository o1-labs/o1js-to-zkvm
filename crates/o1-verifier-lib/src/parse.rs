use std::str::FromStr;

use ark_serialize::CanonicalSerialize;
use mina_curves::pasta::{Fp, Fq, Vesta};
use poly_commitment::ipa::SRS;

#[derive(serde::Deserialize)]
pub struct CircuitDescription {
    #[serde(rename = "verificationKey")]
    pub verification_key: String,
    pub srs: Vec<SrsPoint>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub enum SrsPoint {
    Infinity(()),
    Point { x: String, y: String },
}

#[derive(serde::Deserialize)]
pub struct ProofOutput {
    pub proof: ProofJson,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofJson {
    pub proof: String,
    pub public_input_fields: Vec<String>,
}

fn parse_srs_point(p: &SrsPoint) -> Vesta {
    match p {
        SrsPoint::Infinity(()) => Vesta::default(),
        SrsPoint::Point { x, y } => {
            let x = Fq::from_str(x).expect("invalid SRS x coordinate");
            let y = Fq::from_str(y).expect("invalid SRS y coordinate");
            Vesta::new_unchecked(x, y)
        }
    }
}

/// Parse a circuit description JSON and produce msgpack bytes for the
/// VerifierIndex and SRS, suitable for `load_verifier_index()`.
pub fn parse_circuit_json(circuit_json: &str) -> (Vec<u8>, Vec<u8>) {
    let circuit: CircuitDescription =
        serde_json::from_str(circuit_json).expect("failed to parse circuit JSON");

    let vk_json = String::from_utf8(
        base64::decode(&circuit.verification_key).expect("invalid base64 in verificationKey"),
    )
    .expect("verificationKey is not valid UTF-8");

    let vi: crate::VestaVerifierIndex =
        serde_json::from_str(&vk_json).expect("failed to deserialize VerifierIndex from JSON");
    let vi_bytes = rmp_serde::to_vec(&vi).expect("failed to serialize VerifierIndex to msgpack");

    assert!(
        circuit.srs.len() >= 2,
        "SRS must have at least h + one g element"
    );
    let h = parse_srs_point(&circuit.srs[0]);
    let g: Vec<Vesta> = circuit.srs[1..].iter().map(parse_srs_point).collect();

    let mut srs = SRS::<Vesta>::default();
    srs.h = h;
    srs.g = g;
    let srs_bytes = rmp_serde::to_vec(&srs).expect("failed to serialize SRS to msgpack");

    (vi_bytes, srs_bytes)
}

/// Parse a proof JSON and return the raw proof bytes (msgpack) and
/// serialized public inputs (32 bytes per Fp element, canonical form).
pub fn parse_proof_json(proof_json: &str) -> (Vec<u8>, Vec<u8>) {
    let output: ProofOutput = serde_json::from_str(proof_json).expect("failed to parse proof JSON");

    let proof_bytes = base64::decode(&output.proof.proof).expect("invalid base64 in proof");

    let public_input: Vec<Fp> = output
        .proof
        .public_input_fields
        .iter()
        .map(|s| Fp::from_str(s).expect("invalid public input field element"))
        .collect();

    let mut pub_bytes = Vec::with_capacity(public_input.len() * 32);
    for f in &public_input {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf).unwrap();
        pub_bytes.extend_from_slice(&buf);
    }

    (proof_bytes, pub_bytes)
}
