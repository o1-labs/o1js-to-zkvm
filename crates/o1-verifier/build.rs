use std::env;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Fq, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::ipa::SRS;

type VestaVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, SRS<Vesta>>;

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

fn main() {
    let circuit_path = env::var("CIRCUIT_JSON")
        .expect("CIRCUIT_JSON env var must point to the circuit description JSON");

    println!("cargo::rerun-if-changed={circuit_path}");
    println!("cargo::rerun-if-env-changed=CIRCUIT_JSON");

    let circuit_json = fs::read_to_string(&circuit_path)
        .unwrap_or_else(|e| panic!("failed to read {circuit_path}: {e}"));

    let circuit: CircuitDescription =
        serde_json::from_str(&circuit_json).expect("failed to parse circuit JSON");

    // The verification key is base64(json(VerifierIndex))
    let vk_json = String::from_utf8(
        base64::decode(&circuit.verification_key).expect("invalid base64 in verificationKey"),
    )
    .expect("verificationKey is not valid UTF-8");

    let mut vi: VestaVerifierIndex =
        serde_json::from_str(&vk_json).expect("failed to deserialize VerifierIndex from JSON");

    // Reconstruct the SRS from the circuit description points
    let g: Vec<Vesta> = circuit
        .srs
        .iter()
        .map(|p| match p {
            SrsPoint::Infinity(()) => Vesta::default(),
            SrsPoint::Point { x, y } => {
                let x = Fq::from_str(x).expect("invalid SRS x coordinate");
                let y = Fq::from_str(y).expect("invalid SRS y coordinate");
                Vesta::new_unchecked(x, y)
            }
        })
        .collect();

    let mut srs = SRS::<Vesta>::default();
    srs.g = g;
    vi.srs = Arc::new(srs);

    // Serialize to MessagePack for compact binary embedding
    let vk_bytes = rmp_serde::to_vec(&vi).expect("failed to serialize VerifierIndex to msgpack");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("verifier_index.bin");
    fs::write(&dest, &vk_bytes).expect("failed to write verifier_index.bin");
}
