use std::env;
use std::fs;
use std::path::Path;

use o1_verifier_lib::parse_circuit_json;

fn main() {
    let circuit_path = env::var("CIRCUIT_JSON")
        .expect("CIRCUIT_JSON env var must point to the circuit description JSON");

    println!("cargo::rerun-if-changed={circuit_path}");
    println!("cargo::rerun-if-env-changed=CIRCUIT_JSON");

    let circuit_json = fs::read_to_string(&circuit_path)
        .unwrap_or_else(|e| panic!("failed to read {circuit_path}: {e}"));

    let (vi_bytes, srs_bytes) = parse_circuit_json(&circuit_json);

    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("verifier_index.bin"), &vi_bytes)
        .expect("failed to write verifier_index.bin");
    fs::write(Path::new(&out_dir).join("srs.bin"), &srs_bytes)
        .expect("failed to write srs.bin");
}
