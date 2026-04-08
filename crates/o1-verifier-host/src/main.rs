use std::fs;
use std::str::FromStr;

use ark_serialize::CanonicalSerialize;
use clap::Parser;
use mina_curves::pasta::Fp;
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin};

const ELF: Elf = include_elf!("o1-verifier");

#[derive(Parser)]
#[command(name = "o1-verifier-host")]
#[command(about = "Run the o1-verifier guest program in the SP1 zkVM")]
struct Cli {
    /// Path to the proof JSON file (from the TS CLI prove command)
    #[arg(short, long)]
    proof: String,
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

/// Serialize public inputs as a flat byte buffer of 32-byte canonical Fp elements.
fn serialize_public_inputs(fields: &[Fp]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(fields.len() * 32);
    for f in fields {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf)
            .expect("failed to serialize Fp");
        bytes.extend_from_slice(&buf);
    }
    bytes
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let proof_json_str = fs::read_to_string(&cli.proof)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", cli.proof));
    let proof_output: ProofOutput =
        serde_json::from_str(&proof_json_str).expect("failed to parse proof JSON");

    // Decode the proof from base64 msgpack
    let proof_bytes = base64::decode(&proof_output.proof.proof).expect("invalid base64 in proof");

    // Parse public inputs as Fp field elements and serialize to canonical bytes
    let public_input: Vec<Fp> = proof_output
        .proof
        .public_input_fields
        .iter()
        .map(|s| Fp::from_str(s).expect("invalid public input field element"))
        .collect();
    let public_input_bytes = serialize_public_inputs(&public_input);

    // Set up SP1 stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&proof_bytes);
    stdin.write(&public_input_bytes);

    // Prover mode is set via SP1_PROVER env var (mock, cpu, cuda, network).
    // Defaults to cpu. Use SP1_PROVER=mock for dev/testing without GPU.
    let client = ProverClient::from_env().await;
    let (mut public_values, report) = client.execute(ELF, stdin).await.expect("execution failed");

    let valid: bool = public_values.read();
    assert!(valid, "Kimchi proof verification failed inside SP1 zkVM");

    println!("Kimchi proof verified successfully inside SP1 zkVM!");
    println!("Execution used {} cycles", report.total_instruction_count());
}
