use std::fs;
use std::str::FromStr;

use ark_serialize::CanonicalSerialize;
use clap::Parser;
use mina_curves::pasta::Fp;
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("o1-verifier");

#[derive(Parser)]
#[command(name = "o1-verifier-host")]
#[command(about = "Run the o1-verifier guest program in the SP1 zkVM")]
struct Cli {
    /// Path to the proof JSON file (from the TS CLI prove command)
    #[arg(short, long)]
    proof: String,

    /// Generate a real SP1 proof instead of just executing the program.
    /// Backend is selected by the SP1_PROVER env var (cpu, cuda, network).
    #[arg(long)]
    prove: bool,
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
    // Pick up SP1's tracing logs. Default filter is "off" unless RUST_LOG is
    // set, so set `RUST_LOG=info` (or higher) to see proving progress.
    sp1_sdk::utils::setup_logger();

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

    // Prover backend is selected by SP1_PROVER env var (mock, cpu, cuda, network).
    // Defaults to cpu.
    let client = ProverClient::from_env().await;

    if cli.prove {
        let pk = client.setup(ELF).await.expect("setup failed");
        let proof = client.prove(&pk, stdin).await.expect("prove failed");

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("proof verification failed");

        let mut public_values = proof.public_values.clone();
        let valid: bool = public_values.read();
        assert!(valid, "Kimchi proof verification failed inside SP1 zkVM");

        println!("Kimchi proof verified successfully inside SP1 zkVM!");
        println!("SP1 proof generated and verified.");
    } else {
        let (mut public_values, report) =
            client.execute(ELF, stdin).await.expect("execution failed");

        let valid: bool = public_values.read();
        assert!(valid, "Kimchi proof verification failed inside SP1 zkVM");

        println!("Kimchi proof verified successfully inside SP1 zkVM!");
        println!("Execution used {} cycles", report.total_instruction_count());
    }
}
