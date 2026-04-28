//! Host driver for the Simple_chain wrap-proof guest.
//!
//! Takes paths to one OCaml-emitted `proof_repr_b{N}.json` and the
//! matching `wrap_proof_b{N}.bin`, JSON-decodes the proof_repr into
//! the wire types, msgpack-re-encodes for the guest, and runs the
//! SP1 zkVM. Reports whether kimchi accepts and prints the
//! attested-to `app_state`.

use std::fs;

use clap::Parser;
use o1_pickles_verifier::verify::CommitOutput;
use o1_pickles_verifier::wire::ProofReprWire;
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin};

const ELF: Elf = include_elf!("o1-verifier");

#[derive(Parser)]
#[command(name = "o1zkvm")]
#[command(about = "Verify a Simple_chain wrap proof inside the SP1 zkVM")]
struct Cli {
    /// Path to the OCaml-emitted proof_repr JSON (e.g.
    /// `fixtures/simple_chain_proof_repr_b0.json`).
    #[arg(long)]
    proof_repr: String,

    /// Path to the matching wrap kimchi proof msgpack (e.g.
    /// `fixtures/simple_chain_wrap_proof_b0.bin`).
    #[arg(long)]
    wrap_proof: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let proof_repr_json = fs::read_to_string(&cli.proof_repr)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", cli.proof_repr));
    let proof_repr_wire: ProofReprWire = serde_json::from_str(&proof_repr_json)
        .expect("failed to parse proof_repr JSON into ProofReprWire");
    let proof_repr_msgpack = rmp_serde::to_vec(&proof_repr_wire)
        .expect("failed to msgpack-encode ProofReprWire for the guest");

    let wrap_proof_bytes = fs::read(&cli.wrap_proof)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", cli.wrap_proof));

    let mut stdin = SP1Stdin::new();
    stdin.write(&proof_repr_msgpack);
    stdin.write(&wrap_proof_bytes);

    // Prover mode is set via SP1_PROVER env var (mock, cpu, network).
    // Defaults to cpu. Use SP1_PROVER=mock for fast dev.
    let client = ProverClient::from_env().await;
    let (mut public_values, report) = client.execute(ELF, stdin).await.expect("execution failed");

    let output: CommitOutput = public_values.read();
    assert!(
        output.valid,
        "kimchi rejected the wrap proof inside the SP1 zkVM"
    );

    println!("Simple_chain wrap proof verified inside SP1 zkVM");
    println!("  app_state: {:?}", output.app_state);
    println!(
        "  execution used {} cycles",
        report.total_instruction_count()
    );
}
