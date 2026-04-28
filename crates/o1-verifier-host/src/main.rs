use std::fs;

use clap::{Parser, Subcommand};
use o1_pickles_verifier::messages::compute_dummy_wrap_sg;
use o1_pickles_verifier::parse::{canonical_proof_repr_msgpack, parse_proof_repr_msgpack};
use o1_pickles_verifier::verify::{
    host_populate_prev_challenges, host_precompute, CommitOutput, GuestInput,
};
use o1_pickles_verifier::Pallas;
use o1_verifier_lib::PallasProof;
use poly_commitment::ipa::SRS;
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin};

const ELF: Elf = include_elf!("o1-verifier");

#[derive(Parser)]
#[command(name = "o1zkvm")]
#[command(about = "Drive the SP1 wrap-proof verifier or compute its statement digest")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the SP1 verifier against one (proof_repr, wrap_proof) pair.
    Verify {
        /// Path to the OCaml-emitted proof_repr JSON.
        #[arg(long)]
        proof_repr: String,

        /// Path to the matching wrap kimchi proof msgpack.
        #[arg(long)]
        wrap_proof: String,

        /// Path to the wrap SRS msgpack.
        #[arg(long, default_value = "fixtures/simple_chain_wrap_srs.bin")]
        wrap_srs: String,
    },

    /// Print the SHA-256 statement digest the guest would commit.
    Hash {
        /// Path to a proof_repr JSON.
        #[arg(long)]
        proof_repr: String,
    },
}

fn read_canonical_msgpack(json_path: &str) -> Vec<u8> {
    let proof_repr_json = fs::read_to_string(json_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", json_path));
    canonical_proof_repr_msgpack(&proof_repr_json)
        .expect("failed to canonicalize proof_repr JSON as msgpack")
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Hash { proof_repr } => {
            let bytes = read_canonical_msgpack(&proof_repr);
            let digest = Sha256::digest(&bytes);
            for b in digest.as_slice() {
                print!("{:02x}", b);
            }
            println!();
        }
        Cmd::Verify {
            proof_repr,
            wrap_proof,
            wrap_srs,
        } => run_verify(&proof_repr, &wrap_proof, &wrap_srs).await,
    }
}

async fn run_verify(proof_repr_path: &str, wrap_proof_path: &str, wrap_srs_path: &str) {
    let proof_repr_msgpack = read_canonical_msgpack(proof_repr_path);
    let parsed = parse_proof_repr_msgpack(&proof_repr_msgpack).expect("parse proof_repr");
    let stmt = parsed.statement;
    let prev_evals = parsed.prev_evals;

    let srs_bytes =
        fs::read(wrap_srs_path).unwrap_or_else(|e| panic!("failed to read {}: {e}", wrap_srs_path));
    let srs: SRS<Pallas> = rmp_serde::from_slice(&srs_bytes).expect("parse SRS");
    let dummy_sg = compute_dummy_wrap_sg(&srs);

    let host_precomputed = host_precompute(&stmt, &prev_evals);

    let wrap_proof_bytes = fs::read(wrap_proof_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", wrap_proof_path));
    let mut wrap_proof: PallasProof =
        rmp_serde::from_slice(&wrap_proof_bytes).expect("parse wrap proof");
    host_populate_prev_challenges(&mut wrap_proof, &stmt, dummy_sg);

    let statement_digest = Sha256::digest(&proof_repr_msgpack);
    let mut digest_hex = String::with_capacity(64);
    for b in statement_digest.as_slice() {
        digest_hex.push_str(&format!("{:02x}", b));
    }

    let input = GuestInput {
        proof_repr_msgpack,
        wrap_proof,
        host_precomputed,
    };
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    let client = ProverClient::from_env().await;
    let (mut public_values, report) = client
        .execute(ELF, stdin)
        .await
        .expect("SP1 execution failed");

    let output: CommitOutput = public_values.read();
    assert!(
        output.valid,
        "kimchi rejected the wrap proof inside the SP1 zkVM"
    );

    let mut zkvm_digest_hex = String::with_capacity(64);
    for b in output.statement_digest.iter() {
        zkvm_digest_hex.push_str(&format!("{:02x}", b));
    }
    assert_eq!(
        digest_hex, zkvm_digest_hex,
        "host SHA-256 of canonical msgpack disagrees with guest's commitment"
    );

    println!("wrap proof verified inside SP1 zkVM");
    println!("  app_state:        {:?}", output.app_state);
    println!("  statement_digest: 0x{}", zkvm_digest_hex);
    println!(
        "  execution used {} cycles",
        report.total_instruction_count()
    );
}
