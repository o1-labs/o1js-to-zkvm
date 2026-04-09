use std::env;
use std::fs;
use std::process::ExitCode;

use o1_verifier_lib::{
    lower_simple_chain_metadata, lower_simple_chain_request, parse_simple_chain_bundle,
};
use serde::Serialize;

#[derive(Serialize)]
struct InspectorOutput {
    scope: &'static str,
    bundle_path: String,
    verification_key_bytes: usize,
    fixtures: Vec<FixtureOutput>,
}

#[derive(Serialize)]
struct FixtureOutput {
    name: String,
    statement_fields: Vec<String>,
    proof_bytes: usize,
    metadata_status: &'static str,
    metadata: Option<FixtureMetadataOutput>,
    metadata_error: Option<String>,
    verification_status: &'static str,
    verification: Option<bool>,
    verification_error: Option<String>,
}

#[derive(Serialize)]
struct FixtureMetadataOutput {
    proofs_verified: u8,
    domain_log2: u8,
    sponge_digest_before_evaluations: Vec<String>,
    wrap_challenge_polynomial_commitment: PointOutput,
    wrap_old_bulletproof_challenges_count: usize,
    next_step_challenge_polynomial_commitments: Vec<PointOutput>,
    next_step_old_bulletproof_challenges_count: usize,
    prev_evals_public_input: Vec<String>,
    ft_eval1: String,
}

#[derive(Serialize)]
struct PointOutput {
    x: String,
    y: String,
}

fn usage(program: &str) -> String {
    format!("usage: {program} <simple-chain-bundle.json> [output.json]")
}

fn main() -> ExitCode {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "pickles_inspect".into());
    let Some(bundle_path) = args.next() else {
        eprintln!("{}", usage(&program));
        return ExitCode::from(2);
    };
    let output_path = args.next();

    let bundle_json = match fs::read_to_string(&bundle_path) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("failed to read bundle {bundle_path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let bundle = match parse_simple_chain_bundle(&bundle_json) {
        Ok(bundle) => bundle,
        Err(err) => {
            eprintln!("failed to parse bundle {bundle_path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let fixtures = bundle
        .fixtures
        .iter()
        .map(|fixture| {
            let request = bundle
                .request_for_fixture(&fixture.name)
                .expect("fixture present in bundle");
            let metadata = lower_simple_chain_metadata(&request)
                .map(|metadata| FixtureMetadataOutput {
                    proofs_verified: metadata.proofs_verified,
                    domain_log2: metadata.domain_log2,
                    sponge_digest_before_evaluations: metadata.sponge_digest_before_evaluations,
                    wrap_challenge_polynomial_commitment: PointOutput {
                        x: metadata.wrap_challenge_polynomial_commitment.x,
                        y: metadata.wrap_challenge_polynomial_commitment.y,
                    },
                    wrap_old_bulletproof_challenges_count: metadata
                        .wrap_old_bulletproof_challenges_count,
                    next_step_challenge_polynomial_commitments: metadata
                        .next_step_challenge_polynomial_commitments
                        .into_iter()
                        .map(|point| PointOutput {
                            x: point.x,
                            y: point.y,
                        })
                        .collect(),
                    next_step_old_bulletproof_challenges_count: metadata
                        .next_step_old_bulletproof_challenges_count,
                    prev_evals_public_input: metadata.prev_evals_public_input,
                    ft_eval1: metadata.ft_eval1,
                })
                .map_err(|err| err.to_string());

            let verification = lower_simple_chain_request(&request)
                .map(|_| true)
                .map_err(|err| err.to_string());

            let (metadata_status, metadata, metadata_error) = match metadata {
                Ok(metadata) => ("decoded", Some(metadata), None),
                Err(err) => ("error", None, Some(err)),
            };

            let (verification_status, verification, verification_error) = match verification {
                Ok(valid) => ("verified", Some(valid), None),
                Err(err) => ("not_available", None, Some(err)),
            };

            FixtureOutput {
                name: fixture.name.clone(),
                statement_fields: fixture
                    .statement
                    .to_fields()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                proof_bytes: fixture.proof.0.len(),
                metadata_status,
                metadata,
                metadata_error,
                verification_status,
                verification,
                verification_error,
            }
        })
        .collect();

    let output = InspectorOutput {
        scope: "proof parsing and partial lowering only; Pickles verification is not implemented",
        bundle_path: bundle_path.clone(),
        verification_key_bytes: bundle.verification_key.0.len(),
        fixtures,
    };

    let rendered = match serde_json::to_string_pretty(&output) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("failed to render JSON: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(output_path) = output_path {
        if let Err(err) = fs::write(&output_path, format!("{rendered}\n")) {
            eprintln!("failed to write output {output_path}: {err}");
            return ExitCode::FAILURE;
        }
    } else {
        println!("{rendered}");
    }

    ExitCode::SUCCESS
}
