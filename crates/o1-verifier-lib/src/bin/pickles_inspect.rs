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
    plonk: PlonkDeferredValuesOutput,
    deferred_bulletproof_challenges: Vec<BulletproofChallengeOutput>,
    sponge_digest_before_evaluations: Vec<String>,
    wrap_challenge_polynomial_commitment: PointOutput,
    wrap_old_bulletproof_challenges: Vec<Vec<BulletproofChallengeOutput>>,
    next_step_challenge_polynomial_commitments: Vec<PointOutput>,
    next_step_old_bulletproof_challenges: Vec<Vec<BulletproofChallengeOutput>>,
    prev_evals_public_input: Vec<String>,
    prev_evals_sections: Vec<NamedSectionCountOutput>,
    ft_eval1: String,
    inner_proof: InnerProofOutput,
}

#[derive(Serialize)]
struct PointOutput {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct BulletproofChallengeOutput {
    prechallenge_inner: Vec<String>,
}

#[derive(Serialize)]
struct PlonkFeatureFlagsOutput {
    range_check0: bool,
    range_check1: bool,
    foreign_field_add: bool,
    foreign_field_mul: bool,
    xor: bool,
    rot: bool,
    lookup: bool,
    runtime_tables: bool,
}

#[derive(Serialize)]
struct PlonkDeferredValuesOutput {
    alpha_inner: Vec<String>,
    beta: Vec<String>,
    gamma: Vec<String>,
    zeta_inner: Vec<String>,
    joint_combiner_inner: Option<Vec<String>>,
    feature_flags: PlonkFeatureFlagsOutput,
}

#[derive(Serialize)]
struct NamedSectionCountOutput {
    name: String,
    count: usize,
}

#[derive(Serialize)]
struct InnerProofOutput {
    w_comm_count: usize,
    z_comm_count: usize,
    t_comm_count: usize,
    lookup_present: bool,
    evaluation_sections: Vec<NamedSectionCountOutput>,
    ft_eval1: String,
    lr_count: usize,
    z_1: String,
    z_2: String,
    delta: PointOutput,
    challenge_polynomial_commitment: PointOutput,
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
                    plonk: PlonkDeferredValuesOutput {
                        alpha_inner: metadata.plonk.alpha_inner,
                        beta: metadata.plonk.beta,
                        gamma: metadata.plonk.gamma,
                        zeta_inner: metadata.plonk.zeta_inner,
                        joint_combiner_inner: metadata.plonk.joint_combiner_inner,
                        feature_flags: PlonkFeatureFlagsOutput {
                            range_check0: metadata.plonk.feature_flags.range_check0,
                            range_check1: metadata.plonk.feature_flags.range_check1,
                            foreign_field_add: metadata.plonk.feature_flags.foreign_field_add,
                            foreign_field_mul: metadata.plonk.feature_flags.foreign_field_mul,
                            xor: metadata.plonk.feature_flags.xor,
                            rot: metadata.plonk.feature_flags.rot,
                            lookup: metadata.plonk.feature_flags.lookup,
                            runtime_tables: metadata.plonk.feature_flags.runtime_tables,
                        },
                    },
                    deferred_bulletproof_challenges: metadata
                        .deferred_bulletproof_challenges
                        .into_iter()
                        .map(|challenge| BulletproofChallengeOutput {
                            prechallenge_inner: challenge.prechallenge_inner,
                        })
                        .collect(),
                    sponge_digest_before_evaluations: metadata.sponge_digest_before_evaluations,
                    wrap_challenge_polynomial_commitment: PointOutput {
                        x: metadata.wrap_challenge_polynomial_commitment.x,
                        y: metadata.wrap_challenge_polynomial_commitment.y,
                    },
                    wrap_old_bulletproof_challenges: metadata
                        .wrap_old_bulletproof_challenges
                        .into_iter()
                        .map(|group| {
                            group
                                .into_iter()
                                .map(|challenge| BulletproofChallengeOutput {
                                    prechallenge_inner: challenge.prechallenge_inner,
                                })
                                .collect()
                        })
                        .collect(),
                    next_step_challenge_polynomial_commitments: metadata
                        .next_step_challenge_polynomial_commitments
                        .into_iter()
                        .map(|point| PointOutput {
                            x: point.x,
                            y: point.y,
                        })
                        .collect(),
                    next_step_old_bulletproof_challenges: metadata
                        .next_step_old_bulletproof_challenges
                        .into_iter()
                        .map(|group| {
                            group
                                .into_iter()
                                .map(|challenge| BulletproofChallengeOutput {
                                    prechallenge_inner: challenge.prechallenge_inner,
                                })
                                .collect()
                        })
                        .collect(),
                    prev_evals_public_input: metadata.prev_evals_public_input,
                    prev_evals_sections: metadata
                        .prev_evals_sections
                        .into_iter()
                        .map(|section| NamedSectionCountOutput {
                            name: section.name,
                            count: section.count,
                        })
                        .collect(),
                    ft_eval1: metadata.ft_eval1,
                    inner_proof: InnerProofOutput {
                        w_comm_count: metadata.inner_proof.w_comm_count,
                        z_comm_count: metadata.inner_proof.z_comm_count,
                        t_comm_count: metadata.inner_proof.t_comm_count,
                        lookup_present: metadata.inner_proof.lookup_present,
                        evaluation_sections: metadata
                            .inner_proof
                            .evaluation_sections
                            .into_iter()
                            .map(|section| NamedSectionCountOutput {
                                name: section.name,
                                count: section.count,
                            })
                            .collect(),
                        ft_eval1: metadata.inner_proof.ft_eval1,
                        lr_count: metadata.inner_proof.lr_count,
                        z_1: metadata.inner_proof.z_1,
                        z_2: metadata.inner_proof.z_2,
                        delta: PointOutput {
                            x: metadata.inner_proof.delta.x,
                            y: metadata.inner_proof.delta.y,
                        },
                        challenge_polynomial_commitment: PointOutput {
                            x: metadata.inner_proof.challenge_polynomial_commitment.x,
                            y: metadata.inner_proof.challenge_polynomial_commitment.y,
                        },
                    },
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
