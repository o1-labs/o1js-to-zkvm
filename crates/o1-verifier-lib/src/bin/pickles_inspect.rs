//! CLI inspector for Mina-exported `Simple_chain` Pickles fixtures.
//!
//! The output is meant to answer three questions quickly:
//! - can Rust parse the bundle and side-loaded proof at all?
//! - what structured metadata is already available from the proof bytes?
//! - how much of the wrap public-input vector can Rust derive today?

use std::env;
use std::fs;
use std::process::ExitCode;

use o1_verifier_lib::{
    lower_simple_chain_metadata, lower_simple_chain_public_input_plan, lower_simple_chain_request,
    parse_simple_chain_bundle,
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
    public_input_plan_status: &'static str,
    public_input_plan: Option<PublicInputPlanOutput>,
    public_input_plan_error: Option<String>,
    exported_wrap_public_input_status: &'static str,
    exported_wrap_public_input: Option<Vec<String>>,
    exported_wrap_public_input_error: Option<String>,
    public_input_comparison_status: &'static str,
    public_input_comparison: Option<PublicInputComparisonOutput>,
    public_input_comparison_error: Option<String>,
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
    commitments: CommitmentsOutput,
    evaluations: Vec<NamedPointSectionOutput>,
    ft_eval1: String,
    bulletproof: BulletproofOutput,
}

#[derive(Serialize)]
struct CommitmentsOutput {
    w_comm: Vec<PointOutput>,
    z_comm: Vec<PointOutput>,
    t_comm: Vec<PointOutput>,
    lookup: Option<Vec<PointOutput>>,
}

#[derive(Serialize)]
struct NamedPointSectionOutput {
    name: String,
    raw_payload_items: Vec<String>,
    points: Vec<PointOutput>,
}

#[derive(Serialize)]
struct PointPairOutput {
    left: PointOutput,
    right: PointOutput,
}

#[derive(Serialize)]
struct BulletproofOutput {
    lr_pairs: Vec<PointPairOutput>,
    z_1: String,
    z_2: String,
    delta: PointOutput,
    challenge_polynomial_commitment: PointOutput,
}

#[derive(Serialize)]
struct PublicInputPlanOutput {
    total_fields: usize,
    exact_public_input_available: bool,
    elided_constant_segments: Vec<String>,
    fields: Vec<PublicInputFieldOutput>,
}

#[derive(Serialize)]
struct PublicInputFieldOutput {
    index: usize,
    name: String,
    value_hex: Option<String>,
    source: String,
}

#[derive(Serialize)]
struct PublicInputComparisonOutput {
    planned_fields: usize,
    exported_fields: usize,
    matching_known_fields: usize,
    mismatched_known_fields: Vec<PublicInputMismatchOutput>,
    unknown_plan_slots: usize,
    extra_exported_slots: usize,
}

#[derive(Serialize)]
struct PublicInputMismatchOutput {
    index: usize,
    name: String,
    planned_value_hex: String,
    exported_value_hex: String,
}

fn usage(program: &str) -> String {
    format!("usage: {program} <simple-chain-bundle.json> [output.json]")
}

/// Render a machine-readable view of the current Pickles support boundary.
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
                        commitments: CommitmentsOutput {
                            w_comm: metadata
                                .inner_proof
                                .commitments
                                .w_comm
                                .into_iter()
                                .map(|point| PointOutput {
                                    x: point.x,
                                    y: point.y,
                                })
                                .collect(),
                            z_comm: metadata
                                .inner_proof
                                .commitments
                                .z_comm
                                .into_iter()
                                .map(|point| PointOutput {
                                    x: point.x,
                                    y: point.y,
                                })
                                .collect(),
                            t_comm: metadata
                                .inner_proof
                                .commitments
                                .t_comm
                                .into_iter()
                                .map(|point| PointOutput {
                                    x: point.x,
                                    y: point.y,
                                })
                                .collect(),
                            lookup: metadata.inner_proof.commitments.lookup.map(|points| {
                                points
                                    .into_iter()
                                    .map(|point| PointOutput {
                                        x: point.x,
                                        y: point.y,
                                    })
                                    .collect()
                            }),
                        },
                        evaluations: metadata
                            .inner_proof
                            .evaluations
                            .into_iter()
                            .map(|section| NamedPointSectionOutput {
                                name: section.name,
                                raw_payload_items: section.raw_payload_items,
                                points: section
                                    .points
                                    .into_iter()
                                    .map(|point| PointOutput {
                                        x: point.x,
                                        y: point.y,
                                    })
                                    .collect(),
                            })
                            .collect(),
                        ft_eval1: metadata.inner_proof.ft_eval1,
                        bulletproof: BulletproofOutput {
                            lr_pairs: metadata
                                .inner_proof
                                .bulletproof
                                .lr_pairs
                                .into_iter()
                                .map(|pair| PointPairOutput {
                                    left: PointOutput {
                                        x: pair.left.x,
                                        y: pair.left.y,
                                    },
                                    right: PointOutput {
                                        x: pair.right.x,
                                        y: pair.right.y,
                                    },
                                })
                                .collect(),
                            z_1: metadata.inner_proof.bulletproof.z_1,
                            z_2: metadata.inner_proof.bulletproof.z_2,
                            delta: PointOutput {
                                x: metadata.inner_proof.bulletproof.delta.x,
                                y: metadata.inner_proof.bulletproof.delta.y,
                            },
                            challenge_polynomial_commitment: PointOutput {
                                x: metadata
                                    .inner_proof
                                    .bulletproof
                                    .challenge_polynomial_commitment
                                    .x,
                                y: metadata
                                    .inner_proof
                                    .bulletproof
                                    .challenge_polynomial_commitment
                                    .y,
                            },
                        },
                    },
                })
                .map_err(|err| err.to_string());

            let verification = lower_simple_chain_request(&request)
                .map(|_| true)
                .map_err(|err| err.to_string());
            let public_input_plan = lower_simple_chain_public_input_plan(&request)
                .map(|plan| PublicInputPlanOutput {
                    total_fields: plan.total_fields,
                    exact_public_input_available: plan.exact_public_input_available,
                    elided_constant_segments: plan.elided_constant_segments,
                    fields: plan
                        .fields
                        .into_iter()
                        .map(|field| PublicInputFieldOutput {
                            index: field.index,
                            name: field.name,
                            value_hex: field.value_hex,
                            source: field.source,
                        })
                        .collect(),
                })
                .map_err(|err| err.to_string());
            let exported_wrap_public_input = request
                .exported_wrap_public_input
                .as_ref()
                .map(|exported| exported.hex_fields.clone())
                .ok_or_else(|| "bundle does not include wrap_public_input_fields".to_string());
            let public_input_comparison =
                match (&public_input_plan, &request.exported_wrap_public_input) {
                    (Ok(plan), Some(exported)) => {
                        Ok(compare_public_input_plan(plan, &exported.hex_fields))
                    }
                    (Err(err), _) => Err(err.clone()),
                    (_, None) => Err("bundle does not include wrap_public_input_fields".into()),
                };

            let (metadata_status, metadata, metadata_error) = match metadata {
                Ok(metadata) => ("decoded", Some(metadata), None),
                Err(err) => ("error", None, Some(err)),
            };
            let (public_input_plan_status, public_input_plan, public_input_plan_error) =
                match public_input_plan {
                    Ok(plan) => ("decoded", Some(plan), None),
                    Err(err) => ("error", None, Some(err)),
                };
            let (
                exported_wrap_public_input_status,
                exported_wrap_public_input,
                exported_wrap_public_input_error,
            ) = match exported_wrap_public_input {
                Ok(fields) => ("decoded", Some(fields), None),
                Err(err) => ("missing", None, Some(err)),
            };
            let (
                public_input_comparison_status,
                public_input_comparison,
                public_input_comparison_error,
            ) = match public_input_comparison {
                Ok(comparison) => ("decoded", Some(comparison), None),
                Err(err) => ("not_available", None, Some(err)),
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
                public_input_plan_status,
                public_input_plan,
                public_input_plan_error,
                exported_wrap_public_input_status,
                exported_wrap_public_input,
                exported_wrap_public_input_error,
                public_input_comparison_status,
                public_input_comparison,
                public_input_comparison_error,
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

fn compare_public_input_plan(
    plan: &PublicInputPlanOutput,
    exported_hex_fields: &[String],
) -> PublicInputComparisonOutput {
    let mut matching_known_fields = 0usize;
    let mut mismatched_known_fields = Vec::new();
    let compare_len = plan.fields.len().min(exported_hex_fields.len());

    for index in 0..compare_len {
        let planned = &plan.fields[index];
        let Some(planned_value_hex) = &planned.value_hex else {
            continue;
        };
        let exported_value_hex = &exported_hex_fields[index];
        if normalize_hex(planned_value_hex) == normalize_hex(exported_value_hex) {
            matching_known_fields += 1;
        } else {
            mismatched_known_fields.push(PublicInputMismatchOutput {
                index,
                name: planned.name.clone(),
                planned_value_hex: planned_value_hex.clone(),
                exported_value_hex: exported_value_hex.clone(),
            });
        }
    }

    let unknown_plan_slots = plan
        .fields
        .iter()
        .filter(|field| field.value_hex.is_none())
        .count();

    PublicInputComparisonOutput {
        planned_fields: plan.fields.len(),
        exported_fields: exported_hex_fields.len(),
        matching_known_fields,
        mismatched_known_fields,
        unknown_plan_slots,
        extra_exported_slots: exported_hex_fields.len().saturating_sub(plan.fields.len()),
    }
}

fn normalize_hex(hex: &str) -> String {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.to_ascii_uppercase()
    }
}
