//! Parsing helpers for the Mina `Simple_chain` exporter bundle.
//!
//! This module is intentionally narrow. It only knows how to:
//! - read the JSON fixture bundle emitted by the Mina-side exporter
//! - decode the side-loaded proof / verification key blobs
//! - build the current `SimpleChainStatement` request shape

use std::str::FromStr;

use ark_ff::PrimeField;
use mina_curves::pasta::{Fp, Fq};
use serde::Deserialize;
use serde_json::Value;

use crate::pickles_error::PicklesError;
use crate::pickles_types::{
    CurvePointHex, ExportedBackendEvalsProbe, ExportedLagrangeCommitmentSample,
    ExportedRawWrapProof, ExportedRawWrapVerifier, ExportedRecursionChallenge,
    ExportedSrsIdentity, ExportedWrapOracleFields, ExportedWrapPublicInput, FieldEvalPairHex,
    PicklesVerifyRequest, PolyCommHex, SideLoadedProofBytes, SideLoadedVkBytes,
    SimpleChainFixture, SimpleChainFixtureBundle, SimpleChainStatement,
};

#[derive(Deserialize)]
struct RawSimpleChainBundle {
    #[serde(default)]
    side_loaded_verification_key_base64: Option<String>,
    #[serde(default)]
    raw_wrap_verification_key_json: Option<Value>,
    #[serde(default)]
    srs_identity: Option<Value>,
    rust_bundle: RawRustBundle,
}

#[derive(Deserialize)]
struct RawRustBundle {
    #[allow(dead_code)]
    bundle_version: u32,
    #[serde(default)]
    side_loaded_verification_key_base64: Option<String>,
    #[serde(default)]
    raw_wrap_verification_key_json: Option<Value>,
    #[serde(default)]
    srs_identity: Option<Value>,
    fixtures: Vec<RawRustFixture>,
}

#[derive(Deserialize)]
struct RawRustFixture {
    name: String,
    rust_inputs: RawRustInputs,
}

#[derive(Deserialize)]
struct RawRustInputs {
    statement_field_strings: Vec<String>,
    #[serde(default)]
    wrap_public_input_fields: Option<Vec<String>>,
    #[serde(default)]
    combined_inner_product_field: Option<String>,
    #[serde(default)]
    messages_for_next_step_proof_field: Option<String>,
    #[serde(default)]
    raw_wrap_proof_json: Option<Value>,
    #[serde(default)]
    final_backend_prev_challenges_json: Option<Value>,
    #[serde(default)]
    final_backend_evals_probe_json: Option<Value>,
    side_loaded_proof_base64: String,
}

/// Parse decimal `Fp` strings from the exporter bundle.
fn parse_field_strings(fields: &[String]) -> Result<Vec<Fp>, PicklesError> {
    fields
        .iter()
        .map(|field| {
            Fp::from_str(field).map_err(|_| PicklesError::InvalidFieldElement(field.clone()))
        })
        .collect()
}

/// Decode one base64-encoded exporter field into raw bytes.
fn decode_base64(field_name: &'static str, value: &str) -> Result<Vec<u8>, PicklesError> {
    base64::decode(value).map_err(|_| PicklesError::InvalidBase64(field_name))
}

/// Parse one canonical hex-encoded wrap-field element.
fn parse_hex_field(hex: &str) -> Result<Fq, PicklesError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fq::from(0u64));
    }
    let hex = if hex.len() % 2 == 0 {
        hex.to_owned()
    } else {
        format!("0{hex}")
    };

    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            PicklesError::InvalidFieldElement(format!("invalid canonical hex field: 0x{hex}"))
        })?;

    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

/// Parse a vector of canonical wrap-field hex strings.
fn parse_hex_field_strings(fields: &[String]) -> Result<Vec<Fq>, PicklesError> {
    fields.iter().map(|field| parse_hex_field(field)).collect()
}

/// Parse one affine curve point exported as `[x, y]` hex strings.
fn parse_curve_point_hex(value: &Value, field_name: &'static str) -> Result<CurvePointHex, PicklesError> {
    let coords = value
        .as_array()
        .ok_or_else(|| PicklesError::InvalidJson(format!("{field_name}: expected [x, y] array")))?;
    if coords.len() != 2 {
        return Err(PicklesError::InvalidJson(format!(
            "{field_name}: expected 2 coordinates, got {}",
            coords.len()
        )));
    }
    let x = coords[0].as_str().ok_or_else(|| {
        PicklesError::InvalidJson(format!("{field_name}: invalid x coordinate"))
    })?;
    let y = coords[1].as_str().ok_or_else(|| {
        PicklesError::InvalidJson(format!("{field_name}: invalid y coordinate"))
    })?;
    Ok(CurvePointHex {
        x: x.to_string(),
        y: y.to_string(),
    })
}

/// Parse an optional affine point, accepting `null` and `"infinity"`.
fn parse_optional_curve_point_hex(
    value: &Value,
    field_name: &'static str,
) -> Result<Option<CurvePointHex>, PicklesError> {
    match value {
        Value::Null => Ok(None),
        Value::String(infinity) if infinity == "infinity" => Ok(None),
        other => parse_curve_point_hex(other, field_name).map(Some),
    }
}

/// Parse Mina's JSON form of a polynomial commitment.
fn parse_poly_comm_hex(value: &Value, field_name: &'static str) -> Result<PolyCommHex, PicklesError> {
    let object = value.as_object().ok_or_else(|| {
        PicklesError::InvalidJson(format!("{field_name}: expected object"))
    })?;
    let unshifted = object
        .get("unshifted")
        .and_then(Value::as_array)
        .ok_or_else(|| PicklesError::InvalidJson(format!("{field_name}: missing unshifted")))?;
    let unshifted = unshifted
        .iter()
        .map(|point| parse_curve_point_hex(point, field_name))
        .collect::<Result<Vec<_>, _>>()?;
    let shifted = object
        .get("shifted")
        .map(|value| parse_optional_curve_point_hex(value, field_name))
        .transpose()?
        .flatten();
    Ok(PolyCommHex { unshifted, shifted })
}

/// Parse Mina-exported backend recursion challenges.
fn parse_exported_prev_challenges(
    value: &Value,
) -> Result<Vec<ExportedRecursionChallenge>, PicklesError> {
    let items = value.as_array().ok_or_else(|| {
        PicklesError::InvalidJson("final_backend_prev_challenges_json: expected array".into())
    })?;

    items
        .iter()
        .map(|item| {
            let object = item.as_object().ok_or_else(|| {
                PicklesError::InvalidJson(
                    "final_backend_prev_challenges_json: expected object entry".into(),
                )
            })?;
            let chals = object
                .get("chals")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    PicklesError::InvalidJson(
                        "final_backend_prev_challenges_json: missing chals".into(),
                    )
                })?
                .iter()
                .map(|value| {
                    value.as_str().map(ToString::to_string).ok_or_else(|| {
                        PicklesError::InvalidJson(
                            "final_backend_prev_challenges_json: invalid chal".into(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let comm = parse_poly_comm_hex(
                object.get("comm").ok_or_else(|| {
                    PicklesError::InvalidJson(
                        "final_backend_prev_challenges_json: missing comm".into(),
                    )
                })?,
                "final_backend_prev_challenges_json.comm",
            )?;
            Ok(ExportedRecursionChallenge {
                chals_hex: chals,
                comm,
            })
        })
        .collect()
}

/// Parse the exported SRS identity bundle used for Rust/Mina comparisons.
fn parse_exported_srs_identity(value: &Value) -> Result<ExportedSrsIdentity, PicklesError> {
    let object = value.as_object().ok_or_else(|| {
        PicklesError::InvalidJson("srs_identity: expected object".into())
    })?;
    let urs_h = parse_curve_point_hex(
        object
            .get("urs_h")
            .ok_or_else(|| PicklesError::InvalidJson("srs_identity: missing urs_h".into()))?,
        "srs_identity.urs_h",
    )?;
    let lagrange_commitments_domain_size = object
        .get("lagrange_commitments_domain_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            PicklesError::InvalidJson("srs_identity: missing lagrange_commitments_domain_size".into())
        })? as usize;
    let lagrange_commitments = object
        .get("lagrange_commitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PicklesError::InvalidJson("srs_identity: missing lagrange_commitments".into())
        })?
        .iter()
        .map(|value| parse_poly_comm_hex(value, "srs_identity.lagrange_commitments"))
        .collect::<Result<Vec<_>, _>>()?;
    let lagrange_commitment_samples = object
        .get("lagrange_commitment_samples")
        .map(parse_lagrange_commitment_samples)
        .transpose()?
        .unwrap_or_default();

    Ok(ExportedSrsIdentity {
        urs_h,
        urs_generators: None,
        lagrange_commitments_domain_size,
        lagrange_commitments,
        lagrange_commitment_samples,
    })
}

/// Parse the full ordered URS generator sidecar emitted by the Mina exporter.
fn parse_exported_urs_generators(value: &Value) -> Result<Vec<CurvePointHex>, PicklesError> {
    let items = value.as_array().ok_or_else(|| {
        PicklesError::InvalidJson("urs_generators: expected array".into())
    })?;

    items
        .iter()
        .map(|value| parse_curve_point_hex(value, "urs_generators"))
        .collect()
}

/// Parse sampled ordered Lagrange commitments from the exporter.
fn parse_lagrange_commitment_samples(
    value: &Value,
) -> Result<Vec<ExportedLagrangeCommitmentSample>, PicklesError> {
    let items = value.as_array().ok_or_else(|| {
        PicklesError::InvalidJson("srs_identity.lagrange_commitment_samples: expected array".into())
    })?;

    items.iter()
        .map(|item| {
            let object = item.as_object().ok_or_else(|| {
                PicklesError::InvalidJson(
                    "srs_identity.lagrange_commitment_samples: expected object".into(),
                )
            })?;
            let index = object
                .get("index")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    PicklesError::InvalidJson(
                        "srs_identity.lagrange_commitment_samples: missing index".into(),
                    )
                })? as usize;
            let commitment = parse_poly_comm_hex(
                object.get("commitment").ok_or_else(|| {
                    PicklesError::InvalidJson(
                        "srs_identity.lagrange_commitment_samples: missing commitment".into(),
                    )
                })?,
                "srs_identity.lagrange_commitment_samples.commitment",
            )?;
            Ok(ExportedLagrangeCommitmentSample { index, commitment })
        })
        .collect()
}

/// Parse one `(zeta, zeta_omega)` field-evaluation pair from backend probes.
fn parse_field_eval_pair_hex(
    value: &Value,
    field_name: &'static str,
) -> Result<FieldEvalPairHex, PicklesError> {
    let object = value.as_object().ok_or_else(|| {
        PicklesError::InvalidJson(format!("{field_name}: expected object"))
    })?;
    let parse_array = |name: &str| -> Result<Vec<String>, PicklesError> {
        object
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| PicklesError::InvalidJson(format!("{field_name}: missing {name}")))?
            .iter()
            .map(|value| {
                value.as_str().map(ToString::to_string).ok_or_else(|| {
                    PicklesError::InvalidJson(format!("{field_name}: invalid {name} value"))
                })
            })
            .collect()
    };

    Ok(FieldEvalPairHex {
        zeta: parse_array("zeta")?,
        zeta_omega: parse_array("zeta_omega")?,
    })
}

fn parse_optional_field_eval_pair_hex(
    value: &Value,
    field_name: &'static str,
) -> Result<Option<FieldEvalPairHex>, PicklesError> {
    match value {
        Value::Null => Ok(None),
        other => parse_field_eval_pair_hex(other, field_name).map(Some),
    }
}

fn parse_field_eval_pair_hex_list(
    value: &Value,
    field_name: &'static str,
) -> Result<Vec<FieldEvalPairHex>, PicklesError> {
    value
        .as_array()
        .ok_or_else(|| PicklesError::InvalidJson(format!("{field_name}: expected array")))?
        .iter()
        .map(|item| parse_field_eval_pair_hex(item, field_name))
        .collect()
}

fn parse_optional_field_eval_pair_hex_list(
    value: &Value,
    field_name: &'static str,
) -> Result<Vec<Option<FieldEvalPairHex>>, PicklesError> {
    value
        .as_array()
        .ok_or_else(|| PicklesError::InvalidJson(format!("{field_name}: expected array")))?
        .iter()
        .map(|item| parse_optional_field_eval_pair_hex(item, field_name))
        .collect()
}

/// Parse the small backend-evaluation probe emitted next to a fixture.
fn parse_exported_backend_evals_probe(
    value: &Value,
) -> Result<ExportedBackendEvalsProbe, PicklesError> {
    let object = value.as_object().ok_or_else(|| {
        PicklesError::InvalidJson("final_backend_evals_probe_json: expected object".into())
    })?;
    let parse_named = |name: &'static str| -> Result<FieldEvalPairHex, PicklesError> {
        parse_field_eval_pair_hex(
            object.get(name).ok_or_else(|| {
                PicklesError::InvalidJson(format!(
                    "final_backend_evals_probe_json: missing {name}"
                ))
            })?,
            "final_backend_evals_probe_json",
        )
    };
    let parse_optional_named =
        |name: &'static str| -> Result<Option<FieldEvalPairHex>, PicklesError> {
            parse_optional_field_eval_pair_hex(
                object.get(name).ok_or_else(|| {
                    PicklesError::InvalidJson(format!(
                        "final_backend_evals_probe_json: missing {name}"
                    ))
                })?,
                "final_backend_evals_probe_json",
            )
        };

    Ok(ExportedBackendEvalsProbe {
        witness_columns: parse_field_eval_pair_hex_list(
            object.get("witness_columns").ok_or_else(|| {
                PicklesError::InvalidJson(
                    "final_backend_evals_probe_json: missing witness_columns".into(),
                )
            })?,
            "final_backend_evals_probe_json.witness_columns",
        )?,
        w0: parse_named("w0")?,
        z: parse_named("z")?,
        permutation_columns: parse_field_eval_pair_hex_list(
            object.get("permutation_columns").ok_or_else(|| {
                PicklesError::InvalidJson(
                    "final_backend_evals_probe_json: missing permutation_columns".into(),
                )
            })?,
            "final_backend_evals_probe_json.permutation_columns",
        )?,
        s0: parse_named("s0")?,
        coefficients: parse_field_eval_pair_hex_list(
            object.get("coefficients").ok_or_else(|| {
                PicklesError::InvalidJson(
                    "final_backend_evals_probe_json: missing coefficients".into(),
                )
            })?,
            "final_backend_evals_probe_json.coefficients",
        )?,
        coeff0: parse_named("coeff0")?,
        generic_selector: parse_named("generic_selector")?,
        poseidon_selector: parse_named("poseidon_selector")?,
        complete_add_selector: parse_named("complete_add_selector")?,
        mul_selector: parse_named("mul_selector")?,
        emul_selector: parse_named("emul_selector")?,
        endomul_scalar_selector: parse_named("endomul_scalar_selector")?,
        range_check0_selector: parse_optional_named("range_check0_selector")?,
        range_check1_selector: parse_optional_named("range_check1_selector")?,
        foreign_field_add_selector: parse_optional_named("foreign_field_add_selector")?,
        foreign_field_mul_selector: parse_optional_named("foreign_field_mul_selector")?,
        xor_selector: parse_optional_named("xor_selector")?,
        rot_selector: parse_optional_named("rot_selector")?,
        lookup_aggregation: parse_optional_named("lookup_aggregation")?,
        lookup_table: parse_optional_named("lookup_table")?,
        lookup_sorted: parse_optional_field_eval_pair_hex_list(
            object.get("lookup_sorted").ok_or_else(|| {
                PicklesError::InvalidJson(
                    "final_backend_evals_probe_json: missing lookup_sorted".into(),
                )
            })?,
            "final_backend_evals_probe_json.lookup_sorted",
        )?,
        runtime_lookup_table: parse_optional_named("runtime_lookup_table")?,
        runtime_lookup_table_selector: parse_optional_named("runtime_lookup_table_selector")?,
        xor_lookup_selector: parse_optional_named("xor_lookup_selector")?,
        lookup_gate_lookup_selector: parse_optional_named("lookup_gate_lookup_selector")?,
        range_check_lookup_selector: parse_optional_named("range_check_lookup_selector")?,
        foreign_field_mul_lookup_selector: parse_optional_named(
            "foreign_field_mul_lookup_selector",
        )?,
    })
}

/// Parse a Mina-exported `Simple_chain` fixture bundle into typed Rust data.
pub fn parse_simple_chain_bundle(
    bundle_json: &str,
) -> Result<SimpleChainFixtureBundle, PicklesError> {
    parse_simple_chain_bundle_with_urs_sidecar(bundle_json, None)
}

/// Parse a Mina-exported `Simple_chain` bundle plus the optional full ordered
/// URS sidecar emitted alongside the manifest.
pub fn parse_simple_chain_bundle_with_urs_sidecar(
    bundle_json: &str,
    urs_generators_json: Option<&str>,
) -> Result<SimpleChainFixtureBundle, PicklesError> {
    let raw: RawSimpleChainBundle = serde_json::from_str(bundle_json)
        .map_err(|err| PicklesError::InvalidJson(err.to_string()))?;

    let vk_base64 = raw
        .rust_bundle
        .side_loaded_verification_key_base64
        .or(raw.side_loaded_verification_key_base64)
        .ok_or(PicklesError::InvalidJson(
            "missing side-loaded verification key".into(),
        ))?;

    let verification_key = SideLoadedVkBytes(decode_base64(
        "side_loaded_verification_key_base64",
        &vk_base64,
    )?);
    let exported_raw_wrap_verifier = raw
        .rust_bundle
        .raw_wrap_verification_key_json
        .or(raw.raw_wrap_verification_key_json)
        .map(|json| ExportedRawWrapVerifier {
            verifier_index_json: json.to_string(),
        });
    let mut exported_srs_identity = raw
        .rust_bundle
        .srs_identity
        .or(raw.srs_identity)
        .map(|json| parse_exported_srs_identity(&json))
        .transpose()?;
    if let Some(urs_generators_json) = urs_generators_json {
        let value: Value = serde_json::from_str(urs_generators_json)
            .map_err(|err| PicklesError::InvalidJson(err.to_string()))?;
        let urs_generators = parse_exported_urs_generators(&value)?;
        if let Some(identity) = exported_srs_identity.as_mut() {
            identity.urs_generators = Some(urs_generators);
        }
    }

    let fixtures = raw
        .rust_bundle
        .fixtures
        .into_iter()
        .map(|fixture| {
            let statement_fields =
                parse_field_strings(&fixture.rust_inputs.statement_field_strings)?;
            let statement = SimpleChainStatement::from_fields(&statement_fields)?;
            let proof = SideLoadedProofBytes(decode_base64(
                "side_loaded_proof_base64",
                &fixture.rust_inputs.side_loaded_proof_base64,
            )?);
            let exported_wrap_public_input = fixture
                .rust_inputs
                .wrap_public_input_fields
                .map(|hex_fields| {
                    let fields = parse_hex_field_strings(&hex_fields)?;
                    Ok(ExportedWrapPublicInput { hex_fields, fields })
                })
                .transpose()?;
            let exported_wrap_oracle_fields = match (
                fixture.rust_inputs.combined_inner_product_field,
                fixture.rust_inputs.messages_for_next_step_proof_field,
            ) {
                (
                    Some(combined_inner_product_field_hex),
                    Some(messages_for_next_step_proof_field_hex),
                ) => Some(ExportedWrapOracleFields {
                    combined_inner_product_field_hex,
                    messages_for_next_step_proof_field_hex,
                }),
                (None, None) => None,
                _ => {
                    return Err(PicklesError::InvalidJson(
                        "incomplete exported wrap oracle fields".into(),
                    ))
                }
            };
            let exported_raw_wrap_proof =
                fixture
                    .rust_inputs
                    .raw_wrap_proof_json
                    .map(|json| ExportedRawWrapProof {
                        proof_json: json.to_string(),
                    });
            let exported_backend_prev_challenges = fixture
                .rust_inputs
                .final_backend_prev_challenges_json
                .map(|json| parse_exported_prev_challenges(&json))
                .transpose()?;
            let exported_backend_evals_probe = fixture
                .rust_inputs
                .final_backend_evals_probe_json
                .map(|json| parse_exported_backend_evals_probe(&json))
                .transpose()?;

            Ok(SimpleChainFixture {
                name: fixture.name,
                statement,
                proof,
                exported_wrap_public_input,
                exported_wrap_oracle_fields,
                exported_raw_wrap_proof,
                exported_backend_prev_challenges,
                exported_backend_evals_probe,
            })
        })
        .collect::<Result<Vec<_>, PicklesError>>()?;

    Ok(SimpleChainFixtureBundle {
        verification_key,
        exported_raw_wrap_verifier,
        exported_srs_identity,
        fixtures,
    })
}

/// Parse the bundle and immediately extract one named fixture as a verifier request.
pub fn parse_simple_chain_request(
    bundle_json: &str,
    fixture_name: &str,
) -> Result<PicklesVerifyRequest, PicklesError> {
    let bundle = parse_simple_chain_bundle(bundle_json)?;
    bundle.request_for_fixture(fixture_name)
}
