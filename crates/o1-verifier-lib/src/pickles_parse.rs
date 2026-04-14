//! Parsing helpers for the Mina `Simple_chain` exporter bundle.
//!
//! This module is intentionally narrow. It only knows how to:
//! - read the JSON fixture bundle emitted by the Mina-side exporter
//! - decode the side-loaded proof / verification key blobs
//! - build the current `SimpleChainStatement` request shape

use std::str::FromStr;

use ark_ff::PrimeField;
use mina_curves::pasta::Fp;
use serde::Deserialize;

use crate::pickles_error::PicklesError;
use crate::pickles_types::{
    ExportedWrapOracleFields, ExportedWrapPublicInput, PicklesVerifyRequest, SideLoadedProofBytes,
    SideLoadedVkBytes, SimpleChainFixture, SimpleChainFixtureBundle, SimpleChainStatement,
};

#[derive(Deserialize)]
struct RawSimpleChainBundle {
    #[serde(default)]
    side_loaded_verification_key_base64: Option<String>,
    rust_bundle: RawRustBundle,
}

#[derive(Deserialize)]
struct RawRustBundle {
    #[allow(dead_code)]
    bundle_version: u32,
    #[serde(default)]
    side_loaded_verification_key_base64: Option<String>,
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
    side_loaded_proof_base64: String,
}

fn parse_field_strings(fields: &[String]) -> Result<Vec<Fp>, PicklesError> {
    fields
        .iter()
        .map(|field| {
            Fp::from_str(field).map_err(|_| PicklesError::InvalidFieldElement(field.clone()))
        })
        .collect()
}

fn decode_base64(field_name: &'static str, value: &str) -> Result<Vec<u8>, PicklesError> {
    base64::decode(value).map_err(|_| PicklesError::InvalidBase64(field_name))
}

fn parse_hex_field(hex: &str) -> Result<Fp, PicklesError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(Fp::from(0u64));
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

    Ok(Fp::from_be_bytes_mod_order(&bytes))
}

fn parse_hex_field_strings(fields: &[String]) -> Result<Vec<Fp>, PicklesError> {
    fields.iter().map(|field| parse_hex_field(field)).collect()
}

/// Parse a Mina-exported `Simple_chain` fixture bundle into typed Rust data.
pub fn parse_simple_chain_bundle(
    bundle_json: &str,
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

            Ok(SimpleChainFixture {
                name: fixture.name,
                statement,
                proof,
                exported_wrap_public_input,
                exported_wrap_oracle_fields,
            })
        })
        .collect::<Result<Vec<_>, PicklesError>>()?;

    Ok(SimpleChainFixtureBundle {
        verification_key,
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
