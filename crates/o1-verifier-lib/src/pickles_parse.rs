use std::str::FromStr;

use mina_curves::pasta::Fp;
use serde::Deserialize;

use crate::pickles_error::PicklesError;
use crate::pickles_types::{
    PicklesVerifyRequest, SideLoadedProofBytes, SideLoadedVkBytes, SimpleChainFixture,
    SimpleChainFixtureBundle, SimpleChainStatement,
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
    side_loaded_proof_base64: String,
}

fn parse_field_strings(fields: &[String]) -> Result<Vec<Fp>, PicklesError> {
    fields
        .iter()
        .map(|field| Fp::from_str(field).map_err(|_| PicklesError::InvalidFieldElement(field.clone())))
        .collect()
}

fn decode_base64(field_name: &'static str, value: &str) -> Result<Vec<u8>, PicklesError> {
    base64::decode(value).map_err(|_| PicklesError::InvalidBase64(field_name))
}

pub fn parse_simple_chain_bundle(bundle_json: &str) -> Result<SimpleChainFixtureBundle, PicklesError> {
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
            let statement_fields = parse_field_strings(&fixture.rust_inputs.statement_field_strings)?;
            let statement = SimpleChainStatement::from_fields(&statement_fields)?;
            let proof = SideLoadedProofBytes(decode_base64(
                "side_loaded_proof_base64",
                &fixture.rust_inputs.side_loaded_proof_base64,
            )?);

            Ok(SimpleChainFixture {
                name: fixture.name,
                statement,
                proof,
            })
        })
        .collect::<Result<Vec<_>, PicklesError>>()?;

    Ok(SimpleChainFixtureBundle {
        verification_key,
        fixtures,
    })
}

pub fn parse_simple_chain_request(
    bundle_json: &str,
    fixture_name: &str,
) -> Result<PicklesVerifyRequest, PicklesError> {
    let bundle = parse_simple_chain_bundle(bundle_json)?;
    bundle.request_for_fixture(fixture_name)
}
