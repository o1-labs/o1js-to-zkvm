#![cfg(feature = "std")]

use std::env;
use std::process::ExitCode;

use ark_ff::{BigInteger, PrimeField};
use o1_verifier_lib::{lower_simple_chain_request, parse_simple_chain_bundle};
use o1_verifier_lib::pickles_types::{CurvePointHex, PolyCommHex};
use poly_commitment::SRS as _;

fn normalize_hex(hex: &str) -> String {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.to_ascii_uppercase()
    }
}

fn field_to_hex<F: PrimeField>(field: F) -> String {
    let bytes = field.into_bigint().to_bytes_be();
    if bytes.is_empty() {
        "0x0".into()
    } else {
        let mut out = String::with_capacity(2 + bytes.len() * 2);
        out.push_str("0x");
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut out, "{byte:02X}").expect("write to string");
        }
        out
    }
}

fn compare_point(
    actual_x: &str,
    actual_y: &str,
    expected: &CurvePointHex,
) -> Option<String> {
    if normalize_hex(actual_x) != normalize_hex(&expected.x) {
        return Some(format!(
            "x mismatch: actual={}, expected={}",
            normalize_hex(actual_x),
            normalize_hex(&expected.x)
        ));
    }
    if normalize_hex(actual_y) != normalize_hex(&expected.y) {
        return Some(format!(
            "y mismatch: actual={}, expected={}",
            normalize_hex(actual_y),
            normalize_hex(&expected.y)
        ));
    }
    None
}

fn compare_poly_comm(
    actual: &poly_commitment::commitment::PolyComm<mina_curves::pasta::Pallas>,
    expected: &PolyCommHex,
) -> Option<String> {
    if actual.chunks.len() != expected.unshifted.len() {
        return Some(format!(
            "chunk length mismatch: actual={}, expected={}",
            actual.chunks.len(),
            expected.unshifted.len()
        ));
    }
    if expected.shifted.is_some() {
        return Some("expected shifted commitment is present".into());
    }

    for (chunk_index, (actual_chunk, expected_chunk)) in
        actual.chunks.iter().zip(&expected.unshifted).enumerate()
    {
        let actual_x = field_to_hex(actual_chunk.x);
        let actual_y = field_to_hex(actual_chunk.y);
        if let Some(mismatch) = compare_point(&actual_x, &actual_y, expected_chunk) {
            return Some(format!("chunk[{chunk_index}] {mismatch}"));
        }
    }

    None
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let bundle_path = args
        .next()
        .unwrap_or_else(|| "fixtures/simple_chain_real_bundle.json".into());
    let fixture_name = args.next().unwrap_or_else(|| "recursive_step".into());

    let bundle_json = match std::fs::read_to_string(&bundle_path) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("failed to read bundle {bundle_path}: {err}");
            return ExitCode::from(1);
        }
    };

    let bundle = match parse_simple_chain_bundle(&bundle_json) {
        Ok(bundle) => bundle,
        Err(err) => {
            eprintln!("failed to parse bundle: {err}");
            return ExitCode::from(1);
        }
    };
    let request = match bundle.request_for_fixture(&fixture_name) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("failed to load fixture {fixture_name}: {err}");
            return ExitCode::from(1);
        }
    };
    let exported_srs_identity = match request.exported_srs_identity.as_ref() {
        Some(identity) => identity,
        None => {
            eprintln!("fixture {fixture_name} is missing exported_srs_identity");
            return ExitCode::from(1);
        }
    };

    let lowered = match lower_simple_chain_request(&request) {
        Ok(lowered) => lowered,
        Err(err) => {
            eprintln!("failed to lower wrap request: {err}");
            return ExitCode::from(1);
        }
    };

    let h_x = field_to_hex(lowered.verifier_index.srs.h.x);
    let h_y = field_to_hex(lowered.verifier_index.srs.h.y);
    if let Some(mismatch) = compare_point(&h_x, &h_y, &exported_srs_identity.urs_h) {
        eprintln!("urs_h mismatch: {mismatch}");
        return ExitCode::from(2);
    }

    let lagrange_basis = lowered
        .verifier_index
        .srs
        .get_lagrange_basis(lowered.verifier_index.domain);

    if lagrange_basis.len() != exported_srs_identity.lagrange_commitments.len() {
        eprintln!(
            "lagrange length mismatch: actual={}, expected={}",
            lagrange_basis.len(),
            exported_srs_identity.lagrange_commitments.len()
        );
        return ExitCode::from(3);
    }

    for (index, (actual, expected)) in lagrange_basis
        .iter()
        .zip(&exported_srs_identity.lagrange_commitments)
        .enumerate()
    {
        if let Some(mismatch) = compare_poly_comm(actual, expected) {
            println!(
                "wrap SRS mismatch at lagrange_basis[{index}]: {mismatch}"
            );
            return ExitCode::from(4);
        }
    }

    println!(
        "wrap SRS matches Mina export: h and {} ordered lagrange commitments",
        lagrange_basis.len()
    );
    ExitCode::SUCCESS
}
