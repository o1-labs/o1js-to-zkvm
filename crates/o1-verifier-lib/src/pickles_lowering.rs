extern crate alloc;

use alloc::vec::Vec;

use mina_curves::pasta::Fp;

use crate::pickles_error::PicklesError;
use crate::pickles_types::PicklesVerifyRequest;
use crate::{VestaProof, VestaVerifierIndex};
#[cfg(feature = "std")]
use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use crate::pickles_types::{CurvePointHex, SideLoadedProofMetadata};

pub struct LoweredWrapInstance {
    pub verifier_index: VestaVerifierIndex,
    pub proof: VestaProof,
    pub public_input: Vec<Fp>,
}

pub fn lower_simple_chain_request(
    _request: &PicklesVerifyRequest,
) -> Result<LoweredWrapInstance, PicklesError> {
    Err(PicklesError::LoweringNotImplemented(
        "Pickles side-loaded proof/VK lowering reaches decoded proof metadata, but wrap verification-key decoding and full Kimchi reconstruction are not implemented yet",
    ))
}

#[cfg(feature = "std")]
pub fn lower_simple_chain_metadata(
    request: &PicklesVerifyRequest,
) -> Result<SideLoadedProofMetadata, PicklesError> {
    decode_side_loaded_proof_metadata(&request.proof.0)
}

#[cfg(feature = "std")]
fn decode_side_loaded_proof_metadata(
    proof_bytes: &[u8],
) -> Result<SideLoadedProofMetadata, PicklesError> {
    let proof_text = normalize_proof_text(
        core::str::from_utf8(proof_bytes).map_err(|_| PicklesError::InvalidProofText("proof"))?,
    );
    let sexp =
        sexp::parse(&proof_text).map_err(|err| PicklesError::InvalidSexp(err.to_string()))?;

    let top = list_items(&sexp)?;
    let statement = group_entries(top, "statement")?;
    let proof_state = group_entries(statement, "proof_state")?;
    let deferred_values = group_entries(proof_state, "deferred_values")?;
    let branch_data = group_entries(deferred_values, "branch_data")?;
    let wrap_messages = group_entries(proof_state, "messages_for_next_wrap_proof")?;
    let next_step_messages = group_entries(statement, "messages_for_next_step_proof")?;
    let prev_evals = group_entries(top, "prev_evals")?;
    let prev_eval_evals = group_entries(prev_evals, "evals")?;

    Ok(SideLoadedProofMetadata {
        proofs_verified: parse_proofs_verified(atom(binding_one(
            branch_data,
            "proofs_verified",
        )?)?)?,
        domain_log2: parse_domain_log2(atom(binding_one(branch_data, "domain_log2")?)?)?,
        sponge_digest_before_evaluations: binding_rest(
            proof_state,
            "sponge_digest_before_evaluations",
        )?
        .iter()
        .map(atom_owned)
        .collect::<Result<Vec<_>, _>>()?,
        wrap_challenge_polynomial_commitment: parse_point(binding_one(
            wrap_messages,
            "challenge_polynomial_commitment",
        )?)?,
        wrap_old_bulletproof_challenges_count: binding_rest(
            wrap_messages,
            "old_bulletproof_challenges",
        )
        .and_then(flatten_single_list)?
        .len(),
        next_step_challenge_polynomial_commitments: binding_rest(
            next_step_messages,
            "challenge_polynomial_commitments",
        )?
        .iter()
        .map(parse_point)
        .collect::<Result<Vec<_>, _>>()?,
        next_step_old_bulletproof_challenges_count: binding_rest(
            next_step_messages,
            "old_bulletproof_challenges",
        )
        .and_then(flatten_single_list)?
        .len(),
        prev_evals_public_input: flatten_single_list(binding_rest(prev_eval_evals, "public_input")?)?
            .iter()
            .map(atom_owned)
            .collect::<Result<Vec<_>, _>>()?,
        ft_eval1: atom_owned(binding_one(prev_evals, "ft_eval1")?)?,
    })
}

#[cfg(feature = "std")]
fn normalize_proof_text(proof_text: &str) -> String {
    proof_text.replace("domain_log2\"", "domain_log2 \"")
}

#[cfg(feature = "std")]
fn list_items(sexp: &sexp::Sexp) -> Result<&[sexp::Sexp], PicklesError> {
    match sexp {
        sexp::Sexp::List(items) => Ok(items),
        _ => Err(PicklesError::InvalidSexp(
            "expected list at current node".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn atom(sexp: &sexp::Sexp) -> Result<&str, PicklesError> {
    match sexp {
        sexp::Sexp::Atom(sexp::Atom::S(atom)) => Ok(atom.as_str()),
        sexp::Sexp::Atom(sexp::Atom::I(_)) => Err(PicklesError::InvalidSexp(
            "integer atoms are unsupported in side-loaded proofs".to_string(),
        )),
        sexp::Sexp::Atom(sexp::Atom::F(_)) => Err(PicklesError::InvalidSexp(
            "floating-point atoms are unsupported in side-loaded proofs".to_string(),
        )),
        _ => Err(PicklesError::InvalidSexp(
            "expected atom at current node".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn atom_owned(sexp: &sexp::Sexp) -> Result<String, PicklesError> {
    Ok(atom(sexp)?.to_string())
}

#[cfg(feature = "std")]
fn binding_rest<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a [sexp::Sexp], PicklesError> {
    let entry = entries
        .iter()
        .find(|entry| match entry {
            sexp::Sexp::List(items) => matches!(items.first(), Some(first) if atom(first).ok() == Some(key)),
            _ => false,
        })
        .ok_or(PicklesError::MissingProofField(key))?;

    let items = list_items(entry)?;
    Ok(&items[1..])
}

#[cfg(feature = "std")]
fn binding_one<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a sexp::Sexp, PicklesError> {
    let rest = binding_rest(entries, key)?;
    if rest.len() != 1 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected exactly one payload item for {key}, got {}",
            rest.len()
        )));
    }
    Ok(&rest[0])
}

#[cfg(feature = "std")]
fn group_entries<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a [sexp::Sexp], PicklesError> {
    list_items(binding_one(entries, key)?)
}

#[cfg(feature = "std")]
fn flatten_single_list<'a>(items: &'a [sexp::Sexp]) -> Result<&'a [sexp::Sexp], PicklesError> {
    if items.len() == 1 {
        list_items(&items[0])
    } else {
        Ok(items)
    }
}

#[cfg(feature = "std")]
fn parse_proofs_verified(value: &str) -> Result<u8, PicklesError> {
    match value {
        "N0" => Ok(0),
        "N1" => Ok(1),
        "N2" => Ok(2),
        other => Err(PicklesError::InvalidSexp(format!(
            "unsupported proofs_verified atom: {other}"
        ))),
    }
}

#[cfg(feature = "std")]
fn parse_domain_log2(value: &str) -> Result<u8, PicklesError> {
    let bytes = value.as_bytes();
    if bytes.len() == 1 {
        return Ok(bytes[0]);
    }

    if bytes.len() == 4 && bytes[0] == b'\\' && bytes[1..].iter().all(u8::is_ascii_digit) {
        let octal = core::str::from_utf8(&bytes[1..]).map_err(|_| {
            PicklesError::InvalidSexp(format!("invalid domain_log2 escape: {value:?}"))
        })?;
        return u8::from_str_radix(octal, 8).map_err(|_| {
            PicklesError::InvalidSexp(format!("invalid domain_log2 escape: {value:?}"))
        });
    }

    Err(PicklesError::InvalidSexp(format!(
        "expected domain_log2 byte string, got {value:?}"
    )))
}

#[cfg(feature = "std")]
fn parse_point(sexp: &sexp::Sexp) -> Result<CurvePointHex, PicklesError> {
    let coords = list_items(sexp)?;
    let coords = if coords.len() == 1 {
        list_items(&coords[0])?
    } else {
        coords
    };

    if coords.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected affine point with 2 coordinates, got {}",
            coords.len()
        )));
    }
    Ok(CurvePointHex {
        x: atom_owned(&coords[0])?,
        y: atom_owned(&coords[1])?,
    })
}
