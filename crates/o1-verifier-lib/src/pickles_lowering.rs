extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use mina_curves::pasta::Fp;

use crate::pickles_error::PicklesError;
use crate::pickles_types::{
    BulletproofChallengeHex, CurvePointHex, CurvePointPairHex, NamedPointSectionHex,
    NamedSectionCount, PicklesVerifyRequest, PlonkDeferredValuesHex, PlonkFeatureFlags,
    SideLoadedProofMetadata, WrapBulletproofHex, WrapProofBodyHex, WrapProofCommitmentsHex,
};
use crate::{VestaProof, VestaVerifierIndex};

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
    let (statement, proof_or_wrapper) = split_statement_and_proof(top)?;
    let proof_state = with_context("proof_state", group_entries(statement, "proof_state"))?;
    let deferred_values =
        with_context("deferred_values", group_entries(proof_state, "deferred_values"))?;
    let branch_data = with_context("branch_data", group_entries(deferred_values, "branch_data"))?;
    let plonk = with_context("plonk", group_entries(deferred_values, "plonk"))?;
    let wrap_messages = with_context(
        "messages_for_next_wrap_proof",
        group_entries(proof_state, "messages_for_next_wrap_proof"),
    )?;
    let next_step_messages = with_context(
        "messages_for_next_step_proof",
        group_entries(statement, "messages_for_next_step_proof")
            .or_else(|_| group_entries(proof_or_wrapper, "messages_for_next_step_proof")),
    )?;
    let prev_evals = with_context(
        "prev_evals",
        group_entries(statement, "prev_evals")
            .or_else(|_| group_entries(top, "prev_evals"))
            .or_else(|_| group_entries(proof_or_wrapper, "prev_evals")),
    )?;
    let prev_eval_wrapper = with_context("prev_evals.evals", group_entries(prev_evals, "evals"))?;
    let prev_eval_sections = with_context(
        "prev_evals.evals.evals",
        group_entries(prev_eval_wrapper, "evals"),
    )?;
    let inner_proof =
        with_context("inner_proof", group_entries(proof_or_wrapper, "proof")).unwrap_or(proof_or_wrapper);

    Ok(SideLoadedProofMetadata {
        proofs_verified: with_context(
            "branch_data.proofs_verified",
            parse_proofs_verified(atom(binding_one(branch_data, "proofs_verified")?)?),
        )?,
        domain_log2: with_context(
            "branch_data.domain_log2",
            parse_domain_log2(atom(binding_one(branch_data, "domain_log2")?)?),
        )?,
        plonk: with_context("plonk", parse_plonk(plonk))?,
        deferred_bulletproof_challenges: with_context(
            "deferred_values.bulletproof_challenges",
            parse_prechallenge_group(binding_rest(deferred_values, "bulletproof_challenges")?),
        )?,
        sponge_digest_before_evaluations: with_context(
            "proof_state.sponge_digest_before_evaluations",
            parse_atom_vector(binding_rest(proof_state, "sponge_digest_before_evaluations")?),
        )?,
        wrap_challenge_polynomial_commitment: with_context(
            "messages_for_next_wrap_proof.challenge_polynomial_commitment",
            parse_point(binding_one(wrap_messages, "challenge_polynomial_commitment")?),
        )?,
        wrap_old_bulletproof_challenges: with_context(
            "messages_for_next_wrap_proof.old_bulletproof_challenges",
            parse_prechallenge_groups(binding_rest(wrap_messages, "old_bulletproof_challenges")?),
        )?,
        next_step_challenge_polynomial_commitments: with_context(
            "messages_for_next_step_proof.challenge_polynomial_commitments",
            parse_point_vector(binding_rest(next_step_messages, "challenge_polynomial_commitments")?),
        )?,
        next_step_old_bulletproof_challenges: with_context(
            "messages_for_next_step_proof.old_bulletproof_challenges",
            parse_prechallenge_groups(binding_rest(next_step_messages, "old_bulletproof_challenges")?),
        )?,
        prev_evals_public_input: with_context(
            "prev_evals.evals.public_input",
            parse_atom_vector(binding_rest(prev_eval_wrapper, "public_input")?),
        )?,
        prev_evals_sections: with_context(
            "prev_evals.evals.evals",
            parse_named_section_counts(prev_eval_sections),
        )?,
        ft_eval1: with_context("prev_evals.ft_eval1", atom_owned(binding_one(prev_evals, "ft_eval1")?))?,
        inner_proof: with_context("inner_proof", parse_inner_proof(inner_proof))?,
    })
}

#[cfg(feature = "std")]
fn normalize_proof_text(proof_text: &str) -> String {
    proof_text.replace("domain_log2\"", "domain_log2 \"")
}

#[cfg(feature = "std")]
fn peel_singletons<'a>(mut sexp: &'a sexp::Sexp) -> &'a sexp::Sexp {
    while let sexp::Sexp::List(items) = sexp {
        if items.len() != 1 {
            break;
        }
        sexp = &items[0];
    }
    sexp
}

#[cfg(feature = "std")]
fn list_items(sexp: &sexp::Sexp) -> Result<&[sexp::Sexp], PicklesError> {
    match peel_singletons(sexp) {
        sexp::Sexp::List(items) => Ok(items),
        _ => Err(PicklesError::InvalidSexp(
            "expected list at current node".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn atom(sexp: &sexp::Sexp) -> Result<&str, PicklesError> {
    match peel_singletons(sexp) {
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
    if matches!(entries.first().map(atom), Some(Ok(found)) if found == key) {
        if entries.len() == 2 {
            return Ok(&entries[1..]);
        }
        let next_binding = entries
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(idx, entry)| is_binding_entry(entry).then_some(idx))
            .unwrap_or(entries.len());
        return Ok(&entries[1..next_binding]);
    }

    if entries.len() == 1 {
        if let Ok(inner) = list_items(&entries[0]) {
            if let Ok(rest) = binding_rest(inner, key) {
                return Ok(rest);
            }
        }
    }

    let entry = entries
        .iter()
        .find(|entry| match peel_singletons(entry) {
            sexp::Sexp::List(items) => {
                matches!(items.first(), Some(first) if atom(first).ok() == Some(key))
            }
            _ => false,
        })
        .ok_or_else(|| {
            PicklesError::InvalidSexp(format!(
                "missing proof field: {key}; available keys: {}",
                describe_entry_keys(entries)
            ))
        })?;

    let items = list_items(entry)?;
    Ok(&items[1..])
}

#[cfg(feature = "std")]
fn is_binding_entry(sexp: &sexp::Sexp) -> bool {
    match peel_singletons(sexp) {
        sexp::Sexp::List(items) => matches!(items.first().map(atom), Some(Ok(_))),
        sexp::Sexp::Atom(_) => false,
    }
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
fn binding_optional_rest<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Option<&'a [sexp::Sexp]> {
    binding_rest(entries, key).ok()
}

#[cfg(feature = "std")]
fn group_entries<'a>(
    entries: &'a [sexp::Sexp],
    key: &'static str,
) -> Result<&'a [sexp::Sexp], PicklesError> {
    list_items(binding_one(entries, key)?)
}

#[cfg(feature = "std")]
fn split_statement_and_proof<'a>(
    top: &'a [sexp::Sexp],
) -> Result<(&'a [sexp::Sexp], &'a [sexp::Sexp]), PicklesError> {
    if matches!(top.first().map(atom), Some(Ok("statement"))) {
        let proof_index = top
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(idx, item)| {
                let items = list_items(item).ok()?;
                matches!(items.first().map(atom), Some(Ok("proof"))).then_some(idx)
            })
            .ok_or_else(|| {
                PicklesError::InvalidSexp(format!(
                    "flattened statement root is missing proof payload; available keys: {}",
                    describe_entry_keys(top)
                ))
            })?;

        return Ok((
            &top[1..proof_index],
            list_items(binding_one(&top[proof_index..=proof_index], "proof")?)?,
        ));
    }

    if binding_optional_rest(top, "statement").is_some() {
        return Ok((group_entries(top, "statement")?, group_entries(top, "proof")?));
    }

    Err(PicklesError::InvalidSexp(format!(
        "missing proof field: statement; available keys: {}",
        describe_entry_keys(top)
    )))
}

#[cfg(feature = "std")]
fn with_context<T>(label: &'static str, result: Result<T, PicklesError>) -> Result<T, PicklesError> {
    result.map_err(|err| match err {
        PicklesError::InvalidSexp(message) => PicklesError::InvalidSexp(format!("{label}: {message}")),
        PicklesError::MissingProofField(field) => PicklesError::InvalidSexp(format!(
            "{label}: missing proof field: {field}"
        )),
        other => other,
    })
}

#[cfg(feature = "std")]
fn describe_entry_keys(entries: &[sexp::Sexp]) -> String {
    let mut keys = Vec::new();
    for entry in entries {
        match peel_singletons(entry) {
            sexp::Sexp::List(items) => {
                if let Some(first) = items.first() {
                    if let Ok(name) = atom(first) {
                        keys.push(name.to_string());
                        continue;
                    }
                }
                keys.push("<list>".to_string());
            }
            sexp::Sexp::Atom(_) => keys.push("<atom>".to_string()),
        }
    }
    format!("[{}]", keys.join(", "))
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
fn parse_atom_vector(items: &[sexp::Sexp]) -> Result<Vec<String>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(_) => list_items(&items[0])?,
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(atom_owned).collect()
}

#[cfg(feature = "std")]
fn parse_point(sexp: &sexp::Sexp) -> Result<CurvePointHex, PicklesError> {
    let coords = list_items(sexp)?;
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

#[cfg(feature = "std")]
fn parse_point_vector(items: &[sexp::Sexp]) -> Result<Vec<CurvePointHex>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(inner) if inner.iter().all(|item| parse_point(item).is_ok()) => inner,
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(parse_point).collect()
}

#[cfg(feature = "std")]
fn parse_inner_hex(sexp: &sexp::Sexp) -> Result<Vec<String>, PicklesError> {
    match peel_singletons(sexp) {
        sexp::Sexp::List(items) if items.is_empty() => Err(PicklesError::InvalidSexp(
            "expected inner(...) wrapper".to_string(),
        )),
        sexp::Sexp::List(items) => match atom(&items[0]) {
            Ok("inner") => {
                let payload = if items.len() == 2 {
                    match peel_singletons(&items[1]) {
                        sexp::Sexp::List(_) => list_items(&items[1])?,
                        _ => &items[1..],
                    }
                } else {
                    &items[1..]
                };
                payload.iter().map(atom_owned).collect()
            }
            Ok(_) if items.len() == 1 => parse_inner_hex(&items[0]),
            Ok(other) => Err(PicklesError::InvalidSexp(format!(
                "expected inner(...) wrapper, got {other}"
            ))),
            Err(_) if items.len() == 1 => parse_inner_hex(&items[0]),
            Err(_) => parse_inner_hex(&items[0]),
        },
        _ => Err(PicklesError::InvalidSexp(
            "expected inner(...) wrapper".to_string(),
        )),
    }
}

#[cfg(feature = "std")]
fn parse_pchallenge(sexp: &sexp::Sexp) -> Result<BulletproofChallengeHex, PicklesError> {
    let items = list_items(sexp)?;
    if items.is_empty() || atom(&items[0])? != "prechallenge" {
        return Err(PicklesError::InvalidSexp(
            "expected prechallenge(...) wrapper".to_string(),
        ));
    }
    if items.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected exactly one prechallenge payload, got {}",
            items.len() - 1
        )));
    }
    Ok(BulletproofChallengeHex {
        prechallenge_inner: parse_inner_hex(&items[1])?,
    })
}

#[cfg(feature = "std")]
fn parse_prechallenge_group(items: &[sexp::Sexp]) -> Result<Vec<BulletproofChallengeHex>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(inner) if inner.iter().all(|item| parse_pchallenge(item).is_ok()) => inner,
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(parse_pchallenge).collect()
}

#[cfg(feature = "std")]
fn parse_prechallenge_groups(
    items: &[sexp::Sexp],
) -> Result<Vec<Vec<BulletproofChallengeHex>>, PicklesError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(group) = parse_prechallenge_group(items) {
        return Ok(vec![group]);
    }

    if items.len() == 1 {
        return parse_prechallenge_groups(list_items(&items[0])?);
    }

    items.iter()
        .map(|item| parse_prechallenge_group(list_items(item)?))
        .collect()
}

#[cfg(feature = "std")]
fn parse_bool_atom(sexp: &sexp::Sexp) -> Result<bool, PicklesError> {
    match atom(sexp)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(PicklesError::InvalidSexp(format!(
            "expected boolean atom, got {other}"
        ))),
    }
}

#[cfg(feature = "std")]
fn parse_feature_flags(entries: &[sexp::Sexp]) -> Result<PlonkFeatureFlags, PicklesError> {
    Ok(PlonkFeatureFlags {
        range_check0: with_context(
            "feature_flags.range_check0",
            parse_bool_atom(binding_one(entries, "range_check0")?),
        )?,
        range_check1: with_context(
            "feature_flags.range_check1",
            parse_bool_atom(binding_one(entries, "range_check1")?),
        )?,
        foreign_field_add: with_context(
            "feature_flags.foreign_field_add",
            parse_bool_atom(binding_one(entries, "foreign_field_add")?),
        )?,
        foreign_field_mul: with_context(
            "feature_flags.foreign_field_mul",
            parse_bool_atom(binding_one(entries, "foreign_field_mul")?),
        )?,
        xor: with_context("feature_flags.xor", parse_bool_atom(binding_one(entries, "xor")?))?,
        rot: with_context("feature_flags.rot", parse_bool_atom(binding_one(entries, "rot")?))?,
        lookup: with_context(
            "feature_flags.lookup",
            parse_bool_atom(binding_one(entries, "lookup")?),
        )?,
        runtime_tables: with_context(
            "feature_flags.runtime_tables",
            parse_bool_atom(binding_one(entries, "runtime_tables")?),
        )?,
    })
}

#[cfg(feature = "std")]
fn parse_plonk(entries: &[sexp::Sexp]) -> Result<PlonkDeferredValuesHex, PicklesError> {
    let feature_flags = with_context("feature_flags", group_entries(entries, "feature_flags"))?;
    Ok(PlonkDeferredValuesHex {
        alpha_inner: with_context("plonk.alpha", parse_inner_hex(binding_one(entries, "alpha")?))?,
        beta: with_context("plonk.beta", parse_atom_vector(binding_rest(entries, "beta")?))?,
        gamma: with_context("plonk.gamma", parse_atom_vector(binding_rest(entries, "gamma")?))?,
        zeta_inner: with_context("plonk.zeta", parse_inner_hex(binding_one(entries, "zeta")?))?,
        joint_combiner_inner: match binding_optional_rest(entries, "joint_combiner") {
            Some(rest)
                if !rest.is_empty()
                    && !matches!(peel_singletons(&rest[0]), sexp::Sexp::List(inner) if inner.is_empty()) =>
            {
                Some(with_context("plonk.joint_combiner", parse_inner_hex(&rest[0]))?)
            }
            _ => None,
        },
        feature_flags: with_context("plonk.feature_flags", parse_feature_flags(feature_flags))?,
    })
}

#[cfg(feature = "std")]
fn payload_summary_count(rest: &[sexp::Sexp]) -> usize {
    if rest.is_empty() {
        return 0;
    }

    if rest.len() == 1 {
        match peel_singletons(&rest[0]) {
            sexp::Sexp::List(items) => items.len(),
            sexp::Sexp::Atom(_) => 1,
        }
    } else {
        1
    }
}

#[cfg(feature = "std")]
fn parse_named_section_counts(entries: &[sexp::Sexp]) -> Result<Vec<NamedSectionCount>, PicklesError> {
    entries
        .iter()
        .map(|entry| {
            let items = list_items(entry)?;
            if items.is_empty() {
                return Err(PicklesError::InvalidSexp(
                    "expected named section entry".to_string(),
                ));
            }
            Ok(NamedSectionCount {
                name: atom_owned(&items[0])?,
                count: payload_summary_count(&items[1..]),
            })
        })
        .collect()
}

#[cfg(feature = "std")]
fn parse_inner_proof(entries: &[sexp::Sexp]) -> Result<WrapProofBodyHex, PicklesError> {
    let commitments = group_entries(entries, "commitments")?;
    let evaluations = group_entries(entries, "evaluations")?;
    let bulletproof = group_entries(entries, "bulletproof")?;

    Ok(WrapProofBodyHex {
        commitments: WrapProofCommitmentsHex {
            w_comm: parse_point_vector(binding_rest(commitments, "w_comm")?)?,
            z_comm: parse_point_vector(binding_rest(commitments, "z_comm")?)?,
            t_comm: parse_point_vector(binding_rest(commitments, "t_comm")?)?,
            lookup: binding_optional_rest(commitments, "lookup")
                .map(parse_point_vector)
                .transpose()?,
        },
        evaluations: parse_named_point_sections(evaluations)?,
        ft_eval1: atom_owned(binding_one(entries, "ft_eval1")?)?,
        bulletproof: WrapBulletproofHex {
            lr_pairs: parse_point_pair_vector(binding_rest(bulletproof, "lr")?)?,
            z_1: atom_owned(binding_one(bulletproof, "z_1")?)?,
            z_2: atom_owned(binding_one(bulletproof, "z_2")?)?,
            delta: parse_point(binding_one(bulletproof, "delta")?)?,
            challenge_polynomial_commitment: parse_point(binding_one(
                bulletproof,
                "challenge_polynomial_commitment",
            )?)?,
        },
    })
}

#[cfg(feature = "std")]
fn parse_point_pair(sexp: &sexp::Sexp) -> Result<CurvePointPairHex, PicklesError> {
    let items = list_items(sexp)?;
    if items.len() != 2 {
        return Err(PicklesError::InvalidSexp(format!(
            "expected curve-point pair with 2 entries, got {}",
            items.len()
        )));
    }

    Ok(CurvePointPairHex {
        left: parse_point(&items[0])?,
        right: parse_point(&items[1])?,
    })
}

#[cfg(feature = "std")]
fn parse_point_pair_vector(items: &[sexp::Sexp]) -> Result<Vec<CurvePointPairHex>, PicklesError> {
    let items = if items.len() == 1 {
        match peel_singletons(&items[0]) {
            sexp::Sexp::List(inner) if inner.iter().all(|item| parse_point_pair(item).is_ok()) => inner,
            _ => items,
        }
    } else {
        items
    };

    items.iter().map(parse_point_pair).collect()
}

#[cfg(feature = "std")]
fn parse_named_point_sections(entries: &[sexp::Sexp]) -> Result<Vec<NamedPointSectionHex>, PicklesError> {
    entries
        .iter()
        .map(parse_named_point_section)
        .collect()
}

#[cfg(feature = "std")]
fn parse_named_point_section(entry: &sexp::Sexp) -> Result<NamedPointSectionHex, PicklesError> {
    let items = list_items(entry)?;
    if items.is_empty() {
        return Err(PicklesError::InvalidSexp(
            "expected named point section entry".to_string(),
        ));
    }

    let name = atom_owned(&items[0])?;
    let raw_payload_items = items[1..].iter().map(|item| item.to_string()).collect();
    let points = parse_section_points(&items[1..])?;

    Ok(NamedPointSectionHex {
        name,
        raw_payload_items,
        points,
    })
}

#[cfg(feature = "std")]
fn parse_section_points(items: &[sexp::Sexp]) -> Result<Vec<CurvePointHex>, PicklesError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(points) = parse_point_vector(items) {
        return Ok(points);
    }

    if items.len() == 1 {
        if let Ok(inner) = list_items(&items[0]) {
            if let Ok(points) = parse_point_vector(inner) {
                return Ok(points);
            }
        }
    }

    Ok(Vec::new())
}
