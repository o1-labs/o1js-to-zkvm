//! Verify the JSON → canonical-msgpack → parse round-trip — the host
//! JSON-decodes the OCaml fixture and msgpack-encodes it for the SP1
//! guest, so we need encode/decode symmetry.

#![cfg(feature = "std")]

use o1_pickles_verifier::parse::{
    canonical_proof_repr_msgpack, parse_proof_repr_json, parse_proof_repr_msgpack,
};

const PROOF_REPR_B0: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");

#[test]
fn proof_repr_roundtrips_through_canonical_msgpack() {
    let from_json = parse_proof_repr_json(PROOF_REPR_B0).expect("parse JSON");
    let bytes = canonical_proof_repr_msgpack(PROOF_REPR_B0).expect("canonicalize");
    let from_msgpack = parse_proof_repr_msgpack(&bytes).expect("parse msgpack");

    let a = &from_json.statement;
    let b = &from_msgpack.statement;
    assert_eq!(
        a.proof_state.deferred_values.branch_data.domain_log2,
        b.proof_state.deferred_values.branch_data.domain_log2,
    );
    assert_eq!(
        a.proof_state.sponge_digest_before_evaluations.0,
        b.proof_state.sponge_digest_before_evaluations.0,
    );
    assert_eq!(
        a.messages_for_next_step_proof.app_state,
        b.messages_for_next_step_proof.app_state,
    );
}
