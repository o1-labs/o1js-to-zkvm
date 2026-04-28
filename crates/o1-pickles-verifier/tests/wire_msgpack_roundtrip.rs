//! Verify that `ProofReprWire` round-trips through rmp-serde — the host
//! is going to JSON-decode the OCaml fixture and msgpack-encode it for
//! the SP1 guest, so we need encode/decode symmetry.
//!
//! Loose form for the JSON-quirky fields (`proofs_verified` array tag,
//! `domain_log2` single-char string) is preserved on both sides via
//! the matching `serialize_with`/`deserialize_with` adapters.

#![cfg(feature = "std")]

use o1_pickles_verifier::parse::parse_wrap_statement;
use o1_pickles_verifier::wire::ProofReprWire;

const PROOF_REPR_B0: &str = include_str!("../../../fixtures/simple_chain_proof_repr_b0.json");

#[test]
fn proof_repr_wire_roundtrips_through_rmp_serde() {
    let from_json: ProofReprWire =
        serde_json::from_str(PROOF_REPR_B0).expect("parse JSON proof_repr");
    let bytes = rmp_serde::to_vec(&from_json).expect("rmp encode");
    let from_msgpack: ProofReprWire = rmp_serde::from_slice(&bytes).expect("rmp decode");

    // Lower both via parse_wrap_statement — domain types implement no
    // PartialEq, so we compare a few selected fields directly through
    // the lowered shape.
    let s_json = parse_wrap_statement(from_json.statement).expect("lower from-JSON");
    let s_rmp = parse_wrap_statement(from_msgpack.statement).expect("lower from-msgpack");

    assert_eq!(
        s_json.proof_state.deferred_values.branch_data.domain_log2,
        s_rmp.proof_state.deferred_values.branch_data.domain_log2
    );
    assert_eq!(
        s_json.proof_state.sponge_digest_before_evaluations.0,
        s_rmp.proof_state.sponge_digest_before_evaluations.0
    );
    assert_eq!(
        s_json.messages_for_next_step_proof.app_state.len(),
        s_rmp.messages_for_next_step_proof.app_state.len()
    );
    assert_eq!(
        s_json.messages_for_next_step_proof.app_state,
        s_rmp.messages_for_next_step_proof.app_state
    );
}
