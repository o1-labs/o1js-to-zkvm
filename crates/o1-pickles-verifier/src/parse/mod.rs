//! Read OCaml-emitted proof bundles into the in-Rust domain types.
//!
//! Two input shapes are accepted:
//!
//! * JSON, as `Pickles.Proof.Make(MLMB).to_yojson_full` produces it (with
//!   the host-side `app_state` splice). Std-only, since `serde_json` is
//!   pulled in behind the `std` feature.
//! * msgpack, the canonical shape the host re-encodes for hashing and
//!   ships to the SP1 guest. Available in `no_std` too.
//!
//! In both cases the wire-format types are an implementation detail —
//! callers see only [`ParsedProofRepr`] (statement + prev_evals already
//! lowered into domain types) and [`ParseError`].

extern crate alloc;

use alloc::string::ToString;
#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::statement::WrapStatement;

mod lower;
mod wire;

pub use lower::{ParseError, ParsedPrevEvals};

/// The whole parsed proof bundle. `statement` is the minimal wrap
/// statement; `prev_evals` is the step proof's polynomial evaluations
/// carried alongside it.
pub struct ParsedProofRepr {
    pub statement: WrapStatement,
    pub prev_evals: ParsedPrevEvals,
}

/// Parse a proof bundle from the OCaml-emitted JSON.
#[cfg(feature = "std")]
pub fn parse_proof_repr_json(json: &str) -> Result<ParsedProofRepr, ParseError> {
    let wire: wire::ProofReprWire =
        serde_json::from_str(json).map_err(|e| ParseError::DecodeWire(e.to_string()))?;
    parse_wire(wire)
}

/// Parse a proof bundle from the canonical msgpack shape.
pub fn parse_proof_repr_msgpack(bytes: &[u8]) -> Result<ParsedProofRepr, ParseError> {
    let wire: wire::ProofReprWire =
        rmp_serde::from_slice(bytes).map_err(|e| ParseError::DecodeWire(e.to_string()))?;
    parse_wire(wire)
}

/// Re-encode the OCaml JSON as canonical msgpack — the byte string the
/// SP1 guest hashes for its `statement_digest` commit. This is the
/// host's bridge between the JSON the user holds and the bytes the
/// guest sees.
#[cfg(feature = "std")]
pub fn canonical_proof_repr_msgpack(json: &str) -> Result<Vec<u8>, ParseError> {
    let wire: wire::ProofReprWire =
        serde_json::from_str(json).map_err(|e| ParseError::DecodeWire(e.to_string()))?;
    rmp_serde::to_vec(&wire).map_err(|e| ParseError::EncodeWire(e.to_string()))
}

fn parse_wire(wire: wire::ProofReprWire) -> Result<ParsedProofRepr, ParseError> {
    let statement = lower::parse_wrap_statement(wire.statement)?;
    let prev_evals = lower::parse_prev_evals(wire.prev_evals)?;
    Ok(ParsedProofRepr {
        statement,
        prev_evals,
    })
}
