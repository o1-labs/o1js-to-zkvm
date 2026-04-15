//! Backend proof materialization for the new Pickles path.
//!
//! The target here is the role of
//! `mina-rust/crates/ledger/src/proofs/prover.rs::make_padded_proof_from_p2p`.

use crate::pickles_error::PicklesError;
use crate::pickles_types::PicklesVerifyRequest;
use crate::PallasProof;

/// Materialize a verification-ready wrap proof from Mina-side artifacts.
pub fn make_padded_wrap_proof_from_request(
    _request: &PicklesVerifyRequest,
) -> Result<PallasProof, PicklesError> {
    Err(PicklesError::LoweringNotImplemented(
        "mina-rust-aligned make_padded_wrap_proof_from_request is not implemented yet",
    ))
}
