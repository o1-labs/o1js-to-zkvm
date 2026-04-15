//! High-level verification entrypoint for the new Pickles path.
//!
//! The intended end state is to mirror the conceptual flow in
//! `mina-rust/crates/ledger/src/proofs/verification.rs`, but against this
//! crate's external artifact boundary.

use rand::{CryptoRng, RngCore};

use crate::pickles_error::PicklesError;
use crate::pickles_types::PicklesVerifyRequest;

/// Future high-level Pickles verification entrypoint aligned with `mina-rust`.
pub fn verify_pickles_with_mina_rust_model<R: RngCore + CryptoRng>(
    _request: &PicklesVerifyRequest,
    _rng: &mut R,
) -> Result<bool, PicklesError> {
    Err(PicklesError::LoweringNotImplemented(
        "mina-rust-aligned Pickles verification flow is not implemented yet",
    ))
}
