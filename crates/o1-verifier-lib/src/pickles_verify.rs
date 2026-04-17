//! High-level Pickles verification entrypoints.
//!
//! The intended boundary here sits above raw Kimchi:
//! 1. expand deferred values
//! 2. replay the Fiat-Shamir transcript
//! 3. materialize the wrap proof's recursion accumulator
//! 4. reconstruct the wrap public input
//! 5. call the wrap-side Kimchi verifier
//!
//! The legacy `Simple_chain` path is still available for comparison, but the
//! main verifier entrypoint now routes through the newer `mina-rust`-aligned
//! lowering flow.

use crate::pickles_error::PicklesError;
use crate::pickles_mina_rust::verify_pickles_with_mina_rust_model;
use crate::pickles_types::PicklesVerifyRequest;

/// Attempt to verify a Mina `Simple_chain` Pickles proof.
///
/// This entrypoint now goes through the `mina-rust`-aligned Pickles lowering
/// flow before handing off to the wrap-side Kimchi verifier.
pub fn verify_simple_chain_pickles<R: rand::RngCore + rand::CryptoRng>(
    request: &PicklesVerifyRequest,
    rng: &mut R,
) -> Result<bool, PicklesError> {
    verify_pickles_with_mina_rust_model(request, rng)
}
