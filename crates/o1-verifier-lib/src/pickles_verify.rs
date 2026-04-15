//! Thin orchestration layer for the future Pickles verifier path.
//!
//! Today this module is mostly a placeholder: it routes through the lowering
//! layer and then into the wrap-side raw-Kimchi verifier, but the lowering step
//! is still incomplete for real Mina Pickles proofs.

use crate::pickles_error::PicklesError;
use crate::pickles_lowering::lower_simple_chain_request;
use crate::pickles_types::PicklesVerifyRequest;

/// Attempt to verify a Mina `Simple_chain` Pickles proof.
///
/// This API represents the intended high-level verifier boundary, even though
/// the current lowering step still returns `LoweringNotImplemented`.
pub fn verify_simple_chain_pickles<R: rand::RngCore + rand::CryptoRng>(
    request: &PicklesVerifyRequest,
    rng: &mut R,
) -> Result<bool, PicklesError> {
    let lowered = lower_simple_chain_request(request)?;
    Ok(crate::verify_wrap_kimchi_proof(
        &lowered.verifier_index,
        &lowered.proof,
        &lowered.public_input,
        rng,
    ))
}
