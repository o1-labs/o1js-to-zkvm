use crate::pickles_error::PicklesError;
use crate::pickles_lowering::lower_simple_chain_request;
use crate::pickles_types::PicklesVerifyRequest;

pub fn verify_simple_chain_pickles<R: rand::RngCore + rand::CryptoRng>(
    request: &PicklesVerifyRequest,
    rng: &mut R,
) -> Result<bool, PicklesError> {
    let lowered = lower_simple_chain_request(request)?;
    Ok(crate::verify_kimchi_proof(
        &lowered.verifier_index,
        &lowered.proof,
        &lowered.public_input,
        rng,
    ))
}
