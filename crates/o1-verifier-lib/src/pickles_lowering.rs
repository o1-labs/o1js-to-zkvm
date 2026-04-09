extern crate alloc;

use alloc::vec::Vec;

use mina_curves::pasta::Fp;

use crate::pickles_error::PicklesError;
use crate::pickles_types::PicklesVerifyRequest;
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
        "Pickles side-loaded proof/VK lowering into wrap-level Kimchi artifacts is not implemented yet",
    ))
}
