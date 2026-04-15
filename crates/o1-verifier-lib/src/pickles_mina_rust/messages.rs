//! Next-step and next-wrap message shapes for the new Pickles path.
//!
//! These correspond to the concepts in
//! `mina-rust/crates/ledger/src/proofs/public_input/messages.rs`.

extern crate alloc;

use alloc::vec::Vec;

use mina_curves::pasta::{Fp, Fq};

use crate::pickles_error::PicklesError;
use crate::pickles_mina_rust::app_state::AppState;
use crate::pickles_types::CurvePointHex;

#[derive(Clone, Debug, PartialEq)]
pub struct MessagesForNextWrapProof {
    pub challenge_polynomial_commitment: CurvePointHex,
    pub old_bulletproof_challenges: Vec<[Fq; 15]>,
}

impl MessagesForNextWrapProof {
    /// Placeholder for the `mina-rust`-aligned wrap-message hash.
    pub fn hash(&self) -> Result<[u64; 4], PicklesError> {
        Err(PicklesError::LoweringNotImplemented(
            "mina-rust-aligned hash_messages_for_next_wrap_proof is not implemented yet",
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MessagesForNextStepProof<A: AppState> {
    pub app_state: A,
    pub challenge_polynomial_commitments: Vec<CurvePointHex>,
    pub old_bulletproof_challenges: Vec<[Fp; 16]>,
}

impl<A: AppState> MessagesForNextStepProof<A> {
    /// Placeholder for the `mina-rust`-aligned step-message hash.
    pub fn hash(&self) -> Result<[u64; 4], PicklesError> {
        Err(PicklesError::LoweringNotImplemented(
            "mina-rust-aligned hash_messages_for_next_step_proof is not implemented yet",
        ))
    }
}
