//! Prepared wrap-statement packing for the new Pickles path.
//!
//! The target here is the behavior of
//! `mina-rust/crates/ledger/src/proofs/public_input/prepared_statement.rs`.

use crate::pickles_error::PicklesError;
use crate::pickles_mina_rust::types::{PreparedStatement, WrapVerificationInput};

impl PreparedStatement {
    /// Pack the wrap prepared statement into the final Kimchi public input.
    pub fn to_public_input(
        &self,
        _npublic_input: usize,
    ) -> Result<WrapVerificationInput, PicklesError> {
        Err(PicklesError::LoweringNotImplemented(
            "mina-rust-aligned PreparedStatement::to_public_input is not implemented yet",
        ))
    }
}
