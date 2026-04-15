//! App-state abstraction for the `mina-rust`-aligned Pickles path.
//!
//! The legacy path hardcodes `SimpleChainStatement { value: Fp }`. The new path
//! is intended to match `mina-rust` more closely, where verification is generic
//! over an application statement that can be encoded as Pasta `Fp` elements.

extern crate alloc;

use alloc::vec::Vec;

use mina_curves::pasta::Fp;

use crate::pickles_error::PicklesError;

/// Application statement field encoding for the new Pickles verifier path.
///
/// This intentionally mirrors the role played by `AppState: ToFieldElements<Fp>`
/// in `mina-rust`, but keeps a local trait so we can evolve the dependency story
/// independently.
pub trait AppState {
    fn to_field_elements(&self) -> Result<Vec<Fp>, PicklesError>;
}

/// Minimal app-state wrapper for callers that already hold field elements.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldVectorAppState {
    pub fields: Vec<Fp>,
}

impl AppState for FieldVectorAppState {
    fn to_field_elements(&self) -> Result<Vec<Fp>, PicklesError> {
        Ok(self.fields.clone())
    }
}
