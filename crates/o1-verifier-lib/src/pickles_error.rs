//! Error types for the experimental Pickles ingestion and lowering path.
//!
//! This module covers only the new Mina-side-loaded boundary. The old raw-Kimchi
//! verifier path still uses direct panics/assertions in a few places.

extern crate alloc;

use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PicklesError {
    /// The exported fixture bundle could not be decoded as JSON.
    InvalidJson(String),
    /// A base64-encoded proof or verification key field was malformed.
    InvalidBase64(&'static str),
    /// A string that should represent a Pasta field element was invalid.
    InvalidFieldElement(String),
    /// The requested named fixture was not present in the parsed bundle.
    MissingFixture(String),
    /// The side-loaded proof bytes were not valid UTF-8 text.
    InvalidProofText(&'static str),
    /// The side-loaded proof text did not match the expected S-expression shape.
    InvalidSexp(String),
    /// A required field was missing while traversing the decoded proof tree.
    MissingProofField(&'static str),
    /// The exported application statement shape does not match the current Rust model.
    UnsupportedStatementShape { expected: usize, actual: usize },
    /// Lowering reached a known missing verifier-construction step.
    LoweringNotImplemented(&'static str),
}

impl fmt::Display for PicklesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(err) => write!(f, "invalid JSON: {err}"),
            Self::InvalidBase64(field) => write!(f, "invalid base64 in {field}"),
            Self::InvalidFieldElement(value) => {
                write!(f, "invalid field element: {value}")
            }
            Self::MissingFixture(name) => write!(f, "missing fixture: {name}"),
            Self::InvalidProofText(field) => write!(f, "invalid UTF-8 in {field}"),
            Self::InvalidSexp(err) => write!(f, "invalid S-expression: {err}"),
            Self::MissingProofField(field) => write!(f, "missing proof field: {field}"),
            Self::UnsupportedStatementShape { expected, actual } => {
                write!(
                    f,
                    "unsupported statement shape: expected {expected} fields, got {actual}"
                )
            }
            Self::LoweringNotImplemented(reason) => write!(f, "{reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PicklesError {}
