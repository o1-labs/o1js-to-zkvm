extern crate alloc;

use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PicklesError {
    InvalidJson(String),
    InvalidBase64(&'static str),
    InvalidFieldElement(String),
    MissingFixture(String),
    UnsupportedStatementShape { expected: usize, actual: usize },
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
