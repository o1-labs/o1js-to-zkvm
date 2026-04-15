//! New Pickles verifier path aligned with `mina-rust` terminology.
//!
//! This namespace is the target for the migration away from the legacy custom
//! `Simple_chain` flow. The intended shape mirrors the conceptual breakdown in
//! `mina-rust`:
//! - app-state field encoding
//! - next-step / next-wrap message preparation
//! - prepared wrap statement packing
//! - padded backend proof materialization
//! - final Kimchi verification
//!
//! The modules here are scaffolding only for now. They define stable names and
//! explicit stub boundaries so the migration can proceed incrementally without
//! disturbing the legacy path.

pub mod app_state;
pub mod messages;
pub mod prepared_statement;
pub mod proof_padding;
pub mod types;
pub mod verify;

pub use app_state::*;
pub use messages::*;
pub use proof_padding::*;
pub use types::*;
pub use verify::*;
