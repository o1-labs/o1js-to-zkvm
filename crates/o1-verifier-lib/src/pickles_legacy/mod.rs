//! Legacy custom Pickles scaffolding kept for comparison during migration.
//!
//! This namespace exists so the current `Simple_chain`-oriented flow can stay
//! available while a new verifier path is rebuilt around `mina-rust`
//! semantics. New Pickles work should not expand this area unless it is
//! explicitly maintaining or validating the legacy behavior.

pub mod simple_chain;
