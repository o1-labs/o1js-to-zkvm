//! Core data shapes for the `mina-rust`-aligned Pickles path.
//!
//! These names intentionally follow the structure in
//! `mina-rust/crates/ledger/src/proofs/public_input/prepared_statement.rs`.

extern crate alloc;

use alloc::vec::Vec;

use mina_curves::pasta::{Fp, Fq};

use crate::pickles_types::{CurvePointHex, PlonkFeatureFlags};
use crate::{PallasProof, PallasVerifierIndex};

/// Minimal local shifted-value wrapper used by prepared-statement packing.
#[derive(Clone, Debug, PartialEq)]
pub struct ShiftedValue<F> {
    pub shifted: F,
}

impl<F> ShiftedValue<F> {
    /// Wrap a value that has already been moved into Pickles' shifted
    /// representation.
    pub fn new(shifted: F) -> Self {
        Self { shifted }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Plonk {
    pub alpha: [u64; 2],
    pub beta: [u64; 2],
    pub gamma: [u64; 2],
    pub zeta: [u64; 2],
    pub zeta_to_srs_length: ShiftedValue<Fp>,
    pub zeta_to_domain_size: ShiftedValue<Fp>,
    pub perm: ShiftedValue<Fp>,
    pub lookup: Option<[u64; 2]>,
    pub feature_flags: PlonkFeatureFlags,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlogPlonkVerificationKeyEvals {
    pub sigma: [CurvePointHex; 7],
    pub coefficients: [CurvePointHex; 15],
    pub generic: CurvePointHex,
    pub psm: CurvePointHex,
    pub complete_add: CurvePointHex,
    pub mul: CurvePointHex,
    pub emul: CurvePointHex,
    pub endomul_scalar: CurvePointHex,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BranchData {
    pub proofs_verified: u8,
    pub domain_log2: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeferredValues {
    pub plonk: Plonk,
    pub combined_inner_product: ShiftedValue<Fp>,
    pub b: ShiftedValue<Fp>,
    pub xi: [u64; 2],
    pub bulletproof_challenges: Vec<Fp>,
    pub branch_data: BranchData,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProofState {
    pub deferred_values: DeferredValues,
    pub sponge_digest_before_evaluations: [u64; 4],
    pub messages_for_next_wrap_proof: [u64; 4],
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedStatement {
    pub proof_state: ProofState,
    pub messages_for_next_step_proof: [u64; 4],
}

/// Verification-ready wrap input once all `mina-rust`-aligned lowering is done.
#[derive(Clone, Debug, PartialEq)]
pub struct WrapVerificationInput {
    pub public_input: Vec<Fq>,
}

/// Fully lowered wrap-verification bundle for the new `mina-rust`-aligned path.
#[derive(Clone, Debug)]
pub struct LoweredWrapVerification {
    pub verifier_index: PallasVerifierIndex,
    pub proof: PallasProof,
    pub public_input: Vec<Fq>,
}
