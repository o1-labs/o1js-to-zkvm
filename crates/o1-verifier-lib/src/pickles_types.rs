//! Core data types for the experimental Mina `Simple_chain` Pickles path.
//!
//! These types intentionally sit above raw Kimchi. They model:
//! - the side-loaded proof / VK bytes exported by Mina
//! - proof metadata Rust can already decode from those bytes
//! - the partial wrap public-input plan Rust can already derive

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use mina_curves::pasta::{Fp, Fq};

use crate::pickles_error::PicklesError;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Opaque Mina side-loaded verification key bytes.
pub struct SideLoadedVkBytes(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
/// Opaque Mina side-loaded proof bytes.
pub struct SideLoadedProofBytes(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
/// Affine curve point rendered as Mina-style hex strings.
pub struct CurvePointHex {
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Polynomial commitment exported by Mina as affine chunk points.
pub struct PolyCommHex {
    pub unshifted: Vec<CurvePointHex>,
    pub shifted: Option<CurvePointHex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// One recursion challenge entry from Mina's backend proof object.
pub struct ExportedRecursionChallenge {
    pub chals_hex: Vec<String>,
    pub comm: PolyCommHex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// One sampled ordered Lagrange-basis commitment from Mina's wrap SRS export.
pub struct ExportedLagrangeCommitmentSample {
    pub index: usize,
    pub commitment: PolyCommHex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Mina-exported ordered SRS identity data used to compare Rust's reconstructed
/// wrap URS against the real Mina URS.
pub struct ExportedSrsIdentity {
    pub urs_h: CurvePointHex,
    pub urs_generators: Option<Vec<CurvePointHex>>,
    pub lagrange_commitments_domain_size: usize,
    pub lagrange_commitments: Vec<PolyCommHex>,
    pub lagrange_commitment_samples: Vec<ExportedLagrangeCommitmentSample>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Bulletproof prechallenge as exported by Mina before field packing.
pub struct BulletproofChallengeHex {
    pub prechallenge_inner: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// The subset of PLONK feature flags surfaced in Mina's deferred values.
pub struct PlonkFeatureFlags {
    pub range_check0: bool,
    pub range_check1: bool,
    pub foreign_field_add: bool,
    pub foreign_field_mul: bool,
    pub xor: bool,
    pub rot: bool,
    pub lookup: bool,
    pub runtime_tables: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Deferred PLONK challenges exactly as parsed from the side-loaded proof.
pub struct PlonkDeferredValuesHex {
    pub alpha_inner: Vec<String>,
    pub beta: Vec<String>,
    pub gamma: Vec<String>,
    pub zeta_inner: Vec<String>,
    pub joint_combiner_inner: Option<Vec<String>>,
    pub feature_flags: PlonkFeatureFlags,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Named section counts used by the inspector when only section cardinality is known.
pub struct NamedSectionCount {
    pub name: String,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// One pair of zeta / zeta*omega evaluations from `prev_evals`.
pub struct FieldEvalPairHex {
    pub zeta: Vec<String>,
    pub zeta_omega: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A named `prev_evals` section from the Pickles statement/deferred layer.
///
/// This is *not* the same object as the raw wrap proof's backend
/// `ProofEvaluations`. Mina and `mina-rust` use these deferred evaluations when
/// recomputing transcript/deferred values (`xi`, `b`, `perm`, etc.).
pub struct NamedFieldEvalSectionHex {
    pub name: String,
    pub evaluations: Vec<FieldEvalPairHex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Pair of curve points used in the bulletproof LR rounds.
pub struct CurvePointPairHex {
    pub left: CurvePointHex,
    pub right: CurvePointHex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A named evaluation section from the inner wrap proof's backend opening data.
///
/// These values correspond to the Kimchi wrap proof's `ProofEvaluations`. They
/// are distinct from the Pickles statement's deferred `prev_evals`.
pub struct NamedPointSectionHex {
    pub name: String,
    pub raw_payload_items: Vec<String>,
    pub points: Vec<CurvePointHex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Commitments carried by the inner wrap proof body.
pub struct WrapProofCommitmentsHex {
    pub w_comm: Vec<CurvePointHex>,
    pub z_comm: Vec<CurvePointHex>,
    pub t_comm: Vec<CurvePointHex>,
    pub lookup: Option<Vec<CurvePointHex>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Bulletproof opening data from the inner wrap proof body.
pub struct WrapBulletproofHex {
    pub lr_pairs: Vec<CurvePointPairHex>,
    pub z_1: String,
    pub z_2: String,
    pub delta: CurvePointHex,
    pub challenge_polynomial_commitment: CurvePointHex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// The verifier-relevant inner Kimchi wrap proof payload, still in hex/string form.
pub struct WrapProofBodyHex {
    pub commitments: WrapProofCommitmentsHex,
    pub evaluations: Vec<NamedPointSectionHex>,
    pub ft_eval1: String,
    pub bulletproof: WrapBulletproofHex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Structured metadata Rust can already decode from a Mina side-loaded proof.
///
/// This is not yet enough to verify the proof. It is the currently decoded
/// frontier used by the inspector and the public-input planning code.
pub struct SideLoadedProofMetadata {
    pub proofs_verified: u8,
    pub domain_log2: u8,
    pub plonk: PlonkDeferredValuesHex,
    pub deferred_bulletproof_challenges: Vec<BulletproofChallengeHex>,
    pub sponge_digest_before_evaluations: Vec<String>,
    pub wrap_challenge_polynomial_commitment: CurvePointHex,
    pub wrap_old_bulletproof_challenges: Vec<Vec<BulletproofChallengeHex>>,
    pub next_step_challenge_polynomial_commitments: Vec<CurvePointHex>,
    pub next_step_old_bulletproof_challenges: Vec<Vec<BulletproofChallengeHex>>,
    /// Public-input fields attached to the Pickles statement's deferred
    /// `prev_evals` object, not the raw wrap proof's backend `public` evals.
    pub prev_evals_public_input: Vec<String>,
    /// Deferred `prev_evals` used by Pickles scalar/transcript recomputation.
    pub prev_evals: Vec<NamedFieldEvalSectionHex>,
    pub prev_evals_sections: Vec<NamedSectionCount>,
    /// `ft_eval1` from the Pickles statement/deferred view.
    pub ft_eval1: String,
    /// Raw wrap proof body and backend opening data.
    pub inner_proof: WrapProofBodyHex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// One ordered slot in the packed wrap public-input vector.
///
/// `value_hex` is absent when the slot is known conceptually but cannot yet be
/// derived from the current Mina exporter boundary.
pub struct WrapPublicInputFieldPlan {
    pub index: usize,
    pub name: String,
    pub value_hex: Option<String>,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Ordered plan for the wrap public-input vector expected by Mina's wrap verifier.
///
/// This is a planning artifact, not the final `Vec<Fp>` used by Kimchi.
pub struct WrapPublicInputPlan {
    pub total_fields: usize,
    pub exact_public_input_available: bool,
    pub elided_constant_segments: Vec<String>,
    pub fields: Vec<WrapPublicInputFieldPlan>,
}

#[derive(Clone, Debug, PartialEq)]
/// Exact wrap public-input vector exported by Mina as canonical field hex strings.
pub struct ExportedWrapPublicInput {
    pub hex_fields: Vec<String>,
    pub fields: Vec<Fq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Exact oracle values exported by Mina for wrap public-input slots Rust does not
/// yet derive from first principles.
pub struct ExportedWrapOracleFields {
    pub combined_inner_product_field_hex: String,
    pub messages_for_next_step_proof_field_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Small probe of Mina's final backend wrap-proof evaluations.
pub struct ExportedBackendEvalsProbe {
    pub witness_columns: Vec<FieldEvalPairHex>,
    pub w0: FieldEvalPairHex,
    pub z: FieldEvalPairHex,
    pub permutation_columns: Vec<FieldEvalPairHex>,
    pub s0: FieldEvalPairHex,
    pub coefficients: Vec<FieldEvalPairHex>,
    pub coeff0: FieldEvalPairHex,
    pub generic_selector: FieldEvalPairHex,
    pub poseidon_selector: FieldEvalPairHex,
    pub complete_add_selector: FieldEvalPairHex,
    pub mul_selector: FieldEvalPairHex,
    pub emul_selector: FieldEvalPairHex,
    pub endomul_scalar_selector: FieldEvalPairHex,
    pub range_check0_selector: Option<FieldEvalPairHex>,
    pub range_check1_selector: Option<FieldEvalPairHex>,
    pub foreign_field_add_selector: Option<FieldEvalPairHex>,
    pub foreign_field_mul_selector: Option<FieldEvalPairHex>,
    pub xor_selector: Option<FieldEvalPairHex>,
    pub rot_selector: Option<FieldEvalPairHex>,
    pub lookup_aggregation: Option<FieldEvalPairHex>,
    pub lookup_table: Option<FieldEvalPairHex>,
    pub lookup_sorted: Vec<Option<FieldEvalPairHex>>,
    pub runtime_lookup_table: Option<FieldEvalPairHex>,
    pub runtime_lookup_table_selector: Option<FieldEvalPairHex>,
    pub xor_lookup_selector: Option<FieldEvalPairHex>,
    pub lookup_gate_lookup_selector: Option<FieldEvalPairHex>,
    pub range_check_lookup_selector: Option<FieldEvalPairHex>,
    pub foreign_field_mul_lookup_selector: Option<FieldEvalPairHex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw wrap verifier artifacts exported directly by Mina in Kimchi-compatible
/// JSON form.
pub struct ExportedRawWrapVerifier {
    pub verifier_index_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw wrap proof artifact exported directly by Mina in Kimchi-compatible JSON
/// form.
pub struct ExportedRawWrapProof {
    pub proof_json: String,
}

#[derive(Clone, Debug, PartialEq)]
/// The current Rust model of the `Simple_chain` application statement.
pub struct SimpleChainStatement {
    pub value: Fp,
}

impl SimpleChainStatement {
    /// Build the current `Simple_chain` statement from exported field elements.
    pub fn from_fields(fields: &[Fp]) -> Result<Self, PicklesError> {
        if fields.len() != 1 {
            return Err(PicklesError::UnsupportedStatementShape {
                expected: 1,
                actual: fields.len(),
            });
        }

        Ok(Self { value: fields[0] })
    }

    /// Re-encode the application statement as field elements.
    pub fn to_fields(&self) -> Vec<Fp> {
        vec![self.value]
    }
}

#[derive(Clone, Debug, PartialEq)]
/// One named fixture from the Mina exporter.
pub struct SimpleChainFixture {
    pub name: String,
    pub statement: SimpleChainStatement,
    pub proof: SideLoadedProofBytes,
    pub exported_wrap_public_input: Option<ExportedWrapPublicInput>,
    pub exported_wrap_oracle_fields: Option<ExportedWrapOracleFields>,
    pub exported_raw_wrap_proof: Option<ExportedRawWrapProof>,
    pub exported_backend_prev_challenges: Option<Vec<ExportedRecursionChallenge>>,
    pub exported_backend_evals_probe: Option<ExportedBackendEvalsProbe>,
}

#[derive(Clone, Debug, PartialEq)]
/// Parsed Mina exporter bundle for `Simple_chain`.
pub struct SimpleChainFixtureBundle {
    pub verification_key: SideLoadedVkBytes,
    pub exported_raw_wrap_verifier: Option<ExportedRawWrapVerifier>,
    pub exported_srs_identity: Option<ExportedSrsIdentity>,
    pub fixtures: Vec<SimpleChainFixture>,
}

impl SimpleChainFixtureBundle {
    /// Find a named fixture by bundle-local name.
    pub fn fixture(&self, name: &str) -> Option<&SimpleChainFixture> {
        self.fixtures.iter().find(|fixture| fixture.name == name)
    }

    /// Materialize a verifier request from a named fixture.
    pub fn request_for_fixture(&self, name: &str) -> Result<PicklesVerifyRequest, PicklesError> {
        let fixture = self
            .fixture(name)
            .ok_or_else(|| PicklesError::MissingFixture(name.into()))?;

        Ok(PicklesVerifyRequest {
            vk: self.verification_key.clone(),
            proof: fixture.proof.clone(),
            statement: fixture.statement.clone(),
            exported_wrap_public_input: fixture.exported_wrap_public_input.clone(),
            exported_wrap_oracle_fields: fixture.exported_wrap_oracle_fields.clone(),
            exported_raw_wrap_verifier: self.exported_raw_wrap_verifier.clone(),
            exported_raw_wrap_proof: fixture.exported_raw_wrap_proof.clone(),
            exported_backend_prev_challenges: fixture.exported_backend_prev_challenges.clone(),
            exported_backend_evals_probe: fixture.exported_backend_evals_probe.clone(),
            exported_srs_identity: self.exported_srs_identity.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
/// High-level request shape for the future Pickles verifier path.
pub struct PicklesVerifyRequest {
    pub vk: SideLoadedVkBytes,
    pub proof: SideLoadedProofBytes,
    pub statement: SimpleChainStatement,
    pub exported_wrap_public_input: Option<ExportedWrapPublicInput>,
    pub exported_wrap_oracle_fields: Option<ExportedWrapOracleFields>,
    pub exported_raw_wrap_verifier: Option<ExportedRawWrapVerifier>,
    pub exported_raw_wrap_proof: Option<ExportedRawWrapProof>,
    pub exported_backend_prev_challenges: Option<Vec<ExportedRecursionChallenge>>,
    pub exported_backend_evals_probe: Option<ExportedBackendEvalsProbe>,
    pub exported_srs_identity: Option<ExportedSrsIdentity>,
}
