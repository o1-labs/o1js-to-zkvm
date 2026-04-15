//! Legacy custom `Simple_chain` Pickles path.
//!
//! This module is a compatibility namespace over the existing experimental
//! implementation. It keeps the current exporter-driven fixture parsing,
//! side-loaded proof inspection, raw-wrap lowering, and verification entrypoint
//! grouped under an explicit legacy path while the new `mina-rust`-aligned
//! implementation is introduced alongside it.

pub use crate::pickles_error::PicklesError;
pub use crate::pickles_lowering::{
    lower_simple_chain_metadata, lower_simple_chain_public_input_plan,
    lower_simple_chain_raw_wrap_artifacts, lower_simple_chain_request, LoweredRawWrapArtifacts,
    LoweredWrapInstance,
};
#[cfg(feature = "std")]
pub use crate::pickles_parse::{parse_simple_chain_bundle, parse_simple_chain_request};
pub use crate::pickles_types::{
    BulletproofChallengeHex, CurvePointHex, CurvePointPairHex, ExportedRawWrapProof,
    ExportedRawWrapVerifier, ExportedWrapOracleFields, ExportedWrapPublicInput,
    FieldEvalPairHex, NamedFieldEvalSectionHex, NamedPointSectionHex, NamedSectionCount,
    PicklesVerifyRequest, PlonkDeferredValuesHex, PlonkFeatureFlags, SideLoadedProofBytes,
    SideLoadedProofMetadata, SideLoadedVkBytes, SimpleChainFixture, SimpleChainFixtureBundle,
    SimpleChainStatement, WrapBulletproofHex, WrapProofBodyHex, WrapProofCommitmentsHex,
    WrapPublicInputFieldPlan, WrapPublicInputPlan,
};
pub use crate::pickles_verify::verify_simple_chain_pickles;
