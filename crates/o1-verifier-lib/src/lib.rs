extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::curve::KimchiCurve;
use kimchi::linearization::expr_linearization;
use kimchi::proof::ProverProof;
use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Pallas, PallasParameters, Vesta};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::FULL_ROUNDS;
use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use poly_commitment::ipa::{OpeningProof, SRS};
use serde::de::DeserializeOwned;
use serde_with::serde_as;

/// `serde_with` adapter that reads ark types from compressed bytes
/// while skipping the curve-membership check.
///
/// `o1_utils::serialization::SerdeAs` uses `serialize_compressed` plus
/// `deserialize_compressed` (checked); `SerdeAsUnchecked` uses
/// `serialize_uncompressed` plus `deserialize_uncompressed_unchecked`.
/// They're not byte-compatible with each other. kimchi-stubs writes
/// SRS bytes using `SerdeAs` (compressed), so to read them while
/// skipping checks we need a "compressed and unchecked" variant,
/// which `o1_utils` doesn't ship. Hence this local adapter.
pub struct SerdeAsCompressedUnchecked;

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAsCompressedUnchecked
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        T::deserialize_compressed_unchecked(&bytes[..]).map_err(serde::de::Error::custom)
    }
}

/// On-disk shape of `SRS<G>` as `kimchi-stubs`' `srs_write` emits it
/// (the "prod" path: `g`, `h`, no `lagrange_bases`), with a
/// compressed-and-unchecked deserializer so we skip the per-point
/// `is_on_curve` check that `SerdeAs` runs by default.
///
/// Sound only for trusted SRS bytes (e.g. a baked, known-good fixture).
/// On Pallas with cofactor 1, `is_on_curve` is the only meaningful
/// check — `is_in_correct_subgroup_assuming_on_curve` is a no-op — so
/// skipping it saves ~5 Fq ops per generator (~65k generators per
/// SRS), which is real cycle savings inside the SP1 zkVM.
#[serde_as]
#[derive(serde::Deserialize)]
#[serde(bound = "G: CanonicalDeserialize + CanonicalSerialize")]
pub struct UncheckedSrs<G> {
    #[serde_as(as = "Vec<SerdeAsCompressedUnchecked>")]
    pub g: Vec<G>,
    #[serde_as(as = "SerdeAsCompressedUnchecked")]
    pub h: G,
}

impl<G> From<UncheckedSrs<G>> for SRS<G> {
    fn from(u: UncheckedSrs<G>) -> Self {
        SRS {
            g: u.g,
            h: u.h,
            lagrange_bases: Default::default(),
        }
    }
}

pub type SpongeParams = PlonkSpongeConstantsKimchi;

pub type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams, FULL_ROUNDS>;
pub type PallasScalarSponge = DefaultFrSponge<mina_curves::pasta::Fq, SpongeParams, FULL_ROUNDS>;
pub type PallasVerifierIndex = VerifierIndex<FULL_ROUNDS, Pallas, SRS<Pallas>>;
pub type PallasProof = ProverProof<Pallas, OpeningProof<Pallas, FULL_ROUNDS>, FULL_ROUNDS>;

/// Reconstruct FeatureFlags from the VerifierIndex's optional commitment
/// fields. Works for any curve.
pub fn feature_flags_from_vi<G>(vi: &VerifierIndex<FULL_ROUNDS, G, SRS<G>>) -> FeatureFlags
where
    G: KimchiCurve<FULL_ROUNDS>,
{
    let lookup_features = vi
        .lookup_index
        .as_ref()
        .map(|li| li.lookup_info.features)
        .unwrap_or_default();

    FeatureFlags {
        range_check0: vi.range_check0_comm.is_some(),
        range_check1: vi.range_check1_comm.is_some(),
        foreign_field_add: vi.foreign_field_add_comm.is_some(),
        foreign_field_mul: vi.foreign_field_mul_comm.is_some(),
        xor: vi.xor_comm.is_some(),
        rot: vi.rot_comm.is_some(),
        lookup_features,
    }
}

/// Deserialize a VerifierIndex + SRS from msgpack bytes and reconstruct every
/// `#[serde(skip)]` field needed for verification. Generic in the curve.
///
/// The SRS is read via [`UncheckedSrs`], a local mirror of `SRS<G>`'s
/// on-disk shape (`g`, `h`) but using `o1_utils::serialization::SerdeAsUnchecked`
/// so the per-point `is_on_curve` check that `SerdeAs` runs by default
/// is skipped. Sound only when the SRS bytes come from a trusted source
/// (a baked, known-good fixture). Saves on the order of ~5 Fq ops ×
/// 65k generators per call.
pub fn load_verifier_index_generic<G>(
    vi_bytes: &[u8],
    srs_bytes: &[u8],
) -> VerifierIndex<FULL_ROUNDS, G, SRS<G>>
where
    G: KimchiCurve<FULL_ROUNDS>,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    SRS<G>: DeserializeOwned,
    VerifierIndex<FULL_ROUNDS, G, SRS<G>>: DeserializeOwned,
{
    let mut vi: VerifierIndex<FULL_ROUNDS, G, SRS<G>> =
        rmp_serde::from_slice(vi_bytes).expect("failed to deserialize VerifierIndex");
    let unchecked: UncheckedSrs<G> =
        rmp_serde::from_slice(srs_bytes).expect("failed to deserialize SRS");
    vi.srs = Arc::new(unchecked.into());

    let (_, endo) = G::endos();
    vi.endo = *endo;
    let feature_flags = feature_flags_from_vi(&vi);
    let (linearization, powers_of_alpha) =
        expr_linearization::<G::ScalarField>(Some(&feature_flags), true);
    vi.linearization = linearization;
    vi.powers_of_alpha = powers_of_alpha;

    vi
}

pub fn load_pallas_verifier_index(vi_bytes: &[u8], srs_bytes: &[u8]) -> PallasVerifierIndex {
    let mut vi = load_verifier_index_generic::<Pallas>(vi_bytes, srs_bytes);
    // OCaml's `caml_pasta_fq_plonk_verifier_index_read` (kimchi-stubs
    // pasta_fq_plonk_verifier_index.rs:182) sets `vi.endo` from
    // `endos::<Vesta>().0` (Vesta's BaseField cube root in Fq),
    // NOT from `endos::<Pallas>().1` (Pallas's ScalarField endo, also Fq).
    // For Pasta these differ when the orientation check picks the squared
    // cube root. The kimchi verifier expects OCaml's choice.
    let (vesta_base_endo, _) = poly_commitment::ipa::endos::<Vesta>();
    vi.endo = vesta_base_endo;
    vi
}
