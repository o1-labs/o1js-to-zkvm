//! Slim wrap-proof verification pipeline for the SP1 guest.
//!
//! 1. Hash the input statement bytes (so the end-verifier can
//!    recognize "this exact serialized statement was attested to").
//! 2. Parse the canonical proof_repr msgpack to recover the
//!    [`WrapStatement`].
//! 3. Build the kimchi public input via
//!    [`kimchi_input::assemble_kimchi_public_input`]. Internally that
//!    runs the only Poseidon that *must* live in the zkVM —
//!    `step_messages_digest_fp`, the binding hop for `app_state`.
//! 4. `kimchi::verifier::verify`.
//! 5. Commit `(valid, app_state, statement_digest)`.
//!
//! Soundness: the wrap circuit constrains every value in its public
//! input internally. So lying about any host-supplied piece (cip, b,
//! perm, zeta_to_*, wrap-side digest) makes the wrap circuit's own
//! `expand_deferred` re-derivation disagree with our packed input,
//! and kimchi rejects.
//!
//! See `docs/ARCHITECTURE.md` for the bigger picture.

extern crate alloc;

use alloc::vec::Vec;

use groupmap::GroupMap;
use mina_poseidon::pasta::FULL_ROUNDS;
use sha2::{Digest as Sha2Digest, Sha256};

use o1_verifier_lib::{load_pallas_verifier_index, PallasProof};
use serde::{Deserialize, Serialize};

use crate::kimchi_input::{assemble_kimchi_public_input, HostPrecomputed, WrapVkCommitments};
use crate::parse::parse_proof_repr_msgpack;
use crate::{Fp, Pallas};

/// What the SP1 guest commits as its public output:
///
/// * `valid`: whether kimchi accepted.
/// * `app_state`: the application circuit's public input as a flat
///   `Vec<Fp>`. Bound into the wrap public input via Poseidon, so a
///   kimchi-accepted run means the guest's `app_state` matches what
///   the wrap circuit was committed against.
/// * `statement_digest`: SHA-256 over the statement msgpack bytes the
///   guest was fed. Lets a holder of the original serialized statement
///   verify "the SP1 proof attests to *my* statement, not just one
///   with matching `app_state`."
///
/// Any decode/verify failure yields `valid=false` with empty
/// `app_state` and a zero `statement_digest`.
///
/// Use [`GuestOutput::to_msgpack`] in the guest to produce the bytes
/// for `sp1_zkvm::io::commit`, and [`GuestOutput::from_msgpack`] on
/// the host (or end-verifier) to decode the bytes back.
#[derive(Serialize, Deserialize)]
pub struct GuestOutput {
    pub valid: bool,
    #[serde(with = "crate::serde_compat::ark")]
    pub app_state: Vec<Fp>,
    pub statement_digest: [u8; 32],
}

impl GuestOutput {
    /// msgpack encoding — the wire format the SP1 guest commits to.
    /// Stable across SP1 SDK versions, since the guest commits the
    /// msgpack bytes rather than relying on SP1's default codec.
    pub fn to_msgpack(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).expect("rmp-encode GuestOutput")
    }

    /// Inverse of [`Self::to_msgpack`].
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }

    fn failed() -> Self {
        Self {
            valid: false,
            app_state: Vec::new(),
            statement_digest: [0u8; 32],
        }
    }
}

/// Constants fixed by the wrap circuit — everything we can precompute
/// once at SP1 build time and bake into the guest.
pub struct WrapVerifySetup<'a> {
    /// 28 single-chunk wrap-VK commitments, in
    /// `index_to_field_elements` order. Constant per circuit.
    pub vk_commitments: &'a WrapVkCommitments,
}

/// Everything the host hands the SP1 guest in one shot.
///
/// `proof_repr_msgpack` is the canonical msgpack of the statement +
/// prev_evals (`parse::canonical_proof_repr_msgpack`'s output). The
/// guest hashes it to produce `statement_digest`, then parses it for
/// the wrap statement. `wrap_proof` is the kimchi `ProverProof` with
/// `prev_challenges` already populated by the host.
/// `host_precomputed` carries the values from `host_precompute` so
/// the guest can skip `expand_deferred` and the wrap-messages
/// Poseidon.
#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    pub proof_repr_msgpack: Vec<u8>,
    pub wrap_proof: PallasProof,
    pub host_precomputed: HostPrecomputed,
}

/// Slim guest pipeline. Consumes host-precomputed values for
/// everything kimchi *binds anyway*, and only does the
/// `app_state`-binding step digest plus the SHA-256 of the input
/// statement bytes.
///
/// `wrap_vi_bytes` and `wrap_srs_bytes` are separate because kimchi's
/// `VerifierIndex` serialization marks `srs` as `#[serde(skip)]` — the
/// SRS is large and shared across many circuits, so it lives in its
/// own blob. [`load_pallas_verifier_index`] stitches them together
/// into `vi.srs`.
///
/// Always returns a [`GuestOutput`]: any decode or kimchi-rejection
/// failure produces `valid: false` with empty `app_state` and zero
/// `statement_digest`.
pub fn verify_wrap_proof_precomputed(
    setup: &WrapVerifySetup<'_>,
    wrap_vi_bytes: &[u8],
    wrap_srs_bytes: &[u8],
    input: GuestInput,
) -> GuestOutput {
    let GuestInput {
        proof_repr_msgpack,
        wrap_proof,
        host_precomputed,
    } = input;

    let statement_digest: [u8; 32] = Sha256::digest(&proof_repr_msgpack).into();

    let parsed = match parse_proof_repr_msgpack(&proof_repr_msgpack) {
        Ok(p) => p,
        Err(_) => return GuestOutput::failed(),
    };
    let stmt = parsed.statement;

    let public_input = assemble_kimchi_public_input(&stmt, setup.vk_commitments, &host_precomputed);

    let wrap_vi = load_pallas_verifier_index(wrap_vi_bytes, wrap_srs_bytes);

    // `Map::setup()` does 1 square root + 2 modular inverses over the
    // Pallas base field — non-trivial in the SP1 zkVM since we don't
    // have a Pasta-curve precompile. Worth baking via build.rs as a
    // follow-up; for now we just call it.
    let group_map = <Pallas as poly_commitment::commitment::CommitmentCurve>::Map::setup();
    let kimchi_result = kimchi::verifier::verify::<
        FULL_ROUNDS,
        Pallas,
        mina_poseidon::sponge::DefaultFqSponge<
            mina_curves::pasta::PallasParameters,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            FULL_ROUNDS,
        >,
        mina_poseidon::sponge::DefaultFrSponge<
            crate::Fq,
            mina_poseidon::constants::PlonkSpongeConstantsKimchi,
            FULL_ROUNDS,
        >,
        poly_commitment::ipa::OpeningProof<Pallas, FULL_ROUNDS>,
    >(&group_map, &wrap_vi, &wrap_proof, &public_input);

    match kimchi_result {
        Ok(()) => GuestOutput {
            valid: true,
            app_state: stmt.messages_for_next_step_proof.app_state,
            statement_digest,
        },
        Err(_) => GuestOutput::failed(),
    }
}
