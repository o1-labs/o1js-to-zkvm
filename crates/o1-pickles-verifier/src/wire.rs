//! Wire-format types for the JSON the OCaml `simple_chain.exe` dumps via
//! `Pickles.Proof.Make(MLMB).to_yojson_full` (with a small splice on the
//! OCaml side to replace the `null` `app_state` with the real decimal-string
//! array — see `simple_chain.ml:inject_app_state`).
//!
//! Every type here maps directly to the JSON shape pickles' ppx-derived
//! `to_yojson` emits, so `#[derive(Deserialize)]` parses without custom
//! adapter code except where the OCaml format is inherently quirky (variant
//! tags as `[tag]`, char as a one-character string, u64 limbs as signed
//! `i64` because OCaml JSON has no unsigned ints).
//!
//! The module is compiled in `no_std` with `alloc` — only the derives and
//! `Vec`/`String` from `alloc`. Actually invoking `serde_json::from_str`
//! requires the `std` feature.

use alloc::string::String;
use alloc::vec::Vec;

use serde::de::{self, Deserializer};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize, Serializer};

/// The top-level JSON dumped by `Pickles.Proof.Make(Nat.N1).to_yojson_full`,
/// with the `app_state` splice applied on the OCaml side. We consume
/// `statement` and `prev_evals`; `proof` (the inner wrap kimchi proof) is
/// still parsed opaquely until Stage 3 needs it.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProofReprWire {
    pub statement: StatementWire,
    pub prev_evals: PrevEvalsWire,
    #[serde(default, skip)]
    pub proof: (),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatementWire {
    pub proof_state: ProofStateWire,
    pub messages_for_next_step_proof: MessagesForNextStepProofWire,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofStateWire {
    pub deferred_values: DeferredValuesWire,
    /// 256-bit `Digest.Constant.t`, serialized as four signed int64 limbs.
    /// Reinterpret as `[u64; 4]` when lowering.
    pub sponge_digest_before_evaluations: [i64; 4],
    pub messages_for_next_wrap_proof: MessagesForNextWrapProofWire,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeferredValuesWire {
    pub plonk: PlonkMinimalWire,
    /// `Step_bp_vec` = Tick rounds = 16 entries.
    pub bulletproof_challenges: Vec<BulletproofChallengeWire>,
    pub branch_data: BranchDataWire,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PlonkMinimalWire {
    pub alpha: ScalarChallengeWire,
    /// Plain `Challenge.Constant.t` — two signed-int64 limbs.
    pub beta: [i64; 2],
    pub gamma: [i64; 2],
    pub zeta: ScalarChallengeWire,
    pub joint_combiner: Option<ScalarChallengeWire>,
    pub feature_flags: FeatureFlagsWire,
}

/// `Scalar_challenge.t = { inner }` — wraps a 128-bit challenge.
#[derive(Debug, Deserialize, Serialize)]
pub struct ScalarChallengeWire {
    pub inner: [i64; 2],
}

/// `Bulletproof_challenge.t = { prechallenge : 'scalar_challenge }`.
#[derive(Debug, Deserialize, Serialize)]
pub struct BulletproofChallengeWire {
    pub prechallenge: ScalarChallengeWire,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FeatureFlagsWire {
    pub range_check0: bool,
    pub range_check1: bool,
    pub foreign_field_add: bool,
    pub foreign_field_mul: bool,
    pub xor: bool,
    pub rot: bool,
    pub lookup: bool,
    pub runtime_tables: bool,
}

/// `Branch_data.t`. OCaml serializes `proofs_verified` as the single-
/// element array `["N1"]` (variant tag) and `domain_log2` as a one-character
/// string whose code point is the byte value.
#[derive(Debug, Deserialize, Serialize)]
pub struct BranchDataWire {
    #[serde(
        deserialize_with = "parse_proofs_verified_tag",
        serialize_with = "emit_proofs_verified_tag"
    )]
    pub proofs_verified: ProofsVerifiedTag,
    #[serde(
        deserialize_with = "parse_single_char_u8",
        serialize_with = "emit_single_char_u8"
    )]
    pub domain_log2: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ProofsVerifiedTag {
    N0,
    N1,
    N2,
}

fn parse_proofs_verified_tag<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<ProofsVerifiedTag, D::Error> {
    let v: Vec<String> = Vec::deserialize(d)?;
    match v.as_slice() {
        [s] if s == "N0" => Ok(ProofsVerifiedTag::N0),
        [s] if s == "N1" => Ok(ProofsVerifiedTag::N1),
        [s] if s == "N2" => Ok(ProofsVerifiedTag::N2),
        _ => Err(de::Error::custom(
            r#"expected ["N0"] | ["N1"] | ["N2"] for proofs_verified"#,
        )),
    }
}

fn parse_single_char_u8<'de, D: Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let s: String = String::deserialize(d)?;
    let mut chars = s.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => {
            let code = c as u32;
            if code > 0xff {
                Err(de::Error::custom("domain_log2 character outside u8 range"))
            } else {
                Ok(code as u8)
            }
        }
        _ => Err(de::Error::custom(
            "expected a one-character string for domain_log2",
        )),
    }
}

fn emit_proofs_verified_tag<S: Serializer>(
    tag: &ProofsVerifiedTag,
    s: S,
) -> Result<S::Ok, S::Error> {
    let label = match tag {
        ProofsVerifiedTag::N0 => "N0",
        ProofsVerifiedTag::N1 => "N1",
        ProofsVerifiedTag::N2 => "N2",
    };
    let mut seq = s.serialize_seq(Some(1))?;
    seq.serialize_element(label)?;
    seq.end()
}

fn emit_single_char_u8<S: Serializer>(byte: &u8, s: S) -> Result<S::Ok, S::Error> {
    // Mirror the OCaml emission: a one-character string whose Unicode
    // code point equals the u8 value.
    let c = char::from(*byte);
    let mut buf = [0u8; 4];
    let encoded = c.encode_utf8(&mut buf);
    s.serialize_str(encoded)
}

/// A curve point on either Vesta (for `messages_for_next_wrap_proof`) or
/// Pallas (for `messages_for_next_step_proof`). OCaml emits both as a
/// two-element array of `"0x<hex>"` strings representing the base-field
/// coordinates.
pub type CurvePointWire = [String; 2];

#[derive(Debug, Deserialize, Serialize)]
pub struct MessagesForNextWrapProofWire {
    pub challenge_polynomial_commitment: CurvePointWire,
    /// Outer length = `mlmb`; inner = `Wrap_bp_vec` = 15 entries.
    pub old_bulletproof_challenges: Vec<Vec<BulletproofChallengeWire>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MessagesForNextStepProofWire {
    /// Populated by the OCaml `inject_app_state` step — decimal-string
    /// field elements, one per slot in the step circuit's typed
    /// `public_input`. Raw pickles `Proof.t` fixes `'s = unit` so pickles
    /// itself writes this as `null`; the splice replaces it with the real
    /// value.
    pub app_state: Vec<String>,
    pub challenge_polynomial_commitments: Vec<CurvePointWire>,
    /// Outer length = `most_recent_width`; inner = `Step_bp_vec` = 16 entries.
    pub old_bulletproof_challenges: Vec<Vec<BulletproofChallengeWire>>,
}

// ---- prev_evals -----------------------------------------------------------
//
// OCaml: `Plonk_types.All_evals.Stable.V1.t` from
// `pickles_types/plonk_types.ml`. After `Proof.Make.to_repr` collapses the
// public-input arrays to single values (proof.ml:260-261), each "point
// evaluation" becomes a 2-tuple `(at_zeta, at_zetaw)`:
//
//   * `public_input : ('f * 'f)`           → [String; 2]   (hex strings, 1 F each)
//   * every polynomial in `evals`: chunks  → [Vec<String>; 2]  (1 chunk/point for
//                                             Simple_chain, so inner len = 1)
//
// Optional gates / lookups are emitted as JSON `null` when absent.

/// `{ evals; ft_eval1 }` — the step proof's polynomial evaluations carried
/// by the wrap proof.
#[derive(Debug, Deserialize, Serialize)]
pub struct PrevEvalsWire {
    pub evals: EvalsWithPublicInputWire,
    pub ft_eval1: String,
}

/// `{ public_input; evals }` where `public_input` is the already-combined
/// `(zeta, zeta_omega)` pair (OCaml collapses the chunk arrays in
/// `Proof.Make.to_repr`) and `evals` is the kimchi-shape
/// `ProofEvaluations<PointEvaluations<chunk_array>>`.
#[derive(Debug, Deserialize, Serialize)]
pub struct EvalsWithPublicInputWire {
    pub public_input: [String; 2],
    pub evals: KimchiEvalsWire,
}

/// One polynomial's `(zeta, zeta_omega)` evaluations — each side is an
/// array of chunk evaluations. Simple_chain is single-chunk, so the inner
/// `Vec<String>` always has length 1; keeping it variable-length tracks
/// the OCaml shape exactly.
pub type PointEvalsChunkedWire = [Vec<String>; 2];

/// Direct mirror of kimchi's `ProofEvaluations` shape as pickles emits it.
/// Field order and names match `proof-systems/kimchi/src/proof.rs:50`.
#[derive(Debug, Deserialize, Serialize)]
pub struct KimchiEvalsWire {
    /// 15 witness columns.
    pub w: Vec<PointEvalsChunkedWire>,
    /// 15 coefficient columns.
    pub coefficients: Vec<PointEvalsChunkedWire>,
    /// Permutation polynomial.
    pub z: PointEvalsChunkedWire,
    /// 6 sigma polynomials (PERMUTS - 1).
    pub s: Vec<PointEvalsChunkedWire>,
    pub generic_selector: PointEvalsChunkedWire,
    pub poseidon_selector: PointEvalsChunkedWire,
    pub complete_add_selector: PointEvalsChunkedWire,
    pub mul_selector: PointEvalsChunkedWire,
    pub emul_selector: PointEvalsChunkedWire,
    pub endomul_scalar_selector: PointEvalsChunkedWire,

    // Optional gates
    pub range_check0_selector: Option<PointEvalsChunkedWire>,
    pub range_check1_selector: Option<PointEvalsChunkedWire>,
    pub foreign_field_add_selector: Option<PointEvalsChunkedWire>,
    pub foreign_field_mul_selector: Option<PointEvalsChunkedWire>,
    pub xor_selector: Option<PointEvalsChunkedWire>,
    pub rot_selector: Option<PointEvalsChunkedWire>,

    // Optional lookup-related
    pub lookup_aggregation: Option<PointEvalsChunkedWire>,
    pub lookup_table: Option<PointEvalsChunkedWire>,
    /// Length 5, each `Option`.
    pub lookup_sorted: Vec<Option<PointEvalsChunkedWire>>,
    pub runtime_lookup_table: Option<PointEvalsChunkedWire>,
    pub runtime_lookup_table_selector: Option<PointEvalsChunkedWire>,
    pub xor_lookup_selector: Option<PointEvalsChunkedWire>,
    pub lookup_gate_lookup_selector: Option<PointEvalsChunkedWire>,
    pub range_check_lookup_selector: Option<PointEvalsChunkedWire>,
    pub foreign_field_mul_lookup_selector: Option<PointEvalsChunkedWire>,
}
