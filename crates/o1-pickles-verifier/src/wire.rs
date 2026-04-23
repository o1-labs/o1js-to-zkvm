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
use serde::Deserialize;

/// The top-level JSON dumped by `Pickles.Proof.Make(Nat.N1).to_yojson_full`,
/// with the `app_state` splice applied on the OCaml side. We only consume
/// `statement` here; `prev_evals` and `proof` are parsed opaquely to keep
/// this module focused.
#[derive(Debug, Deserialize)]
pub struct ProofReprWire {
    pub statement: StatementWire,
    #[serde(default, skip)]
    pub prev_evals: (),
    #[serde(default, skip)]
    pub proof: (),
}

#[derive(Debug, Deserialize)]
pub struct StatementWire {
    pub proof_state: ProofStateWire,
    pub messages_for_next_step_proof: MessagesForNextStepProofWire,
}

#[derive(Debug, Deserialize)]
pub struct ProofStateWire {
    pub deferred_values: DeferredValuesWire,
    /// 256-bit `Digest.Constant.t`, serialized as four signed int64 limbs.
    /// Reinterpret as `[u64; 4]` when lowering.
    pub sponge_digest_before_evaluations: [i64; 4],
    pub messages_for_next_wrap_proof: MessagesForNextWrapProofWire,
}

#[derive(Debug, Deserialize)]
pub struct DeferredValuesWire {
    pub plonk: PlonkMinimalWire,
    /// `Step_bp_vec` = Tick rounds = 16 entries.
    pub bulletproof_challenges: Vec<BulletproofChallengeWire>,
    pub branch_data: BranchDataWire,
}

#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
pub struct ScalarChallengeWire {
    pub inner: [i64; 2],
}

/// `Bulletproof_challenge.t = { prechallenge : 'scalar_challenge }`.
#[derive(Debug, Deserialize)]
pub struct BulletproofChallengeWire {
    pub prechallenge: ScalarChallengeWire,
}

#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
pub struct BranchDataWire {
    #[serde(deserialize_with = "parse_proofs_verified_tag")]
    pub proofs_verified: ProofsVerifiedTag,
    #[serde(deserialize_with = "parse_single_char_u8")]
    pub domain_log2: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A curve point on either Vesta (for `messages_for_next_wrap_proof`) or
/// Pallas (for `messages_for_next_step_proof`). OCaml emits both as a
/// two-element array of `"0x<hex>"` strings representing the base-field
/// coordinates.
pub type CurvePointWire = [String; 2];

#[derive(Debug, Deserialize)]
pub struct MessagesForNextWrapProofWire {
    pub challenge_polynomial_commitment: CurvePointWire,
    /// Outer length = `mlmb`; inner = `Wrap_bp_vec` = 15 entries.
    pub old_bulletproof_challenges: Vec<Vec<BulletproofChallengeWire>>,
}

#[derive(Debug, Deserialize)]
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
