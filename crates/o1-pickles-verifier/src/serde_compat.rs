//! Tiny no_std + alloc port of the `SerdeAs` adapter mina uses in
//! `o1-utils::serialization`: bridge `serde::{Serialize, Deserialize}`
//! to `ark_serialize::{CanonicalSerialize, CanonicalDeserialize}` so
//! ark types (Fp/Fq, Pasta points) can ride inside any
//! serde-serializable container.
//!
//! We need this because SP1's `sp1_zkvm::io::{commit, read}` go
//! through `serde`, but `ark-ff` 0.5 has no `serde` feature — its
//! field elements implement only `CanonicalSerialize`. The mina
//! upstream `o1-utils` crate solves the same problem but pulls in
//! `std` (`bcs`, `rayon`, ...), so we can't reuse it inside the
//! guest.
//!
//! Usage on a struct field:
//!
//! ```ignore
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Wrapper {
//!     #[serde(with = "crate::serde_compat::ark")]
//!     value: Fp,
//! }
//! ```
//!
//! The byte form is whatever `serialize_compressed` produces, wrapped
//! as a length-prefixed `serde` byte array. This roundtrips through
//! bincode (used by SP1) and rmp-serde alike.

extern crate alloc;

use alloc::vec::Vec;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod ark {
    use super::*;

    pub fn serialize<T, S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: CanonicalSerialize,
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(val.compressed_size());
        val.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        T::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
    }
}
