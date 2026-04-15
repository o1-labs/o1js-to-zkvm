//! Prepared wrap-statement packing for the new Pickles path.
//!
//! The target here is the behavior of
//! `mina-rust/crates/ledger/src/proofs/public_input/prepared_statement.rs`.

use ark_ff::BigInteger256;
use mina_curves::pasta::{Fp, Fq};

use crate::pickles_error::PicklesError;
use crate::pickles_mina_rust::types::{BranchData, PreparedStatement, WrapVerificationInput};
use crate::pickles_types::PlonkFeatureFlags;

impl PreparedStatement {
    /// Pack the wrap prepared statement into the final Kimchi public input.
    pub fn to_public_input(
        &self,
        npublic_input: usize,
    ) -> Result<WrapVerificationInput, PicklesError> {
        let mut fields = Vec::with_capacity(npublic_input);

        let deferred_values = &self.proof_state.deferred_values;
        let plonk = &deferred_values.plonk;

        let to_fq = |fp: Fp| -> Fq { Fq::from(BigInteger256::from(fp)) };

        fields.push(to_fq(deferred_values.combined_inner_product.shifted));
        fields.push(to_fq(deferred_values.b.shifted));
        fields.push(to_fq(plonk.zeta_to_srs_length.shifted));
        fields.push(to_fq(plonk.zeta_to_domain_size.shifted));
        fields.push(to_fq(plonk.perm.shifted));

        fields.push(two_u64_to_field::<Fq>(&plonk.beta));
        fields.push(two_u64_to_field::<Fq>(&plonk.gamma));

        fields.push(two_u64_to_field::<Fq>(&plonk.alpha));
        fields.push(two_u64_to_field::<Fq>(&plonk.zeta));
        fields.push(two_u64_to_field::<Fq>(&deferred_values.xi));

        fields.push(four_u64_to_field::<Fq>(&self.proof_state.sponge_digest_before_evaluations)?);
        fields.push(four_u64_to_field::<Fq>(&self.proof_state.messages_for_next_wrap_proof)?);
        fields.push(four_u64_to_field::<Fq>(&self.messages_for_next_step_proof)?);

        fields.extend(deferred_values.bulletproof_challenges.iter().copied().map(to_fq));

        fields.push(pack_branch_data(&deferred_values.branch_data)?);

        for enabled in feature_flag_values(&plonk.feature_flags) {
            fields.push(Fq::from(u64::from(enabled)));
        }

        let uses_lookup = uses_lookup(&plonk.feature_flags);
        fields.push(Fq::from(u64::from(uses_lookup)));
        fields.push(if uses_lookup {
            plonk
                .lookup
                .map(|v| two_u64_to_field::<Fq>(&v))
                .unwrap_or_else(|| Fq::from(0u64))
        } else {
            Fq::from(0u64)
        });

        if fields.len() != npublic_input {
            return Err(PicklesError::InvalidJson(format!(
                "prepared statement packed {} public-input fields, expected {npublic_input}",
                fields.len()
            )));
        }

        Ok(WrapVerificationInput {
            public_input: fields,
        })
    }
}

fn four_u64_to_field<F>(v: &[u64; 4]) -> Result<F, PicklesError>
where
    F: ark_ff::Field + TryFrom<BigInteger256>,
{
    let bigint = BigInteger256::new(*v);
    F::try_from(bigint).map_err(|_| {
        PicklesError::InvalidFieldElement(format!(
            "invalid 4-limb field element: {:016x?}",
            v
        ))
    })
}

fn two_u64_to_field<F>(v: &[u64; 2]) -> F
where
    F: ark_ff::Field + TryFrom<BigInteger256>,
    <F as TryFrom<BigInteger256>>::Error: core::fmt::Debug,
{
    let mut bigint = [0u64; 4];
    bigint[..2].copy_from_slice(v);
    let bigint = BigInteger256::new(bigint);
    F::try_from(bigint).expect("2-limb challenge field must be valid")
}

fn pack_branch_data(branch_data: &BranchData) -> Result<Fq, PicklesError> {
    let proofs_verified = match branch_data.proofs_verified {
        0 => 0b00,
        1 => 0b10,
        2 => 0b11,
        other => {
            return Err(PicklesError::InvalidJson(format!(
                "unsupported proofs_verified value for branch_data packing: {other}"
            )))
        }
    };
    let branch_data = ((branch_data.domain_log2 as u64) << 2) | proofs_verified;
    Ok(Fq::from(branch_data))
}

fn feature_flag_values(feature_flags: &PlonkFeatureFlags) -> [bool; 8] {
    [
        feature_flags.range_check0,
        feature_flags.range_check1,
        feature_flags.foreign_field_add,
        feature_flags.foreign_field_mul,
        feature_flags.xor,
        feature_flags.rot,
        feature_flags.lookup,
        feature_flags.runtime_tables,
    ]
}

fn uses_lookup(feature_flags: &PlonkFeatureFlags) -> bool {
    [
        feature_flags.range_check0,
        feature_flags.range_check1,
        feature_flags.foreign_field_mul,
        feature_flags.xor,
        feature_flags.rot,
        feature_flags.lookup,
    ]
    .iter()
    .any(|b| *b)
}
