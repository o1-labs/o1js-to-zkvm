extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use mina_curves::pasta::Fp;

use crate::pickles_error::PicklesError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideLoadedVkBytes(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideLoadedProofBytes(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurvePointHex {
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideLoadedProofMetadata {
    pub proofs_verified: u8,
    pub domain_log2: u8,
    pub sponge_digest_before_evaluations: Vec<String>,
    pub wrap_challenge_polynomial_commitment: CurvePointHex,
    pub wrap_old_bulletproof_challenges_count: usize,
    pub next_step_challenge_polynomial_commitments: Vec<CurvePointHex>,
    pub next_step_old_bulletproof_challenges_count: usize,
    pub prev_evals_public_input: Vec<String>,
    pub ft_eval1: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SimpleChainStatement {
    pub value: Fp,
}

impl SimpleChainStatement {
    pub fn from_fields(fields: &[Fp]) -> Result<Self, PicklesError> {
        if fields.len() != 1 {
            return Err(PicklesError::UnsupportedStatementShape {
                expected: 1,
                actual: fields.len(),
            });
        }

        Ok(Self { value: fields[0] })
    }

    pub fn to_fields(&self) -> Vec<Fp> {
        vec![self.value]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SimpleChainFixture {
    pub name: String,
    pub statement: SimpleChainStatement,
    pub proof: SideLoadedProofBytes,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SimpleChainFixtureBundle {
    pub verification_key: SideLoadedVkBytes,
    pub fixtures: Vec<SimpleChainFixture>,
}

impl SimpleChainFixtureBundle {
    pub fn fixture(&self, name: &str) -> Option<&SimpleChainFixture> {
        self.fixtures.iter().find(|fixture| fixture.name == name)
    }

    pub fn request_for_fixture(&self, name: &str) -> Result<PicklesVerifyRequest, PicklesError> {
        let fixture = self
            .fixture(name)
            .ok_or_else(|| PicklesError::MissingFixture(name.into()))?;

        Ok(PicklesVerifyRequest {
            vk: self.verification_key.clone(),
            proof: fixture.proof.clone(),
            statement: fixture.statement.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PicklesVerifyRequest {
    pub vk: SideLoadedVkBytes,
    pub proof: SideLoadedProofBytes,
    pub statement: SimpleChainStatement,
}
