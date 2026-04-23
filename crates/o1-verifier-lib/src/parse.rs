use std::str::FromStr;

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::PrimeField;
use kimchi::curve::KimchiCurve;
use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Fp, Fq, PallasParameters, VestaParameters};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::ipa::SRS;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(serde::Deserialize)]
pub struct CircuitDescription {
    #[serde(rename = "verificationKey")]
    pub verification_key: String,
    pub srs: Vec<SrsPoint>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub enum SrsPoint {
    Infinity(()),
    Point { x: String, y: String },
}

#[derive(serde::Deserialize)]
pub struct ProofOutput {
    pub proof: ProofJson,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofJson {
    pub proof: String,
    pub public_input_fields: Vec<String>,
}

type VerifierIndexFor<P> = VerifierIndex<FULL_ROUNDS, Affine<P>, SRS<Affine<P>>>;

/// Parse one `OrInfinity` SRS point into an affine group element. Decodes the
/// coordinates in the curve's base field.
fn parse_srs_point<P>(p: &SrsPoint) -> Affine<P>
where
    P: SWCurveConfig,
    P::BaseField: PrimeField + FromStr,
{
    match p {
        SrsPoint::Infinity(()) => Affine::<P>::identity(),
        SrsPoint::Point { x, y } => {
            let x = P::BaseField::from_str(x)
                .ok()
                .expect("invalid SRS x coordinate");
            let y = P::BaseField::from_str(y)
                .ok()
                .expect("invalid SRS y coordinate");
            Affine::<P>::new_unchecked(x, y)
        }
    }
}

/// Parse a `{verificationKey, srs}` JSON bundle and produce msgpack bytes for
/// the VerifierIndex and SRS suitable for `load_verifier_index_generic`.
/// Generic over the curve's SW config [P].
pub fn parse_circuit_json_generic<P>(circuit_json: &str) -> (Vec<u8>, Vec<u8>)
where
    P: SWCurveConfig,
    P::BaseField: PrimeField + FromStr,
    Affine<P>: KimchiCurve<FULL_ROUNDS>,
    VerifierIndexFor<P>: DeserializeOwned + Serialize,
{
    let circuit: CircuitDescription =
        serde_json::from_str(circuit_json).expect("failed to parse circuit JSON");

    let vk_json = String::from_utf8(
        base64::decode(&circuit.verification_key).expect("invalid base64 in verificationKey"),
    )
    .expect("verificationKey is not valid UTF-8");

    let vi: VerifierIndexFor<P> =
        serde_json::from_str(&vk_json).expect("failed to deserialize VerifierIndex from JSON");
    let vi_bytes = rmp_serde::to_vec(&vi).expect("failed to serialize VerifierIndex to msgpack");

    assert!(
        circuit.srs.len() >= 2,
        "SRS must have at least h + one g element"
    );
    let h = parse_srs_point::<P>(&circuit.srs[0]);
    let g: Vec<Affine<P>> = circuit.srs[1..].iter().map(parse_srs_point::<P>).collect();

    let srs = SRS::<Affine<P>> {
        h,
        g,
        ..SRS::<Affine<P>>::default()
    };
    let srs_bytes = rmp_serde::to_vec(&srs).expect("failed to serialize SRS to msgpack");

    (vi_bytes, srs_bytes)
}

/// Parse a proof JSON and return raw proof bytes (msgpack) and serialized
/// public inputs (canonical, per field element). Generic over the public input
/// field [F].
pub fn parse_proof_json_generic<F: PrimeField + FromStr>(proof_json: &str) -> (Vec<u8>, Vec<u8>) {
    let output: ProofOutput = serde_json::from_str(proof_json).expect("failed to parse proof JSON");

    let proof_bytes = base64::decode(&output.proof.proof).expect("invalid base64 in proof");

    let public_input: Vec<F> = output
        .proof
        .public_input_fields
        .iter()
        .map(|s| {
            F::from_str(s)
                .ok()
                .expect("invalid public input field element")
        })
        .collect();

    let mut pub_bytes = Vec::with_capacity(public_input.len() * 32);
    for f in &public_input {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf).unwrap();
        pub_bytes.extend_from_slice(&buf);
    }

    (proof_bytes, pub_bytes)
}

// --- Curve-specific wrappers ---

pub fn parse_vesta_circuit_json(circuit_json: &str) -> (Vec<u8>, Vec<u8>) {
    parse_circuit_json_generic::<VestaParameters>(circuit_json)
}

pub fn parse_pallas_circuit_json(circuit_json: &str) -> (Vec<u8>, Vec<u8>) {
    parse_circuit_json_generic::<PallasParameters>(circuit_json)
}

pub fn parse_vesta_proof_json(proof_json: &str) -> (Vec<u8>, Vec<u8>) {
    parse_proof_json_generic::<Fp>(proof_json)
}

pub fn parse_pallas_proof_json(proof_json: &str) -> (Vec<u8>, Vec<u8>) {
    parse_proof_json_generic::<Fq>(proof_json)
}
