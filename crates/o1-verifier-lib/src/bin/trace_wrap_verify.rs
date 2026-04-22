//! Timing and boundary tracer for the final wrap-verification path.
//!
//! This binary is used when the high-level Pickles verifier reaches Kimchi but
//! still returns the wrong answer or stalls. It splits the wrap-verification
//! path into major phases such as public-input commitment construction, oracle
//! replay, batch construction, and the final opening-proof check.

#![cfg(feature = "std")]

use std::env;
use std::time::Instant;

use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, Polynomial};
use groupmap::GroupMap;
use kimchi::circuits::argument::ArgumentType;
use kimchi::circuits::berkeley_columns::{BerkeleyChallenges, Column};
use kimchi::circuits::constraints::ConstraintSystem;
use kimchi::circuits::expr::{Constants, PolishToken};
use kimchi::circuits::gate::GateType;
use kimchi::circuits::polynomials::permutation;
use kimchi::circuits::wires::{COLUMNS, PERMUTS};
use kimchi::curve::KimchiCurve;
use kimchi::verifier::Context;
use mina_curves::pasta::{Fq, Pallas};
use mina_poseidon::pasta::FULL_ROUNDS;
use o1_verifier_lib::pickles_mina_rust::verify::lower_pickles_with_mina_rust_model;
use o1_verifier_lib::{parse_simple_chain_bundle_with_urs_sidecar, WrapBaseSponge, WrapScalarSponge};
use poly_commitment::commitment::{BatchEvaluationProof, CommitmentCurve, Evaluation, PolyComm};
use poly_commitment::ipa::{OpeningProof, SRS as IpaSRS};
use poly_commitment::{OpenProof, SRS as SRSTrait};
use rand::rngs::StdRng;
use rand::SeedableRng;

const REAL_SIMPLE_CHAIN_BUNDLE_JSON: &str =
    include_str!("../../../../fixtures/simple_chain_real_bundle.json");
const REAL_SIMPLE_CHAIN_URS_GENERATORS_JSON: &str =
    include_str!("../../../../fixtures/simple_chain_real_bundle.urs_generators.json");

/// Execute the traced wrap-verification flow for one fixture and print the time
/// spent in each major Kimchi-side phase.
fn main() {
    let bundle = parse_simple_chain_bundle_with_urs_sidecar(
        REAL_SIMPLE_CHAIN_BUNDLE_JSON,
        Some(REAL_SIMPLE_CHAIN_URS_GENERATORS_JSON),
    )
    .expect("real bundle should parse");

    let fixture_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "recursive_step".to_string());
    let request = bundle
        .request_for_fixture(&fixture_name)
        .unwrap_or_else(|err| panic!("failed to load fixture {fixture_name}: {err}"));

    let started = Instant::now();
    let lowered = lower_pickles_with_mina_rust_model(&request)
        .unwrap_or_else(|err| panic!("failed to lower fixture {fixture_name}: {err}"));
    println!("lowered: {:?}", started.elapsed());

    let context = Context {
        verifier_index: &lowered.verifier_index,
        proof: &lowered.proof,
        public_input: &lowered.public_input,
    };

    let public_comm_started = Instant::now();
    let public_comm = build_public_comm(&context);
    println!("public_comm: {:?}", public_comm_started.elapsed());

    let oracles_started = Instant::now();
    let oracles = lowered
        .proof
        .oracles::<WrapBaseSponge, WrapScalarSponge, _>(
            &lowered.verifier_index,
            &public_comm,
            Some(&lowered.public_input),
        )
        .expect("oracles should build");
    println!("oracles: {:?}", oracles_started.elapsed());

    let batch_started = Instant::now();
    let batch = build_batch(&context, public_comm, oracles);
    println!("batch_build: {:?}", batch_started.elapsed());

    let opening_started = Instant::now();
    let mut batch_vec = vec![batch];
    let group_map = <Pallas as CommitmentCurve>::Map::setup();
    let mut rng = StdRng::seed_from_u64(42);
    let ok = OpeningProof::<Pallas, FULL_ROUNDS>::verify(
        lowered.verifier_index.srs().as_ref(),
        &group_map,
        &mut batch_vec,
        &mut rng,
    );
    println!("opening_verify: {:?}", opening_started.elapsed());
    println!("result: {ok}");
}

/// Rebuild the public-input commitment that Kimchi feeds into oracle replay.
///
/// This is the first expensive verifier step after Pickles has already lowered
/// the prepared statement into raw wrap public input.
fn build_public_comm(
    context: &Context<'_, { FULL_ROUNDS }, Pallas, OpeningProof<Pallas, FULL_ROUNDS>, IpaSRS<Pallas>>,
) -> PolyComm<Pallas> {
    let verifier_index = context.verifier_index;
    let public_input = context.public_input;

    let chunk_size = {
        let d1_size = verifier_index.domain.size();
        if d1_size < verifier_index.max_poly_size {
            1
        } else {
            d1_size / verifier_index.max_poly_size
        }
    };

    let lagrange_started = Instant::now();
    let lgr_comm = verifier_index
        .srs()
        .get_lagrange_basis(verifier_index.domain);
    println!("public_comm.get_lagrange_basis: {:?}", lagrange_started.elapsed());
    let com: Vec<_> = lgr_comm.iter().take(verifier_index.public).collect();
    if public_input.is_empty() {
        PolyComm::new(vec![verifier_index.srs().blinding_commitment(); chunk_size])
    } else {
        let elm: Vec<_> = public_input.iter().map(|s| -*s).collect();
        let msm_started = Instant::now();
        let public_comm = PolyComm::<Pallas>::multi_scalar_mul(&com, &elm);
        println!("public_comm.multi_scalar_mul: {:?}", msm_started.elapsed());
        let mask_started = Instant::now();
        let masked = verifier_index
            .srs()
            .mask_custom(
                public_comm.clone(),
                &public_comm.map(|_| Fq::from(1u64)),
            )
            .unwrap()
            .commitment;
        println!("public_comm.mask_custom: {:?}", mask_started.elapsed());
        masked
    }
}

/// Recreate the exact batch opening-check structure that Kimchi feeds into IPA
/// verification for the wrap proof.
///
/// This lets the tracer measure the boundary between oracle replay and the
/// final opening-proof check without going through the entire verifier as one
/// opaque call.
fn build_batch<'a>(
    context: &'a Context<
        'a,
        { FULL_ROUNDS },
        Pallas,
        OpeningProof<Pallas, FULL_ROUNDS>,
        IpaSRS<Pallas>,
    >,
    public_comm: PolyComm<Pallas>,
    oracles_result: kimchi::oracles::OraclesResult<{ FULL_ROUNDS }, Pallas, WrapBaseSponge>,
) -> BatchEvaluationProof<'a, Pallas, WrapBaseSponge, OpeningProof<Pallas, FULL_ROUNDS>, { FULL_ROUNDS }> {
    let verifier_index = context.verifier_index;
    let proof = context.proof;
    let zk_rows = verifier_index.zk_rows;

    assert!(
        verifier_index.lookup_index.is_none(),
        "trace_wrap_verify only supports the lookup-free Simple_chain wrap path"
    );

    let kimchi::oracles::OraclesResult {
        fq_sponge,
        oracles,
        all_alphas,
        public_evals,
        powers_of_eval_points_for_chunks,
        polys,
        zeta1: zeta_to_domain_size,
        ft_eval0,
        combined_inner_product,
        ..
    } = oracles_result;

    let evals = proof.evals.combine(&powers_of_eval_points_for_chunks);

    let f_comm = {
        let permutation_vanishing_polynomial = verifier_index
            .permutation_vanishing_polynomial_m()
            .evaluate(&oracles.zeta);

        let alphas = all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);

        let mut commitments = vec![&verifier_index.sigma_comm[PERMUTS - 1]];
        let mut scalars = vec![ConstraintSystem::perm_scalars(
            &evals,
            oracles.beta,
            oracles.gamma,
            alphas,
            permutation_vanishing_polynomial,
        )];

        let constants = Constants {
            endo_coefficient: verifier_index.endo,
            mds: &Pallas::sponge_params().mds,
            zk_rows,
        };
        let challenges = BerkeleyChallenges {
            alpha: oracles.alpha,
            beta: oracles.beta,
            gamma: oracles.gamma,
            joint_combiner: oracles
                .joint_combiner
                .as_ref()
                .map(|j| j.1)
                .unwrap_or_else(Fq::zero),
        };

        for (col, tokens) in &verifier_index.linearization.index_terms {
            let scalar = PolishToken::evaluate(
                tokens,
                verifier_index.domain,
                oracles.zeta,
                &evals,
                &constants,
                &challenges,
            )
            .expect("linearization term should evaluate");

            scalars.push(scalar);
            commitments.push(
                context
                    .get_column(*col)
                    .expect("missing commitment during trace"),
            );
        }

        PolyComm::multi_scalar_mul(&commitments, &scalars)
    };

    let ft_comm = {
        let zeta_to_srs_len = oracles.zeta.pow([verifier_index.max_poly_size as u64]);
        let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - Fq::from(1u64))
    };

    let mut evaluations = vec![];
    evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
        commitment: c,
        evaluations: e,
    }));
    evaluations.push(Evaluation {
        commitment: public_comm,
        evaluations: public_evals.to_vec(),
    });
    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
    });

    for col in [
        Column::Z,
        Column::Index(GateType::Generic),
        Column::Index(GateType::Poseidon),
        Column::Index(GateType::CompleteAdd),
        Column::Index(GateType::VarBaseMul),
        Column::Index(GateType::EndoMul),
        Column::Index(GateType::EndoMulScalar),
    ]
    .into_iter()
    .chain((0..COLUMNS).map(Column::Witness))
    .chain((0..COLUMNS).map(Column::Coefficient))
    .chain((0..PERMUTS - 1).map(Column::Permutation))
    .chain(
        verifier_index
            .range_check0_comm
            .as_ref()
            .map(|_| Column::Index(GateType::RangeCheck0)),
    )
    .chain(
        verifier_index
            .range_check1_comm
            .as_ref()
            .map(|_| Column::Index(GateType::RangeCheck1)),
    )
    .chain(
        verifier_index
            .foreign_field_add_comm
            .as_ref()
            .map(|_| Column::Index(GateType::ForeignFieldAdd)),
    )
    .chain(
        verifier_index
            .foreign_field_mul_comm
            .as_ref()
            .map(|_| Column::Index(GateType::ForeignFieldMul)),
    )
    .chain(
        verifier_index
            .xor_comm
            .as_ref()
            .map(|_| Column::Index(GateType::Xor16)),
    )
    .chain(
        verifier_index
            .rot_comm
            .as_ref()
            .map(|_| Column::Index(GateType::Rot64)),
    ) {
        let evals = proof
            .evals
            .get_column(col)
            .expect("missing evaluation during trace");
        evaluations.push(Evaluation {
            commitment: context
                .get_column(col)
                .expect("missing commitment during trace")
                .clone(),
            evaluations: vec![evals.zeta.clone(), evals.zeta_omega.clone()],
        });
    }

    let evaluation_points = vec![oracles.zeta, oracles.zeta * verifier_index.domain.group_gen];
    BatchEvaluationProof {
        sponge: fq_sponge,
        evaluations,
        evaluation_points,
        polyscale: oracles.v,
        evalscale: oracles.u,
        opening: &proof.proof,
        combined_inner_product,
    }
}
