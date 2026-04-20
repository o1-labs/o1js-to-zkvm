#![cfg(feature = "std")]

use std::env;
use std::time::Instant;

use o1_verifier_lib::pickles_mina_rust::verify_pickles_with_mina_rust_model;
use o1_verifier_lib::parse_simple_chain_bundle_with_urs_sidecar;
use rand::rngs::StdRng;
use rand::SeedableRng;

const REAL_SIMPLE_CHAIN_BUNDLE_JSON: &str =
    include_str!("../../../../fixtures/simple_chain_real_bundle.json");
const REAL_SIMPLE_CHAIN_URS_GENERATORS_JSON: &str =
    include_str!("../../../../fixtures/simple_chain_real_bundle.urs_generators.json");

fn main() {
    let bundle = parse_simple_chain_bundle_with_urs_sidecar(
        REAL_SIMPLE_CHAIN_BUNDLE_JSON,
        Some(REAL_SIMPLE_CHAIN_URS_GENERATORS_JSON),
    )
    .expect("real bundle should parse");

    let fixture_names = env::args().skip(1).collect::<Vec<_>>();
    let fixture_names = if fixture_names.is_empty() {
        vec!["base_case".to_string(), "recursive_step".to_string()]
    } else {
        fixture_names
    };

    for fixture_name in fixture_names {
        let request = bundle
            .request_for_fixture(&fixture_name)
            .unwrap_or_else(|err| panic!("failed to load fixture {fixture_name}: {err}"));
        let started = Instant::now();
        let mut rng = StdRng::seed_from_u64(42);
        let result = verify_pickles_with_mina_rust_model(&request, &mut rng);
        println!(
            "{fixture_name}: elapsed={:?} result={result:?}",
            started.elapsed()
        );
    }
}
