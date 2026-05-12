fn main() {
    // Activates mina-curves' SP1 precompile fast-path for Pasta Fp/Fq
    // in the guest sub-build only — host workspace's mina-curves is
    // unaffected.
    let args = sp1_build::BuildArgs {
        features: vec!["sp1".to_string()],
        ..Default::default()
    };
    sp1_build::build_program_with_args("../o1-verifier", args);
}
