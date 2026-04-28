//! Embed the wrap-circuit `VerifierIndex` and `SRS<Pallas>` from the
//! Simple_chain fixtures directory into the guest's read-only memory
//! via `OUT_DIR`. The point in directing build.rs to a directory
//! (rather than two paths) is uniformity: regenerated fixtures all
//! land in one place, controlled by a single env var.

use std::env;
use std::fs;
use std::path::Path;

const VI_NAME: &str = "simple_chain_wrap_vi.bin";
const SRS_NAME: &str = "simple_chain_wrap_srs.bin";

fn main() {
    let dir = env::var("SIMPLE_CHAIN_FIXTURES_DIR").expect(
        "SIMPLE_CHAIN_FIXTURES_DIR env var must point to the directory \
         containing simple_chain_wrap_vi.bin and simple_chain_wrap_srs.bin",
    );
    println!("cargo::rerun-if-env-changed=SIMPLE_CHAIN_FIXTURES_DIR");

    let dir = Path::new(&dir);
    let vi_path = dir.join(VI_NAME);
    let srs_path = dir.join(SRS_NAME);
    println!("cargo::rerun-if-changed={}", vi_path.display());
    println!("cargo::rerun-if-changed={}", srs_path.display());

    let out_dir = env::var("OUT_DIR").unwrap();
    let out = Path::new(&out_dir);
    fs::copy(&vi_path, out.join(VI_NAME)).unwrap_or_else(|e| {
        panic!("failed to copy {}: {e}", vi_path.display());
    });
    fs::copy(&srs_path, out.join(SRS_NAME)).unwrap_or_else(|e| {
        panic!("failed to copy {}: {e}", srs_path.display());
    });
}
