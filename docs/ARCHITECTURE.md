# Architecture: wrap-proof verification in SP1

This document explains what data flows where, and why, in the Rust+SP1 verifier. It complements (it does not replace) the Pickles glossary in `mina/src/lib/crypto/pickles/pickles.mli`.

## Pipeline overview

```
                     ┌──────────────────────┐
                     │  OCaml simple_chain  │
                     │      .exe            │
                     │   (one-time)         │
                     └─────────┬────────────┘
                               │
                     emits to fixtures/
                               │
        ┌──────────────────────┼─────────────────────────┐
        │                      │                         │
        ▼                      ▼                         ▼
  wrap_vi.bin            proof_repr_bN.json       wrap_proof_bN.bin
  wrap_srs.bin           (Minimal statement +     (kimchi ProverProof
  (shared,               prev_evals as JSON)       msgpack, Pallas)
   per-circuit)


  ┌──────────────┐     ┌──────────────────────┐     ┌─────────┐
  │   build.rs   │     │   Guest (SP1)        │     │  Host   │
  │              │     │   o1-verifier        │     │ o1zkvm  │
  └──────┬───────┘     └─────────┬────────────┘     └────┬────┘
         │                       │                       │
   bakes constants:              │                       │
   - VI/SRS bytes                │                       │
   - vk_commitments              │                       │
         │                       │                       │
         └─► OUT_DIR ──► include_bytes!                  │
                                 │                       │
                                 │ ◄──── stdin ──────────┤
                                 │                       │
                            verify pipeline              │
                                 │                       │
                                 ▼                       │
                          CommitOutput {                 │
                            valid: bool,                 │
                            app_state: Vec<Fp>,          │
                            statement_digest: [u8; 32],  │
                          }                              │
                                 │                       │
                                 └─── public values ────►│
                                                         │
                                              (Groth16 wrapper
                                               consumes this)
```

## Terminology

Different people use overlapping words for what *is* the proof's "statement". Here's how this codebase uses them, smallest representation to largest:

### Statement (Minimal)

The shape OCaml's `Pickles.Proof.t` natively serializes. Type:

* **OCaml**: `Composition_types.Wrap.Statement.Minimal.t`
* **Rust wire**: private (`crates/o1-pickles-verifier/src/parse/wire.rs`)
* **Rust domain**: `statement::WrapStatement` (`crates/o1-pickles-verifier/src/statement.rs`)

Carries:
* the **plonk minimal challenges** (alpha, beta, gamma, zeta, xi, joint_combiner) as raw 128-bit values
* the **bulletproof challenges** as raw 128-bit values
* the **branch_data** (proofs_verified tag + domain_log2)
* the **two messages-for-next-* records** (sg commitments + raw bp prechallenges + app_state)
* the **sponge_digest_before_evaluations**

What it does *not* carry: the expanded values (`combined_inner_product`, `b`, `perm`, `zeta_to_*`). Important nuance — the *wrap proof itself* was generated against the **expanded** form (kimchi committed to those values as part of the wrap circuit's public input slots), and pickles forwards the expanded values into the next step circuit's witness during recursion. The drop happens only at the external `Pickles.Proof.t` serialization boundary: when OCaml writes a proof to disk via `to_yojson_full`, the minimal form is what lands there, on the (correct) assumption that anyone holding a `Proof.t` and prev_evals can re-derive the expansion deterministically. The verifier here does that re-derivation to reconstruct the kimchi public input.

So the chain looks like:

* **wrap circuit (proving time)** — public input contains *expanded* values; kimchi commits to them.
* **`Pickles.Proof.t` (serialized form)** — drops expanded values; carries only minimal.
* **next step circuit (consuming the proof)** — has the expanded values from `Wrap_deferred_values.expand_deferred` as witness, asserts they match the wrap proof's public input.
* **our verifier (this codebase)** — re-derives expanded values for the same reason as the next step circuit: to reconstruct the kimchi public input.

### Prev evals

The polynomial evaluations from the *step* proof underneath the wrap proof — `(at_zeta, at_zeta_omega)` pairs for every kimchi polynomial column, plus `ft_eval1`. Lives next to the statement under `prev_evals` in the proof-repr JSON.

* **OCaml**: `Plonk_types.All_evals.t`
* **Rust wire**: private (`crates/o1-pickles-verifier/src/parse/wire.rs`)
* **Rust domain**: `parse::ParsedPrevEvals`

### Expanded Statement

What you get after running `expand_deferred` on `(statement, prev_evals)`. Same shape as the minimal statement *plus* the derived deferred values:

* `combined_inner_product` (Fp)
* `b` (Fp)
* `perm` (Fp)
* `zeta_to_domain_size`, `zeta_to_srs_length` (Fp)
* the new bulletproof challenges (used internally for the accumulator check, not for packing)

This intermediate is never serialized in our flow — `expand_deferred` runs and its outputs feed straight into the packing step.

### Packed Statement

The 40-element `Vec<Fq>` that kimchi's verifier consumes as the wrap proof's *public input*. Built by `assemble_wrap_main_input`. Layout:

| slots | what |
|---|---|
| 0..5 | shifted-to-Fq cross-field encodings of the 5 expanded Fp values |
| 5..7 | beta, gamma (raw 128-bit packed) |
| 7..10 | alpha, zeta, xi (scalar challenges) |
| 10..13 | three Poseidon digests (sponge / msgs-for-next-wrap / msgs-for-next-step) |
| 13..29 | 16 bulletproof challenges |
| 29 | branch_data (8 bits proofs_verified + 8 bits domain_log2 packed) |
| 30..38 | feature flag bits (8 — none used by typical wrap circuits) |
| 38..40 | lookup opt flag + opt scalar challenge (zero for typical circuits) |

This is what the *wrap circuit* asserts its derivations equal, and what the *verifier* must hand kimchi.

### Wrap kimchi proof

The kimchi `ProverProof<Pallas>` produced by the wrap circuit. Lives separately from the statement (in `wrap_proof_bN.bin`). Contains:
* commitments (`w_comm`, `z_comm`, `t_comm`, `lookup`)
* opening proof (`L`, `R`, `delta`, `z1`, `z2`, `sg`)
* polynomial evaluations
* `ft_eval1`
* `prev_challenges` field — but this is *empty* in our msgpack (`Wrap_hack.pad_accumulator` data is reconstructed by the Rust verifier from the statement; see below)

### Dummy sg

`Wrap_hack.pad_accumulator` always front-pads `prev_challenges` to length 2 with `(Dummy.Ipa.Wrap.sg, Dummy.Ipa.Wrap.challenges_computed)`. The Pallas point `dummy_sg` is the IPA accumulator commitment of the dummy challenges, computed as `MSM(b_poly_coefficients(dummy_chals), srs.g)`. Function only of the (fixed) wrap SRS. The host computes it once and stuffs it into the wrap proof's `prev_challenges` before shipping the proof bytes to the guest.

### VK commitments

The 28 single-chunk Pallas points pulled out of the kimchi `VerifierIndex` in `index_to_field_elements` order (7 sigma + 15 coefficient + 6 standalone). They feed into `hash_messages_for_next_step_proof` along with `app_state`. Constant per circuit — also baked.

### `app_state`

The application circuit's public input (a `Vec<Fp>`). Lives in `messages_for_next_step_proof.app_state`. This is what the SP1 guest commits as part of `CommitOutput` so the Groth16 wrapper can read it.

## Per-artifact origins

| artifact | produced by | size (b0) | constancy |
|---|---|---|---|
| `simple_chain_wrap_vi.bin` | `Pickles.Verification_key.index` → `Kimchi_bindings.Protocol.VerifierIndex.Fq.write` | ~1.5 KB | per-circuit constant |
| `simple_chain_wrap_srs.bin` | `index.srs` → `Kimchi_bindings.Protocol.SRS.Fq.write` | ~1.1 MB | per-circuit constant |
| `simple_chain_proof_repr_bN.json` | `Pickles.Proof.Make(Nat.N1).to_yojson_full` + app_state splice | ~25 KB | per-iteration |
| `simple_chain_wrap_proof_bN.bin` | `Wrap_wire_proof.to_kimchi_proof` → `to_backend_with_public_evals' [] [||]` → `Kimchi_bindings.Protocol.Proof.Fq.write` | ~5 KB | per-iteration |

## Stage-by-stage transformations

### Build time (`crates/o1-verifier/build.rs`)

1. Read `simple_chain_wrap_vi.bin` + `simple_chain_wrap_srs.bin` from `SIMPLE_CHAIN_FIXTURES_DIR`.
2. Extract `vk_commitments` via `WrapVkCommitments::extract(&vi)`.
3. Copy VI/SRS bytes and serialize `vk_commitments` into `OUT_DIR`. The guest `include_bytes!`s them.

### Host (`crates/o1-verifier-host/src/main.rs`)

Two subcommands:

* **`o1zkvm verify`** — runs the full SP1 attestation:
  1. Read `proof_repr_bN.json` and re-encode to canonical msgpack via `parse::canonical_proof_repr_msgpack`. This *exact* byte string is what the guest hashes for `statement_digest`.
  2. Lower to domain types via `parse::parse_proof_repr_json` and run `host_precompute(stmt, prev_evals)` — that's where `expand_deferred` + `hash_messages_for_next_wrap_proof` actually run, in std-land.
  3. Populate `wrap_proof.prev_challenges` (mirroring `Wrap_hack.pad_accumulator`) and re-encode the proof bytes.
  4. Feed three msgpack blobs into the guest via stdin: the canonical proof_repr, the proof with prev_challenges populated, and the precomputed-values blob.
  5. Read back `CommitOutput`. Sanity-check the digest against a host-side SHA-256 over the same canonical bytes (the guest precompile and the host crate produce the same value for the same input).

* **`o1zkvm hash --proof-repr <PATH>`** — emit `SHA-256(canonical_proof_repr_msgpack)` for a holder of a JSON statement. They compare to the SP1 commitment without re-running anything.

### Guest (`crates/o1-verifier/src/main.rs`)

Slim — only the work that *binds `app_state`* into the kimchi public input stays here:

1. **Deserialize baked constants.** `vk_commitments` from `OUT_DIR` via `CanonicalDeserialize`. VI/SRS bytes pass straight to the kimchi loader.
2. **Read runtime inputs** via `io::read_vec()`: `proof_repr_msgpack`, `wrap_proof_bytes` (already with `prev_challenges` populated), `host_precomputed_msgpack`.
3. **SHA-256 the proof_repr msgpack** via SP1's precompile-patched `sha2::Sha256` → `statement_digest`. (~9.5 cycles per 64-byte block.)
4. **rmp-decode + lower.** `parse::parse_proof_repr_msgpack` yields a `ParsedProofRepr`; we use only `.statement` since `expand_deferred` already ran on the host.
5. **Compute `step_messages_digest_fp`.** Poseidon over `app_state` + the baked `vk_commitments` + `step_prev_proofs` from the statement. This is the only Poseidon call in the guest, and the only piece of binding that *can't* move to the host: `app_state` flows through this digest into the kimchi public input.
6. **Pack.** `assemble_wrap_main_input` combines the host-supplied expanded values + the Poseidon digest we just computed + raw challenges from the statement into the 40-element `Vec<Fq>`.
7. **kimchi verify.** `kimchi::verifier::verify(group_map, vi, wrap_proof, packed)`. Wrong host-supplied values → kimchi rejects (the wrap circuit re-derives them internally and the equalities fail).
8. **Commit.** `CommitOutput { valid, app_state, statement_digest }`.

## Why doesn't the guest run `expand_deferred`?

The wrap proof was generated against the *expanded* statement — kimchi already saw those values when it committed to the wrap circuit's public input at proving time. Internally, pickles' next step circuit reads them too: in a chain b0 → b1, the expanded values from b0 enter b1's witness, and b1's step circuit asserts they match what's in b0's wrap-proof public input.

So three places already produce this expansion:

1. **Wrap circuit at proving time** — derives the expanded values from witnessed (minimal statement + evals) and binds them into its public input slots, which kimchi commits to.
2. **Next step circuit when consuming the proof recursively** — re-derives the same values and asserts equality with what's in the wrap proof's public input slots, to prove it knows the statement honestly.
3. **Anyone reconstructing the kimchi public input from the on-disk minimal form** — needs to redo it because `Pickles.Proof.t` only serializes the minimal statement.

For (3), a verifier is just trying to figure out *what to feed kimchi*. If kimchi accepts, the wrap circuit's internal re-derivation matches whatever we packed. So an external party who computes the expansion on the **host side** and hands it to the guest is sound — kimchi rejects any lie. Moving (3) to the host is what makes the guest small.

The `app_state`-binding Poseidon (step messages digest) is the one piece that *can't* move: if the host computed it and lied, the guest's `app_state` commitment would be unmoored from what kimchi actually verified. So that hash stays in-zkVM.

## Trust boundaries

| boundary | trusts | verifies |
|---|---|---|
| Build-time constants (`vk_commitments`) | the fixtures + Rust helpers | nothing dynamic; computed once and baked |
| Host → Guest | the wire format (rmp roundtrip) | nothing — host is untrusted with respect to the SP1 attestation |
| Guest → kimchi verifier | the packed input being well-formed | the wrap proof against the packed input |
| Guest → end verifier | the SP1 proof system | reads `(valid, app_state, statement_digest)` as public output |

The host can hand the guest *any* bytes. If they're bogus, parsing fails (commits `valid=false`) or kimchi rejects (commits `valid=false`). If they parse and verify, kimchi has accepted a wrap proof whose `app_state` is what the guest commits.

## Pickles-untouched constraints

Two constraints shape this design:

1. **`mina/src/lib/crypto/pickles/{pickles.ml, pickles_intf.mli}` stay vanilla.** Internal modules (`Wrap_deferred_values`, `Common`, `Wrap_hack`, `Endo`, `Reduced_messages_for_next_proof_over_same_field`, `Challenge`, `Scalar_challenge`, `Ipa`) cannot be called from outside the pickles library. Any helper that needs them lives in our Rust port instead.

2. **`simple_chain.ml` is fair game** — it's an example, not the library. It only uses the public Pickles API plus `Pickles.Backend.Tock.Proof.to_backend_with_public_evals'` for emitting the kimchi proof bytes. It deliberately writes empty `chal_polys` and `primary_input`; the Rust side reconstructs `prev_challenges` and packs its own public input.

Consequence: things that were OCaml-side fixtures derived from internal pickles helpers (`simple_chain_wrap_public_input_bN.json`, `simple_chain_wrap_debug_intermediates_bN.json`) were retired when we reverted those internal-module-touching helpers. Kimchi acceptance per iteration is now the source of truth.

## Soundness summary

What does the Groth16-wrapping end-verifier learn when it sees a valid SP1 proof committing `CommitOutput { valid: true, app_state: X, statement_digest: D }`?

That somewhere, *some* prover ran the SP1 guest with input bytes whose canonical `proof_repr` msgpack hashed to `D`, and:

1. Those bytes parsed cleanly into a wrap proof and statement.
2. The `host_precompute` outputs the host supplied (cip, b, perm, zeta_to_*, wrap-side digest) were the *unique* values consistent with that proof — kimchi rejects any others, since the wrap circuit re-derives them internally and asserts equality against the public input.
3. The Poseidon hash the guest itself computed over `(vk_commitments, X, step_prev_proofs)` is what the wrap circuit's public input contains at the step-digest slot.
4. kimchi accepted the wrap proof against the resulting 40-Fq packed input *under the baked VI/SRS*.

Together these imply: a holder of the *original* `proof_repr_bN.json` can recompute `D = SHA-256(canonical_msgpack(file))` locally (via `o1zkvm hash`), match it against the SP1 commitment, and conclude "this attestation is for *my* statement," and the `app_state` in the commitment is the application-level public input that wrap proof was actually built against.
