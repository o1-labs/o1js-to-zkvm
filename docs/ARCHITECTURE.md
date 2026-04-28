# Architecture: Simple_chain wrap-proof verification in SP1

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


  ┌──────────────┐     ┌─────────┐     ┌──────────────────────┐
  │   build.rs   │     │  Host   │     │   Guest (SP1)        │
  │              │     │ o1zkvm  │     │   o1-verifier        │
  └──────┬───────┘     └────┬────┘     └─────────┬────────────┘
         │                  │                    │
   bakes constants:         │                    │
   - VI/SRS bytes           │                    │
   - dummy_sg (Pallas)      │                    │
   - vk_commitments         │                    │
         │                  │                    │
         └──────► OUT_DIR ──┼──────────►  include_bytes!
                            │                    │
                            │  parses JSON,      │
                            │  rmp-encodes wire  │
                            │                    │
                            └──── stdin ────────►│
                                                 │
                                            verify pipeline
                                                 │
                                                 ▼
                                          CommitOutput {
                                            valid: bool,
                                            app_state: Vec<Fp>,
                                          }
                                                 │
                            (Groth16 wrapper consumes this)
```

## Terminology

Different people use overlapping words for what *is* the proof's "statement". Here's how this codebase uses them, smallest representation to largest:

### Statement (Minimal)

The shape OCaml's `Pickles.Proof.t` natively serializes. Type:

* **OCaml**: `Composition_types.Wrap.Statement.Minimal.t`
* **Rust wire**: `wire::StatementWire` (`crates/o1-pickles-verifier/src/wire.rs`)
* **Rust domain**: `statement::WrapStatement` (`crates/o1-pickles-verifier/src/statement.rs`)

Carries:
* the **plonk minimal challenges** (alpha, beta, gamma, zeta, xi, joint_combiner) as raw 128-bit values
* the **bulletproof challenges** as raw 128-bit values
* the **branch_data** (proofs_verified tag + domain_log2)
* the **two messages-for-next-* records** (sg commitments + raw bp prechallenges + app_state)
* the **sponge_digest_before_evaluations**

What it does *not* carry: the expanded values (`combined_inner_product`, `b`, `perm`, `zeta_to_*`). Those were computed inside the wrap circuit; the minimal form drops them and counts on the verifier to re-derive them.

### Prev evals

The polynomial evaluations from the *step* proof underneath the wrap proof — `(at_zeta, at_zeta_omega)` pairs for every kimchi polynomial column, plus `ft_eval1`. Lives next to the statement under `prev_evals` in the proof-repr JSON.

* **OCaml**: `Plonk_types.All_evals.t`
* **Rust wire**: `wire::PrevEvalsWire`
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
| 30..38 | feature flag bits (8 — all zero for Simple_chain) |
| 38..40 | lookup opt flag + opt scalar challenge (zeros for Simple_chain) |

This is what the *wrap circuit* asserts its derivations equal, and what the *verifier* must hand kimchi.

### Wrap kimchi proof

The kimchi `ProverProof<Pallas>` produced by the wrap circuit. Lives separately from the statement (in `wrap_proof_bN.bin`). Contains:
* commitments (`w_comm`, `z_comm`, `t_comm`, `lookup`)
* opening proof (`L`, `R`, `delta`, `z1`, `z2`, `sg`)
* polynomial evaluations
* `ft_eval1`
* `prev_challenges` field — but this is *empty* in our msgpack (`Wrap_hack.pad_accumulator` data is reconstructed by the Rust verifier from the statement; see below)

### Dummy sg

`Wrap_hack.pad_accumulator` always front-pads `prev_challenges` to length 2 with `(Dummy.Ipa.Wrap.sg, Dummy.Ipa.Wrap.challenges_computed)`. The Pallas point `dummy_sg` is the IPA accumulator commitment of the dummy challenges, computed as `MSM(b_poly_coefficients(dummy_chals), srs.g)`. Function only of the (fixed) wrap SRS — baked into the guest at build time.

### VK commitments

The 28 single-chunk Pallas points pulled out of the kimchi `VerifierIndex` in `index_to_field_elements` order (7 sigma + 15 coefficient + 6 standalone). They feed into `hash_messages_for_next_step_proof` along with `app_state`. Constant per circuit — also baked.

### `app_state`

The application circuit's public input (a `Vec<Fp>`). For Simple_chain that's `[initial, current]`. Lives in `messages_for_next_step_proof.app_state`. This is what the SP1 guest commits as part of `CommitOutput` so the Groth16 wrapper can read it.

## Per-artifact origins

| artifact | produced by | size (Simple_chain b0) | constancy |
|---|---|---|---|
| `simple_chain_wrap_vi.bin` | `Pickles.Verification_key.index` → `Kimchi_bindings.Protocol.VerifierIndex.Fq.write` | ~1.5 KB | per-circuit constant |
| `simple_chain_wrap_srs.bin` | `index.srs` → `Kimchi_bindings.Protocol.SRS.Fq.write` | ~1.1 MB | per-circuit constant |
| `simple_chain_proof_repr_bN.json` | `Pickles.Proof.Make(Nat.N1).to_yojson_full` + app_state splice | ~25 KB | per-iteration |
| `simple_chain_wrap_proof_bN.bin` | `Wrap_wire_proof.to_kimchi_proof` → `to_backend_with_public_evals' [] [||]` → `Kimchi_bindings.Protocol.Proof.Fq.write` | ~5 KB | per-iteration |

## Stage-by-stage transformations

### Build time (`crates/o1-verifier/build.rs`)

1. Read `simple_chain_wrap_vi.bin` + `simple_chain_wrap_srs.bin` from `SIMPLE_CHAIN_FIXTURES_DIR`.
2. Compute `dummy_sg` via `compute_dummy_wrap_sg(&srs)`.
3. Extract `vk_commitments` via `WrapVkCommitments::extract(&vi)`.
4. Serialize all four artifacts into `OUT_DIR`. The guest `include_bytes!`s them.

### Host (`crates/o1-verifier-host/src/main.rs`)

Stateless shuttle:

1. Read `proof_repr_bN.json` → `ProofReprWire` (`serde_json::from_str`).
2. Re-encode → msgpack bytes (`rmp_serde::to_vec`).
3. Read `wrap_proof_bN.bin` as raw bytes.
4. Send both via `SP1Stdin::write`. Read `CommitOutput` on the way back.

The host deliberately doesn't lower wire → domain — the guest does that. This keeps the host's input shape stable as we evolve domain types.

### Guest (`crates/o1-verifier/src/main.rs`)

Per-call:

1. **Deserialize baked constants.** `dummy_sg`, `vk_commitments` from `OUT_DIR` via `CanonicalDeserialize`. The VI/SRS bytes are passed straight to the kimchi loader.
2. **Read runtime inputs.** `proof_repr_msgpack` + `wrap_proof_bytes` from stdin.
3. **rmp-decode + lower.** `ProofReprWire` → `WrapStatement` (`parse_wrap_statement`) and `ParsedPrevEvals` (`parse_prev_evals`). Decode `PallasProof` from the wrap-proof bytes.
4. **Reconstruct `prev_challenges`.** The msgpack proof has empty `prev_challenges`; we override with `(dummy_sg, dummy_chals)` + `(real_sg, expanded_real_chals)` mirroring `Wrap_hack.pad_accumulator`. See `messages::build_simple_chain_prev_challenges`.
5. **Compute the expanded statement.** `expand_deferred` derives `cip`, `b`, plonk's `perm`/`zeta_to_*`, and a few internal-only fields.
6. **Hash both messages-for-next-* digests.** Poseidon over Fp (step) and Fq (wrap), inputs include `vk_commitments`, `app_state`, and the prior step proof's accumulator data.
7. **Pack.** `assemble_wrap_main_input` flattens the expanded statement + digests + raw challenges into the 40-element `Vec<Fq>`.
8. **kimchi verify.** `kimchi::verifier::verify(group_map, vi, wrap_proof, packed)`.
9. **Commit.** `CommitOutput { valid, app_state }`.

## Why does the verifier run `expand_deferred`?

The wrap circuit *also* runs the same expansion internally and asserts the result equals what's in its public input. Two independent runs of the same computation, bound by the equality constraint inside the circuit:

* **Wrap circuit's run** binds the prover honest: "the expanded values you committed to in the public input are derived from the minimal values + evals according to `expand_deferred`."
* **Verifier's run** is what gives kimchi the public input it needs to check the proof: "I claim the public input is *this 40-element vector*; verify it matches the proof."

If the verifier supplied wrong expanded values, kimchi would reject — the wrap circuit's internal derivation would differ from the public input we provided. So the redundancy *is* the soundness binding from the verifier's side.

The minimal form is what `Pickles.Proof.t` natively carries (it has to be — for the *next* iteration of the chain, only the minimal form is small enough to forward as part of the recursive statement). The verifier re-derives the expansion. There's no shortcut available without modifying pickles to expose `Wrap_deferred_values.expand_deferred` outside the library.

## Trust boundaries

| boundary | trusts | verifies |
|---|---|---|
| Build-time constants (`dummy_sg`, `vk_commitments`) | the fixtures + Rust helpers | nothing dynamic; computed once and baked |
| Host → Guest | the wire format (rmp roundtrip) | nothing — host is untrusted with respect to the SP1 attestation |
| Guest → kimchi verifier | the packed input being well-formed | the wrap proof against the packed input |
| Guest → end verifier | the SP1 proof system | reads `(valid, app_state)` as public output |

The host can hand the guest *any* bytes. If they're bogus, parsing fails (commits `valid=false`) or kimchi rejects (commits `valid=false`). If they parse and verify, kimchi has accepted a wrap proof whose `app_state` is what the guest commits.

## Pickles-untouched constraints

Two constraints shape this design:

1. **`mina/src/lib/crypto/pickles/{pickles.ml, pickles_intf.mli}` stay vanilla.** Internal modules (`Wrap_deferred_values`, `Common`, `Wrap_hack`, `Endo`, `Reduced_messages_for_next_proof_over_same_field`, `Challenge`, `Scalar_challenge`, `Ipa`) cannot be called from outside the pickles library. Any helper that needs them lives in our Rust port instead.

2. **`simple_chain.ml` is fair game** — it's an example, not the library. It only uses the public Pickles API plus `Pickles.Backend.Tock.Proof.to_backend_with_public_evals'` for emitting the kimchi proof bytes. It deliberately writes empty `chal_polys` and `primary_input`; the Rust side reconstructs `prev_challenges` and packs its own public input.

Consequence: things that were OCaml-side fixtures derived from internal pickles helpers (`simple_chain_wrap_public_input_bN.json`, `simple_chain_wrap_debug_intermediates_bN.json`) were retired when we reverted those internal-module-touching helpers. Kimchi acceptance per iteration is now the source of truth.

## Soundness summary

What does the Groth16-wrapping end-verifier learn when it sees a valid SP1 proof committing `CommitOutput { valid: true, app_state: X }`?

That somewhere, *some* prover ran the SP1 guest with *some* pair of (proof_repr_msgpack, wrap_proof_bytes), and:

1. The bytes parsed cleanly into a Simple_chain wrap proof and statement.
2. Running `expand_deferred` + Poseidon-hashing-with-the-baked-`vk_commitments` produced a 40-Fq packed input.
3. kimchi accepted that wrap proof against that packed input *under the baked VI/SRS*.
4. The `app_state` in the statement is the `X` it committed.

Steps 1–3 transitively imply: the wrap circuit's witness derives the same expanded values from the minimal statement, those expanded values match what we packed (because kimchi accepted), and the messages-for-next-step digest in the packed input was derived from the *same* `vk_commitments` and `app_state` as the guest used to compute it. So the Groth16 layer's view of `app_state` corresponds to the actual application state attested by the wrap proof.
