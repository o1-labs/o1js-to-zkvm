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
                          GuestOutput {                  │
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

The host CLI also exposes `o1zkvm hash --proof-repr <PATH>`: it emits `SHA-256(canonical_proof_repr_msgpack)` from a JSON statement on disk so a holder can match it against the `statement_digest` in a `GuestOutput` without re-running the verifier.

## Terminology

Different people use overlapping words for what *is* the proof's "statement". Here's how this codebase uses them, smallest representation to largest:

### Statement (Minimal)

The form `Pickles.Proof.t` carries — both in memory and serialized. The expanded deferred values (`combined_inner_product`, `b`, `perm`, `zeta_to_*`) live in the wrap circuit's public-input slots (kimchi commits to them), but pickles never stores them in `Proof.t`: they're computed transiently from the minimal statement plus `prev_evals` whenever needed.

In a normal pickles chain the *next* step circuit recomputes them as advice (private witness) and asserts they match the wrap proof's public input. In our setup the guest verifies the wrap proof, so the host recomputes them via `expand_deferred` and passes the results in. The guest then packs them into the kimchi public input the same way the wrap circuit did at proving time. This is sound because the wrap circuit asserts each expanded value equals what it recomputes from the witness (see `Wrap_verifier.finalize_other_proof` in `mina/src/lib/crypto/pickles/wrap_verifier.ml`), so any lie fails an in-circuit equality and kimchi rejects.

Carries:
* plonk minimal challenges (alpha, beta, gamma, zeta, xi, joint_combiner) as raw 128-bit values
* bulletproof challenges as raw 128-bit values
* `branch_data` (proofs_verified tag + domain_log2)
* the two `messages-for-next-*` records (sg commitments + raw bp prechallenges + app_state)
* `sponge_digest_before_evaluations`

Types:
* **OCaml**: `Composition_types.Wrap.Statement.Minimal.t`
* **Rust wire**: private (`crates/o1-pickles-verifier/src/parse/wire.rs`)
* **Rust domain**: `statement::WrapStatement` (`crates/o1-pickles-verifier/src/statement.rs`)

### Prev evals

The polynomial evaluations from the *step* proof underneath the wrap proof — `(at_zeta, at_zeta_omega)` pairs for every kimchi polynomial column, plus `ft_eval1`. Lives next to the statement under `prev_evals` in the proof-repr JSON.

* **OCaml**: `Plonk_types.All_evals.t`
* **Rust wire**: private (`crates/o1-pickles-verifier/src/parse/wire.rs`)
* **Rust domain**: `parse::ParsedPrevEvals`

### Expanded Statement

What you get after running `expand_deferred` on `(statement, prev_evals)` — the same set of values the wrap circuit's prover computed transiently in-circuit to fill the public-input slots. Same shape as the minimal statement *plus* the derived deferred values:

* `combined_inner_product` (Fp)
* `b` (Fp)
* `perm` (Fp)
* `zeta_to_domain_size`, `zeta_to_srs_length` (Fp)
* the new bulletproof challenges (used internally for the accumulator check, not for packing)

Like in pickles itself, this form is never serialized — `expand_deferred` runs and its outputs feed straight into the packing step.

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

The kimchi `ProverProof<Pallas>` produced by the wrap circuit. Lives separately from the statement (in `wrap_proof_bN.bin`). Contains the standard kimchi-proof fields (commitments, opening proof, polynomial evaluations, `ft_eval1`) plus a `prev_challenges` field. That field is empty in our msgpack — its contents are pickles padding (`Wrap_hack.pad_accumulator`) determined by the statement and the wrap SRS, so the host fills it in deterministically before shipping the proof to the guest.

### VK commitments

The 28 single-chunk Pallas points pulled out of the kimchi `VerifierIndex` in `index_to_field_elements` order (7 sigma + 15 coefficient + 6 standalone). They feed into `hash_messages_for_next_step_proof` along with `app_state`. Constant per circuit — also baked.

### `app_state`

The application circuit's public input (a `Vec<Fp>`). Lives in `messages_for_next_step_proof.app_state`. The guest commits it as part of `GuestOutput` so the Groth16 wrapper can read it.

## Per-artifact origins

| artifact | produced by | size (b0) | constancy |
|---|---|---|---|
| `simple_chain_wrap_vi.bin` | `Pickles.Verification_key.index` → `Kimchi_bindings.Protocol.VerifierIndex.Fq.write` | ~1.5 KB | per-circuit constant |
| `simple_chain_wrap_srs.bin` | `index.srs` → `Kimchi_bindings.Protocol.SRS.Fq.write` | ~1.1 MB | per-circuit constant |
| `simple_chain_proof_repr_bN.json` | `Pickles.Proof.Make(Nat.N1).to_yojson_full` + app_state splice | ~25 KB | per-iteration |
| `simple_chain_wrap_proof_bN.bin` | `Wrap_wire_proof.to_kimchi_proof` → `to_backend_with_public_evals' [] [||]` → `Kimchi_bindings.Protocol.Proof.Fq.write` | ~5 KB | per-iteration |

## Why doesn't the guest run `expand_deferred`?

The wrap proof was generated against the *expanded* statement — kimchi already saw those values when it committed to the wrap circuit's public input at proving time. Pickles' next step circuit also reads them: when one wrap proof feeds into the next step in a chain, that step circuit takes the expanded values as private witness and asserts they match the wrap proof's public input.

So three places already produce this expansion:

1. **Wrap circuit at proving time** — derives the expanded values from witnessed (minimal statement + evals) and binds them into its public input slots, which kimchi commits to.
2. **Next step circuit when consuming the proof recursively** — re-derives the same values and asserts equality with what's in the wrap proof's public input slots, to prove it knows the statement honestly.
3. **Anyone reconstructing the kimchi public input from the on-disk minimal form** — needs to redo it because `Pickles.Proof.t` only serializes the minimal statement.

For (3), a verifier is just trying to figure out *what to feed kimchi*. If kimchi accepts, the wrap circuit's internal re-derivation matches whatever we packed. So an external party who computes the expansion on the **host side** and hands it to the guest is sound — kimchi rejects any lie. Moving (3) to the host is what makes the guest small.

The `app_state`-binding Poseidon (step messages digest) is the one piece that *can't* move: if the host computed it and lied, the guest's `app_state` commitment would be unmoored from what kimchi actually verified. So that hash stays in the guest.

## What does a verifier need?

Two actors:

* **Operator** runs the entire prover pipeline — OCaml `simple_chain`, the host CLI, the SP1 prover, the Groth16 wrapper. They publish two anchor artifacts so others can verify their proofs without trusting them:
  * the SP1 **vkey** — a hash that commits to the compiled `o1-verifier` guest binary. The wrap VI and SRS are baked into the guest at build time, so this single hash commits to the entire verification program.
  * the **Groth16 verification key** for the wrapped SP1 program.

  The operator can also publish the `o1-verifier` source so verifiers can rebuild it and confirm the resulting SP1 vkey matches.

* **Verifier** holds the same minimal wrap statement that OCaml's `Pickles.Proof.t` carries (its `statement` field, of type `Composition_types.Wrap.Statement.Minimal.t`; see [Statement (Minimal)](#statement-minimal)) plus the `app_state` they care about. They want to receive a proof from the operator and check that it attests to *their* statement and `app_state`, without trusting the operator or running any part of the prover pipeline.

The verifier needs only:

1. The operator's published anchors (Groth16 VK + SP1 vkey), audited via rebuild against published source.
2. A way to recompute the `statement_digest` from their copy of the statement. The digest is the SHA-256 of a canonical msgpack encoding of the statement; the `o1zkvm hash` subcommand emits it, and any independent reimplementation of the canonicalization rules works equally well.
3. An off-the-shelf Groth16 verifier.

Per-proof workflow:

1. Operator sends a Groth16 proof plus its public values.
2. Verifier runs Groth16 verification against the published VK. If it passes, the SP1 attestation is valid for the program pinned by the published SP1 vkey.
3. Verifier reads `GuestOutput { valid, app_state, statement_digest }` from the public values.
4. Verifier checks: `valid` is true, `app_state` matches their copy, and `statement_digest` matches the digest they computed from their copy of the statement.

All four passing means the operator's wrap proof for the verifier's exact statement and `app_state` was accepted by kimchi under the program the verifier audited. The verifier never runs the host, the guest, or the OCaml binary.