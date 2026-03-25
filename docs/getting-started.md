# Getting Started

> Quick orientation for reading and contributing to `shell-chain`.

## Current Phase at a Glance

`shell-chain` is in the **MVP** phase, specifically an MVP-local bootstrap state built on the earlier docs-and-scaffold work.

**Purpose**

Prove a local end-to-end reference flow from repository-local docs, specs, fixtures, and crate wiring.

**What that means today**

- The repository is still docs-first and built around post-quantum assumptions from genesis.
- The Rust workspace contains real crates for fixtures, primitives, crypto, state, execution, mempool, consensus, network boundaries, and the thin `shell-cli` harness.
- `crates/shell-cli/` is a local reference harness crate, not a user-facing node.
- Fixtures live in both `vectors/` and `crates/shell-fixtures/`, with 58 repository-local vectors currently exercising the documented contracts.
- The current harness proves one local reference flow: admit fixture-backed transactions, verify witness/state continuity, execute planned transitions, and import a block against documented roots.
- Harness coverage now also proves that scenario-shape mismatches fail before expensive work, missing authorization material and altered gossip payloads fail closed, the current multi-authorization rule is `RequireAll`, and witness failures remain typed rejects instead of leaking into implicit transport behavior.

**Still out of scope before testnet**

- claiming a runnable node,
- documenting stable operator or RPC behavior,
- implying multi-node networking or operator lifecycle support,
- freezing protocol details that still need spec-first iteration,
- adding legacy migration assumptions that fight the post-quantum design direction.

## Phase Roadmap

| Phase | Purpose | Exit conditions | Do not do too early |
|---|---|---|---|
| **docs-and-scaffold** | Lock protocol shape, crate boundaries, validation order, and fixture ownership. | Docs, specs, and workspace scaffolding agree closely enough to support a local reference flow. | Do not overstate maturity or ship operator/runtime claims before the harness exists. |
| **MVP** | Prove the protocol end to end locally. | Local block and transaction flow works against documented fixtures, with `shell-cli` limited to thin fixture-runner and local-wiring tasks if it exists. | Do not market it as production-ready, treat `shell-cli` as operator/RPC surface, or optimize away clarity. |
| **Testnet** | Exercise adversarial networking and operator use. | Multi-node behavior and operator workflows are tested under stress. | Do not make mainnet promises or freeze unstable surfaces. |
| **Mainnet** | Launch a stable production chain with post-quantum assumptions from genesis. | Network behavior, releases, and operator procedures are stable enough for production. | Do not dilute the post-quantum design into a migration retrofit. |

## Recommended Reading Path

If you are starting fresh, use the repository in this order:

1. `README.md` for the project overview and phase model
2. `docs/getting-started.md` for orientation and terminology
3. `docs/api-reference.md` for the conceptual public surface
4. `specs/README.md` for the implementation-spec index
5. `specs/crate-structure.md` for crate and dependency boundaries
6. `specs/data-types.md` for the Rust-facing object model
7. `specs/validation-rules.md` for validation order and failure handling
8. `specs/testing-vectors.md` for fixture planning and invariant ownership
9. `docs/contributing.md` before opening a change

If terms like SSZ, witness sidecars, or post-quantum authorization are new, read them here as shorthand for canonical SimpleSerialize encoding, proof-heavy side data kept separate from executable envelopes, and post-quantum-capable signature handling.

## Workspace Overview

The intended architecture is organized around explicit boundaries:

- **`shell-fixtures`** for shared fixture helpers and test-vector support
- **`shell-primitives`** for SSZ-facing types, roots, and canonical codec helpers
- **`shell-crypto`** for hashing and signature-dispatch abstractions
- **`shell-state`** for witnesses, state keys, and accumulator verification
- **`shell-execution`** for state-transition execution logic
- **`shell-mempool`** for transaction admission and fee-policy checks
- **`shell-consensus`** for block assembly and import orchestration
- **`shell-network`** for propagation, fetch policy, and peer consequences
- **`shell-cli`** for thin MVP-local fixture running, local wiring, and reference adapters only; operator-facing entry points come later

All nine items above are real workspace crates today. `shell-cli` remains intentionally limited to a thin local harness rather than an operator, RPC, transport, or runtime node surface.

## Validation Expectations

The current repository-local baseline commands are:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

For documentation-only changes, the minimum bar is still to keep links, terminology, stated maturity, and claimed harness coverage aligned with the actual repository.

## First Contribution Checklist

Before opening a change, confirm that:

- the explanation is self-contained inside this repository,
- planned components are labeled as planned,
- current limits are stated honestly,
- docs and specs still agree on phase, scope, and ownership,
- the change reinforces a docs-first, post-quantum design rather than a migration retrofit.
