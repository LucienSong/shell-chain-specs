# shell-chain Implementation Specifications

Implementation-facing specifications for `shell-chain` live in this directory.
They are intended to stand on their own without requiring outside documents for basic repository context.

## Role in the Current Phase

`shell-chain` is in the **MVP** phase, with a local reference harness now built on the earlier docs-and-scaffold foundation.
In this phase, the specs remain the implementation source of truth for:

- crate and module boundaries,
- Rust-facing data types and codec expectations,
- validation order and error surfaces,
- fixture ownership across `vectors/` and `crates/shell-fixtures/`.

The current goal is still not to claim a finished node. The goal is to keep the protocol coherent enough that the MVP-local harness proves the intended flow without overstating the surface.

The strengthened MVP harness now covers more than the original scaffold: repository-local tests exercise fail-fast scenario integrity, fail-closed adapter handling for altered gossip inputs, the current multi-authorization `RequireAll` rule across admission and block import, and witness-failure propagation into typed reject outcomes. Those tests strengthen the local reference claim without widening the phase boundary beyond MVP.

## Phase Roadmap

| Phase | What the specs must do |
|---|---|
| **docs-and-scaffold** | Define the protocol shape clearly enough to drive scaffolding, fixtures, and validation order. |
| **MVP** | Support a local end-to-end reference flow without hand-waving crate responsibilities, while keeping `shell-cli` limited to thin local harness wiring. |
| **Testnet** | Expand into adversarial networking and operator realities without breaking the documented core model. |
| **Mainnet** | Stabilize around production operation while preserving the PQ-native design from genesis. |

## Scope

The specs in this directory describe how the planned Rust implementation should be organized and where responsibilities should live.
They focus on implementation contracts such as:

- crate and module boundaries,
- Rust-facing data types and codec expectations,
- validation order and error surfaces,
- future testing-vector responsibilities,
- and the boundary that any MVP `shell-cli` remains fixture-runner/local-wiring glue instead of an operator, RPC, or production-runtime surface.

When a protocol detail is still unsettled, the local specs mark it as pending rather than inventing a finalized rule. The same applies to `shell-cli`: MVP-local harness behavior can be described only as repository-local reference wiring, not as a stable external API or node contract. Witness/proof encoding details, validator credential modeling, richer multi-authorization semantics beyond the current `RequireAll` rule, and non-testnet operator/networking surfaces must stay explicit as provisional or deferred until later phases close them.
The four core specs below remain `draft` because MVP bootstrap work is still about proving the local path before claiming broader operational maturity.

## Shared Protocol Context

The documents here assume the following core ideas throughout the repository:

- **Envelope and sidecar separation**: transaction payloads and the larger witness data needed for stateless checks are modeled as related but distinct objects.
- **Canonical SSZ behavior**: wire-facing objects must preserve exact SSZ (SimpleSerialize) encode/decode and merkleization behavior.
- **PQ-capable authorization paths**: signature verification is dispatched through a scheme-aware abstraction for post-quantum-capable signing instead of hard-coding a legacy signature family.
- **Cheap-first validation**: structural decoding, root checks, and fee-floor checks happen before expensive proof reconstruction or heavy execution.
- **Unified state accumulator**: state access proofs target a compressed binary-tree style accumulator and stateless verification flow.

## Contents

| Spec | Status | Description |
|---|---|---|
| [Crate Structure](crate-structure.md) | draft | Workspace layout, dependency rules, and trait placement guidance |
| [Data Types](data-types.md) | draft | Rust-facing object model, SSZ bindings, and state/witness types |
| [Validation Rules](validation-rules.md) | draft | Transaction, block, and peer-handling validation flow |
| [Testing Vectors](testing-vectors.md) | draft | Vector matrix, fixture guidance, and invariant ownership |

## Reading Order

For the full newcomer path, read `README.md`, then `docs/getting-started.md`, then `docs/api-reference.md`, then continue here:

1. `crate-structure.md` for planned package boundaries
2. `data-types.md` for the object model
3. `validation-rules.md` for runtime flow and error handling
4. `testing-vectors.md` for fixture ownership and future verification obligations

When you are ready to make a repository change, continue with `docs/contributing.md`.
