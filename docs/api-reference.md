# API Reference

> Conceptual public API reference for the future `shell-chain` Rust workspace.

## How to Read This Document

`shell-chain` is in an **MVP-local bootstrap** state. This file describes the public-facing boundaries the repository now proves locally and the larger surfaces that still remain intentionally absent.

- Treat the crate responsibilities below as the stable direction.
- Treat concrete type names, module placement, and final runtime entry points as still subject to refinement where the specs say so.
- Do not read this document as proof that node, RPC, or operator CLI surfaces already exist.

## Phase Alignment

| Phase | API meaning |
|---|---|
| **docs-and-scaffold** | Lock conceptual crate boundaries, object ownership, and validation entry points. |
| **MVP** | Prove those contracts work together in a local end-to-end reference flow, with `shell-cli` kept as thin harness glue for fixtures, adapters, and local wiring only. |
| **Testnet** | Add operator and networking surfaces that survive adversarial use. |
| **Mainnet** | Freeze production-facing APIs only after the PQ-native protocol is operationally credible. |

## Planned Public Surface by Area

### 1. Primitives and Wire-Facing Types

The base layer is expected to expose:

- root and byte-wrapper aliases such as `Root`, `Bytes32`, and address-sized types,
- transaction fee wrappers such as `ChainId`, `TxValue`, `GasPrice`, and `BasicFeesPerGas`,
- canonical SSZ encode/decode helpers,
- `hash_tree_root`-style helpers shared across higher layers.

This layer should remain policy-free: it owns object shape and canonical encoding, not mempool or consensus decisions.

### 2. Transaction Objects

The transaction model is expected to revolve around:

- `TransactionPayload` as the payload union,
- payload variants such as basic transfer/call and contract-creation forms,
- `Authorization` entries that bind a signature to a payload root,
- `TransactionEnvelope` as the executable object,
- signing helpers similar to `SigningData` for domain-separated signing roots.

The key API requirement is that payload encoding, decoding, and root calculation follow one canonical path so mempool, execution, and consensus code cannot disagree about what was signed.

### 3. Cryptography Interfaces

The crypto layer is expected to provide:

- a scheme-aware verification trait, similar to `SignatureVerifier`,
- a dispatcher that routes transaction-path and validator-path verification,
- scheme-local size checks and uniform verification errors,
- hashing boundaries shared with the primitives layer.

Callers should depend on stable traits rather than on concrete post-quantum libraries.

For validator-path verification, higher layers should also depend on a proposer-credential resolver boundary rather than on a concrete validator-state backend. In the current phase, the shared contract is effectively:

- input: `ProposerCredentialQuery { block_root, proposer_index_hint }`,
- output: `(scheme_id, public_key_material)`,
- ownership: resolver trait in `shell-primitives`, orchestration in `shell-consensus`, signature dispatch in `shell-crypto`.

Validator-path verification errors should continue to distinguish local transport pressure from consensus-invalid data: configurable validator-message size guards stay policy-grade, while malformed credential bytes, unsupported schemes, and cryptographic failures remain structured invalid-block or invalid-signature outcomes.

### 4. State and Witness Interfaces

The state layer is expected to expose:

- key types such as `StateKey`,
- committed witness containers such as `StateWitness`,
- transition containers such as `StatePatch`,
- accumulator-style traits for proof retrieval, transition application, and state-root reporting.

A core design goal is to keep committed transport objects separate from any optimized in-memory proof index used during execution.

### 5. Validation and Execution Boundaries

Higher layers are expected to expose structured validation entry points for:

- cheap transaction admission,
- witness and proof verification,
- heavy execution and output-root calculation,
- block import orchestration,
- peer-handling consequences for malformed versus merely excessive traffic, including `shell-network` announcement filtering, fetch policy, and reputation scaffolding.

The public contract here is mostly about clean layering and error taxonomy rather than about one monolithic "validate everything" function.

### 6. Fixtures and Conformance Inputs

The fixture surface is expected to cover:

- repository-local vectors under `vectors/`,
- reusable fixture helpers in `crates/shell-fixtures/`,
- stable ownership for which crate or spec defines each invariant.

This matters in the current phase because fixture planning is part of the API contract: imports, validation flow, and object encoding should be testable before the full runtime exists.

### 7. Local Harness Boundary and Later Operator Entry Points

Today, `shell-cli` is a repository-local Rust harness crate. Its current boundary is intentionally narrow:

- `LocalReferenceScenario` and owned fixture material for shaping documented local scenarios,
- `LocalReferenceRuntime` and `LocalReferenceFlowOutcome` for running the reference path in process,
- thin `shell-network` adapter implementations that reuse the same fixture-backed flow for typed local accept/reject outcomes.

That harness proves a local reference flow can:

- run documented fixture-backed scenarios in process,
- admit transactions through the documented mempool boundary,
- verify witnesses and state continuity before execution,
- execute planned state transitions and compare committed roots,
- import a block through the documented consensus path.

For MVP-local work, `shell-cli` stays explicitly out of scope for:

- operator lifecycle management,
- RPC server integration,
- production/runtime node startup,
- multi-node networking,
- stable external automation contracts.

Those operator-facing entry points are planned for later phases. The current `shell-cli` crate is intentionally limited to harness-local reference wiring rather than a real operator or RPC surface.

## Intentionally Absent Today

The repository does not yet provide:

- generated `cargo doc` output checked into the repository,
- versioned Rust APIs,
- runnable node binaries,
- real operator or RPC interfaces,
- a stable `shell-cli` surface beyond the thin MVP-local harness boundary.

## When This Document Should Change

Update this document when:

- a crate boundary changes,
- a public validation or fixture contract moves,
- an API becomes concrete enough to replace a conceptual description,
- a later phase introduces real operator or network surfaces that should no longer be described as planned.
