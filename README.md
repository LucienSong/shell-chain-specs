# shell-chain

> A docs-first Rust repository for a smart-contract chain designed for post-quantum security.
> The project is designed from genesis around post-quantum assumptions, not as a retrofit for a legacy chain.

## Project Phases

### Current phase: MVP

**Purpose**

Prove the protocol end to end locally with a thin reference harness while keeping the project docs-first and designed for post-quantum security from genesis.

**What exists today**

- The docs-and-scaffold foundation that locked the protocol shape, crate boundaries, validation order, and fixture plan.
- A real Rust workspace with `shell-cli`, `shell-fixtures`, `shell-primitives`, `shell-crypto`, `shell-state`, `shell-execution`, `shell-mempool`, `shell-consensus`, and `shell-network`.
- 58 shared vectors in `vectors/` plus reusable fixture helpers in `crates/shell-fixtures/`.
- Draft implementation specs in `specs/` that still define the source of truth for boundaries and validation flow.
- A thin `shell-cli` reference harness crate that wires the local MVP flow together without claiming operator, transport, RPC, or runtime-node status.

**What the current MVP bootstrap proves**

- documented fixtures can drive transaction admission through `shell-mempool`, witness/state continuity through `shell-state`, planned transitions through `shell-execution`, and block import through `shell-consensus`,
- the local reference harness now fails fast on scenario-shape mismatches before signature, witness, or execution work begins,
- missing authorization material and altered gossip payloads fail closed instead of silently degrading into partial validation,
- the current local multi-authorization closure is `RequireAll`: every authorization present in an envelope must verify during admission and block import,
- witness corruption and unsupported committed witness shapes propagate as typed rejects through the consensus and `shell-network` adapter boundaries,
- and the same local reference data can feed thin `shell-network` adapters that normalize typed accept/reject outcomes without claiming a transport service, RPC surface, or running node.

**Still out of scope before testnet**

- Do not present the repository as a runnable node, production network, or stable operator surface.
- Do not describe `shell-cli` as a user-facing node, transport service, RPC server, daemon, or operator workflow.
- Do not imply multi-node behavior, adversarial networking, recovery, or operational guarantees.
- Do not freeze validator credential, witness/proof encoding or compression, or networking details that still need spec-first refinement.
- Do not reintroduce legacy migration assumptions that weaken the post-quantum design established from genesis.

### Phase roadmap

| Phase | Purpose | Exit conditions | Do not do too early |
|---|---|---|---|
| **docs-and-scaffold** | Lock the protocol shape, crate boundaries, validation order, and fixture ownership. | Docs, specs, and workspace boundaries are coherent enough to support a local reference flow. | Avoid implying a working local reference implementation before the harness proves it. |
| **MVP** | Prove the protocol end to end locally as a reference implementation, with `shell-cli` limited to thin local harness duties. | A local reference flow can admit transactions, validate witnesses, execute state transitions, and import blocks against documented fixtures through fixture-runner and local-wiring helpers that do not claim operator or RPC status. | Avoid treating `shell-cli` as an operator surface, RPC API, production/runtime node, or performance work that hides protocol clarity. |
| **Testnet** | Validate the chain under adversarial networking and real operator use. | Multi-node behavior, peer policy, recovery, and operator workflows have been exercised under hostile conditions with docs that match reality. | Avoid mainnet promises, irreversible parameter freezes, or compatibility shortcuts that compromise the post-quantum design. |
| **Mainnet** | Launch a stable production chain built around post-quantum assumptions from genesis. | Releases, operator procedures, upgrade discipline, and network behavior are stable enough for production use. | Avoid treating post-quantum security as an optional migration layer or expanding scope faster than the protocol can remain coherent. |

## North Star and Guardrails

- Keep `shell-chain` docs-first until the documented contracts are strong enough to drive implementation, fixtures, and validation.
- Build toward a chain designed for post-quantum security from the start rather than patched later for post-quantum compatibility.
- Keep one canonical SSZ/object model so roots, encoding, and signing inputs do not drift across crates.
- Prefer cheap-first stateless validation before expensive proof reconstruction, execution, or peer-policy work.
- Keep unfinished protocol areas explicit and provisional instead of letting placeholders become accidental APIs.
- If `shell-cli` appears in MVP-local work, keep it as boundary-clean fixture-runner and local-wiring glue rather than an operator, RPC, or runtime surface.

## Repository Layout

| Path | Purpose |
|---|---|
| `README.md` | High-level overview, phase model, and repository guardrails |
| `docs/` | Onboarding, conceptual API expectations, and contribution workflow |
| `specs/` | Implementation-facing specs for crate boundaries, data types, validation flow, and fixture planning |
| `crates/shell-fixtures/` | Repository-local fixture helpers and shared test assets |
| `vectors/` | Fixture files and vector material used by the specs and workspace |

## Workspace Shape

The current workspace already includes:

- `shell-fixtures`: shared fixture helpers and test-vector support
- `shell-primitives`: SSZ-facing types, roots, aliases, and canonical codec helpers
- `shell-crypto`: signature dispatch, hashing boundaries, and verification adapters
- `shell-state`: state-key modeling, witness verification, and accumulator abstractions
- `shell-execution`: execution-layer transition logic and post-state output calculation
- `shell-mempool`: transaction admission, fee-floor checks, and cheap-first screening
- `shell-consensus`: block-level binding, header/body checks, and import orchestration
- `shell-network`: propagation, fetch policy, and peer-consequence scaffolding
- `shell-cli`: thin local reference-harness wiring across the workspace and fixtures

Still intentionally out of scope before testnet:

- a runnable node,
- an operator binary, RPC surface, or production/runtime node,
- finalized validator economics and witness-compression rules,
- production networking, multi-node behavior, and operational guarantees.

## Documentation Map

Read the repository in this order:

1. `docs/getting-started.md`
2. `docs/api-reference.md`
3. `specs/README.md`
4. `specs/crate-structure.md`
5. `specs/data-types.md`
6. `specs/validation-rules.md`
7. `specs/testing-vectors.md`
8. `docs/contributing.md`

## Validation Commands

The repository-local baseline commands are:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

The docs and specs remain the source of truth for what the MVP harness does prove locally and what stays out of scope until testnet.
