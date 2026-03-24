# Contributing to shell-chain

## Contributing in the Current Phase

`shell-chain` is in the **MVP** phase, currently focused on an honest local reference harness.
Contributions should help keep the docs-first, natively quantum-safe design aligned with the MVP-local flow the repository actually proves.

Useful work in this phase includes:

- clarifying crate responsibilities and terminology,
- tightening the description of what the local reference harness proves,
- tightening API and validation docs,
- aligning fixtures, vectors, and spec ownership,
- extending the workspace scaffold or harness when the docs change with it,
- removing wording that overstates maturity or contradicts the current phase.

## Phase Guardrails

Before making a change, keep these constraints in mind:

- Do not describe the repository as a runnable node or stable operator surface.
- Do not treat `shell-cli` as an operator surface, RPC API, or production/runtime node; in MVP work it stays a thin local harness.
- Do not move the project toward a migration retrofit; keep the design native to post-quantum assumptions from genesis.
- Do not freeze unsettled validator, witness, or networking details just to make the docs sound more complete.

## Workflow

1. Create a branch for your change.
2. Update the relevant local docs and specs first.
3. Keep cross-file terminology and maturity claims consistent.
4. If you add or change scaffolding, update the related docs, fixtures, and validation instructions in the same change.
5. Open a pull request with a clear explanation of what changed and why.

## Anti-Drift Checklist

Before opening a pull request, confirm that:

- any boundary or behavior change is reflected in the local specs before code,
- the crate graph changes only with a deliberate spec update,
- cheap-first validation still happens before heavier execution or consensus work,
- SSZ/root logic stays centralized instead of being reimplemented across crates,
- post-quantum specifics remain behind clean crypto boundaries,
- fixtures in `vectors/` and `crates/shell-fixtures/` still have clear ownership,
- placeholders are still labeled as provisional rather than presented as stable APIs,
- any harness description says exactly which local flow is proven and avoids implying more,
- any `shell-cli` wording stays limited to fixture-runner, local-wiring, and reference-adapter duties until later phases introduce real operator surfaces.

## Validation Expectations

The repository-local baseline commands are:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

For documentation-only changes, at minimum keep links, terminology, stated repository maturity, and harness scope accurate. Do not claim stronger local tooling unless it has been added in the same change.

## Review Guidance

Reviewers should check that a contribution:

- improves local clarity,
- keeps the repository self-contained,
- matches the current project phase,
- stays consistent with a docs-first, PQ-native direction,
- updates the relevant docs or specs when behavior changes,
- and leaves the documented validation commands green.

## Commit Messages

Use a clear, imperative summary that explains the user-visible or contributor-visible change.
Examples:

- `Clarify project phase roadmap`
- `Align fixture ownership docs`
- `Tighten validation boundary language`
