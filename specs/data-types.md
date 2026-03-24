# Data Types (Rust API Mapping)

> **Non-normative Rust binding:** this document describes the Rust-facing data types and local protocol assumptions that `shell-chain` should implement.
> It is meant to stand on its own for repository-local work: closed wire contracts are stated directly here, and still-open areas are kept explicitly provisional.

## 1. Binding goals

This file is intentionally implementation-oriented:

- prefer strongly typed Rust wrappers over raw SSZ containers,
- preserve exact upstream commitment behavior where upstream is already frozen,
- isolate still-open protocol areas behind traits, wrappers, or codec boundaries,
- avoid baking temporary mock container limits into consensus or fee logic.

The most important consequence is that Rust types may be richer than the wire schema, but any wire-facing codec must still round-trip to the exact upstream SSZ object and `hash_tree_root`.

## 2. Core aliases and temporary progressive containers

```rust
use ssz_rs::prelude::*;
// U256: sourced from the single workspace-level large-number crate declared
// in the root Cargo.toml (see §2.2 and crate-structure.md §9).
// Do not introduce a per-crate U256 alias or re-export.

pub type Root = Vector<u8, 32>;
pub type Bytes32 = Vector<u8, 32>;
pub type Bytes31 = Vector<u8, 31>;
pub type Bytes4   = Vector<u8, 4>;
pub type ExecutionAddress = Vector<u8, 20>;

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct ChainId(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct TxValue(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct GasPrice(pub U256);

// Default is derivable because all three fields are GasPrice, which itself
// derives Default (a zero-valued U256).  Any caller that requires a non-zero
// fee floor must construct BasicFeesPerGas explicitly rather than relying on
// this default.  See §2.2 for the rationale.
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct BasicFeesPerGas {
    pub regular: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub max_witness_priority_fee: GasPrice,
}

// Temporary stand-ins for upstream Progressive containers.
// These names must remain obviously provisional in Rust code.
pub type MockProgressiveByteList = List<u8, 1048576>;
pub type MockProgressiveList<T> = List<T, 8192>;
```

### 2.1 Mock-container discipline

Upstream transaction and witness specs treat `ProgressiveByteList` / `ProgressiveList[T]` as protocol-level semantic types. The current bounded aliases above are only local implementation substitutes until the upstream-compatible container story is closed in the Rust stack.

Rust implementation guidance:

- treat `MockProgressiveByteList` and `MockProgressiveList<T>` as **codec adapters**, not as protocol constants,
- do **not** derive fee heuristics, mempool scoring, gossip assumptions, or proof-shape assumptions from `1048576` or `8192`,
- keep local ingress ceilings configurable and clearly labeled as implementation policy unless upstream freezes a protocol number,
- keep the merkleization / gindex mental model tied to the upstream progressive semantics, not to the temporary bounded replacement.

Within this spec set, mock container bounds are implementation-only adapters and are not part of frozen protocol behavior.

### 2.2 `U256` dependency and `BasicFeesPerGas` default

**`U256` source.**
`U256` is not provided by the standard library.  Per `crate-structure.md §9`, large-number crates must be selected and versioned at the workspace level; `shell-primitives` is the single crate that re-exports the canonical `U256` type for the rest of the workspace.  Each crate that needs `U256` imports it from `shell-primitives`, not directly from a vendor crate.  This rule prevents version skew and ensures that SSZ round-trip tests cover exactly one numeric representation.

**`BasicFeesPerGas` default.**
`BasicFeesPerGas` derives `Default` because every field is a `GasPrice`, which itself derives `Default` (wrapping a zero-valued `U256`).  An all-zero `BasicFeesPerGas` is structurally valid but semantically meaningless as a fee floor: it expresses that any fee level is acceptable.  Callers that need a non-trivial fee floor must construct the struct explicitly.  Mempool admission code must never treat a derived default as an implicit protocol fee floor; that policy belongs in `shell-mempool` configuration, not in the default value of this type.

## 3. Transaction bindings

```rust
#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct BasicTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub to: ExecutionAddress,
    pub value: TxValue,
    pub input: MockProgressiveByteList,
    pub access_commitment: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct CreateTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub value: TxValue,
    pub initcode: MockProgressiveByteList,
    pub access_commitment: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct Authorization {
    pub scheme_id: u8,
    pub payload_root: Root,
    pub signature: MockProgressiveByteList,
}

// TransactionEnvelope cannot derive SimpleSerialize because its payload
// field must use TransactionPayloadSsz (the custom union wrapper described in
// §3.1) rather than the plain TransactionPayload enum.  The SSZ
// implementation of TransactionEnvelope must delegate encode, decode, and
// hash_tree_root to TransactionPayloadSsz for the payload field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEnvelope {
    pub payload: TransactionPayloadSsz,
    pub authorizations: MockProgressiveList<Authorization>,
}

// domain_type is a fixed 4-byte tag; see §3.3 for width guidance.
// object_root carries the hash_tree_root of the signed object; when used
// for transaction authorization, object_root must equal
// Authorization.payload_root (see §3.3).
#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct SigningData {
    pub object_root: Root,
    pub domain_type: Bytes4,
}
```

### 3.1 `TransactionPayload` is a frozen SSZ union contract

Upstream has already frozen the wire-level meaning of `TransactionPayload` as a `CompatibleUnion` with append-only evolution.

That means the Rust binding must implement the following contract explicitly:

1. **Frozen discriminants**
   - tag `0` = `BasicTransactionPayload`
   - tag `1` = `CreateTransactionPayload`
   - future variants may only append new tags; existing tags must never be reused, reordered, or deleted.

2. **Codec ownership**
   - a plain Rust `enum` declaration is not itself the contract,
   - the wire-facing implementation must be owned by a dedicated wrapper, custom SSZ codec, or equivalent macro expansion that guarantees the exact upstream union encoding,
   - decode must reject unknown tags as an unsupported payload variant rather than silently coercing them.

3. **Root stability**
   - `hash_tree_root(TransactionPayload)` must be computed from the exact upstream union representation,
   - `Authorization.payload_root` validation depends on this being stable,
   - mempool, consensus, and signing helpers must all share the same codec path or a provably identical one.

4. **Wrapper expectation**
   - if the ergonomic Rust API uses a native enum, keep it behind a wrapper that controls SSZ encode/decode and root calculation,
   - do not rely on `repr(...)`, compiler layout, or derive defaults to define the wire format,
   - round-trip tests should assert `(bytes, tag, hash_tree_root)` compatibility for each known variant.

Illustrative shape:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionPayload {
    Basic(BasicTransactionPayload),
    Create(CreateTransactionPayload),
}

pub struct TransactionPayloadSsz(TransactionPayload);

impl TransactionPayloadSsz {
    pub const TAG_BASIC: u8 = 0;
    pub const TAG_CREATE: u8 = 1;

    pub fn protocol_tag(&self) -> u8 { /* custom mapping */ }
    pub fn hash_tree_root(&self) -> Root { /* exact union root */ }
    pub fn to_wire_bytes(&self) -> Vec<u8> { /* exact union codec */ }
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, DecodeError> { /* reject unknown tag */ }
}
```

The example above is not itself normative API, but the separation of:

- ergonomic domain enum,
- frozen union tags,
- explicit encode/decode/root logic,

should be treated as the expected Rust binding shape.

### 3.2 Validation alignment for transaction types

`specs/validation-rules.md` now assumes:

- unknown `TransactionPayload` tags fail as `UnsupportedPayloadVariant(Tag)`,
- `payload_root` is recomputed from the exact `TransactionPayload` wire object,
- witness-sidecar work stays downstream of cheaper structural and fee-floor checks.

The Rust binding should therefore make it difficult to:

- compute roots from an alternate in-memory shape,
- accept tag aliases,
- or run sidecar logic through payload codecs that differ from the shared canonical path.

### 3.3 `SigningData` field contracts

**`domain_type` width and repository-local constants.**
`domain_type` is a fixed **4-byte** tag (`Bytes4 = Vector<u8, 4>`).  The 4-byte width is the established convention for domain-type tags in SSZ-based signing flows.  Using a wider type (e.g. `Bytes32`) for this field would produce a different `hash_tree_root(SigningData)` than any conforming counterparty and must be rejected.

For the current repository milestone, the local binding is:

- `DOMAIN_TX_SHELL = [0x01, 0x00, 0x00, 0x00]`
- `DOMAIN_VALIDATOR_MESSAGE = [0x02, 0x00, 0x00, 0x00]`

These values are now frozen for this repository so lower-layer crates can share one signing-root construction path.  If an upstream protocol source later chooses different values, the repository must treat that as an intentional compatibility change rather than leaving the bytes implicit.

**`object_root` and `Authorization.payload_root`.**
When a signer constructs a `SigningData` to produce or verify an `Authorization`, the following identity must hold:

```
SigningData.object_root == Authorization.payload_root
                       == hash_tree_root(TransactionPayloadSsz)
```

`Authorization.payload_root` stores the canonical Merkle root of the `TransactionPayload` union computed through `TransactionPayloadSsz` (see §3.1).  `SigningData.object_root` carries that same root as the "what is being signed" field.  Implementations must use the single shared `TransactionPayloadSsz` codec path for both root calculations; a mismatch between the codec used during signing and the one used during authorization verification is a correctness bug, not a configuration difference.

### 3.4 Repository-local closure for proposer credentials

Validator-path signing now has one repository-local closure even though the full validator lifecycle remains open: the **credential lookup interface** is fixed, but the **credential source and persistence model** are not.

The minimal shared shape is:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerCredential {
    pub scheme_id: u8,
    pub public_key_material: MockProgressiveByteList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposerCredentialQuery {
    pub block_root: Root,
    pub proposer_index_hint: Option<u64>,
}

pub trait ProposerCredentialResolver {
    fn resolve_proposer_credential(
        &self,
        query: ProposerCredentialQuery,
    ) -> Result<ProposerCredential, ProposerCredentialResolutionError>;
}
```

Repository-local meaning:

- `scheme_id` is the validator-path signature family selector consumed by `shell-crypto`.
- `public_key_material` stays opaque bytes at this layer so the repository does not prematurely freeze a validator-key encoding beyond what the selected scheme requires.
- `query.block_root` is provided because a resolver may need block-context-aware scheduling or epoch snapshots.
- `query.proposer_index_hint` is optional because the eventual block-header shape may carry a direct proposer identifier, but the repository does not yet freeze that header field here.
- `ProposerCredentialResolutionError::InvalidCredentialEncoding { scheme_id, context }` is the locally closed way to report malformed credential bytes without exposing a concrete validator-storage model.

This closes only the **resolver boundary**. It does **not** close:

- the validator credential lifecycle,
- whether validator credentials are stored in consensus state, execution state, or an external registry,
- richer threshold / multisignature validator models.

Those remain deferred and must stay behind the resolver trait rather than leaking into low-level cryptographic dispatch.

## 4. State-layer bindings

```rust
// StateKey has no derive(SimpleSerialize).  Its enum shape (tuple variants,
// struct variants) is not directly expressible by the ssz_rs derive macro.
// Structs that include StateKey fields (StateWitness, StatePatch) require
// custom SSZ implementations or an intermediate StateKeyBytes wrapper.
// See §4.5 for encoding and crate-placement guidance.
pub enum StateKey {
    AccountHeader(ExecutionAddress),
    StorageSlot { address: ExecutionAddress, slot: Bytes32 },
    CodeChunk { address: ExecutionAddress, chunk_index: u32 },
    RawTreeKey(Bytes32),
    Stem(Bytes31),
}

// Belongs in shell-state::keys; see §4.5 for placement rationale.
pub fn canonicalize_execution_address(addr: &ExecutionAddress) -> Bytes32 {
    let mut key = Bytes32::default();
    key[12..32].copy_from_slice(addr.as_ref());
    key
}

// StateWitness cannot derive SimpleSerialize because StateKey has no SSZ
// derive.  The SSZ implementation must be custom or use a StateKeyBytes
// wrapper (see §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWitness {
    pub key: StateKey,
    pub leaf_value: MockProgressiveByteList,
    pub proof: MockProgressiveList<Bytes32>,
}

// StatePatch cannot derive SimpleSerialize for two independent reasons:
// 1. StateKey has no SSZ derive (see §4.5).
// 2. new_values is a nested variable-length container
//    (MockProgressiveList<MockProgressiveByteList> = List<List<u8,N>,M>);
//    ssz_rs does not support this shape via plain derive (see §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePatch {
    pub accesses: MockProgressiveList<StateKey>,
    pub new_values: MockProgressiveList<MockProgressiveByteList>,
}

pub trait StateAccumulator {
    fn get_witness_for_accesses(&self, accesses: &[StateKey]) -> Result<Vec<StateWitness>, StateError>;
    fn apply_transition(&mut self, patch: StatePatch) -> Result<Root, StateError>;
    fn state_root(&self) -> Root;
}
```

### 4.1 What is known now vs. what is still pending upstream closure

The Rust binding should separate already-closed assumptions from still-open ones.

| Area | Closed enough to bind now | Still pending / should stay abstract |
|---|---|---|
| State accumulator family | Unified binary tree / JMT-style compressed binary accumulator is selected upstream. | Exact proof-node object model exposed on the wire may still evolve. |
| Address normalization | `ExecutionAddress` should canonicalize to a 32-byte tree key by left-padding with 12 zero bytes. | No additional alternate address-key encodings should be assumed. |
| Witness transport containers | `StateWitness` exists as the witness unit referenced by tx sidecars and block sidecars. | Witness compression and canonical byte encoding are not yet frozen upstream. |
| Proof verification flow | Validation requires canonical `StateKey` ordering before reconstruction and proof verification in `shell-state`. | Exact proof element layout inside `proof` is still placeholder-grade in the current upstream state-transition text. |
| Block-sidecar handling | Commitment checks must preserve committed ordering and bytes before any optimized indexing or dedup-aware execution view is built. | Any normalized in-memory proof index is local-only and must not be treated as a new canonical protocol form. |

### 4.1.1 Repository-local closure decisions

For the first Rust scaffold, this repository treats the following binding choices as locally fixed:

| Area | Closed local binding | Why it is safe to build against now |
|---|---|---|
| Address-to-tree-key mapping | `ExecutionAddress` canonicalizes to a 32-byte key by left-padding with 12 zero bytes. | This rule is already used consistently across the current spec set and does not depend on unresolved witness encoding details. |
| Witness ordering key | One canonical `StateKey` comparator is the shared ordering rule for sidecar validation. | `validation-rules.md` already requires ordering checks before proof reconstruction. |
| Transport vs. derived witness forms | `StateWitness` is the committed transport object; any optimized proof/index view is derived and local-only. | This preserves commitment semantics while leaving proof internals abstract. |
| Mock progressive bounds | `MockProgressiveByteList` and `MockProgressiveList<T>` are codec adapters only, never consensus constants. | This prevents temporary Rust bounds from leaking into fee, gossip, or proof heuristics. |

The following must remain abstract even during the first implementation pass:

- the exact internal proof-node encoding behind `StateWitness.proof`,
- canonical witness compression or normalization rules,
- any stronger claim that `proof` is permanently a flat hash list on the wire.

### 4.2 `StateWitness.proof` should be treated as a proof-shape abstraction

The current placeholder:

```rust
pub proof: MockProgressiveList<Bytes32>
```

is useful as a temporary Rust field, but it should not be misread as a final statement that every upstream proof will forever be a flat list of hashes.

Binding guidance:

- expose proof verification behind traits or wrapper types in `shell-state`,
- keep `StateWitness` as the committed transport object and allow a separate decoded proof view for execution,
- assume the internal meaning of each proof element may later become richer once upstream closes the exact `InternalNode` / `StemNode` witness encoding,
- keep the verification API centered on `StateKey`, committed proof bytes/elements, and expected root reconstruction outcome.

In practice, a useful Rust split is:

- **committed form:** what SSZ decodes from the sidecar and what commitment checks see,
- **derived form:** an execution-friendly proof/index structure built only after ordering and commitment checks pass.

That split keeps `shell-state` aligned with validation ordering and avoids coupling execution optimizations to a still-open wire proof shape.

For the current repository milestone, one narrower local classification is now closed to reduce churn across fixtures and validation code:

- `reference_empty`: the committed witness carries no interpreted proof nodes, and the reference backend derives the path locally,
- `placeholder_committed_nodes`: committed proof nodes are present, but their internal meaning is still provisional and must not be treated as a finalized wire proof contract.

This classification is intentionally smaller than a final protocol proof model.  It exists so vectors, consensus fixtures, and state helpers can share one boundary without pretending that the upstream proof-node layout is already frozen.

### 4.3 Canonical ordering requirements

For transaction witness sidecars, upstream-facing validation now expects `state_proofs` to be canonically ordered by `StateKey` before proof reconstruction.

Rust guidance:

- define one canonical comparator for `StateKey`,
- reuse it everywhere sidecar ordering is validated,
- reject non-canonical ordering before heavy proof work,
- keep any later in-memory grouping, deduplication, or indexing downstream of that check.

For block witness sidecars, preserve the committed sidecar ordering and bytes during root checks even if execution later builds a deduplicated index. Import code must not require a non-deduplicated per-transaction layout because upstream explicitly allows block-building deduplication.

### 4.4 Mock bounds must not leak into protocol heuristics

The witness path is where temporary implementation choices are most likely to become accidental protocol assumptions. Avoid that.

Specifically:

- do not interpret `List<Bytes32, 8192>` as proof-count consensus,
- do not price witnesses as if the temporary list ceiling were a protocol witness budget,
- do not use the mock container size to justify search depth, proof branching expectations, or cache eviction heuristics,
- do not rewrite, normalize, recompress, or canonicalize sidecar bytes before commitment verification unless upstream later freezes that transform.

This matters because witness compression and canonical sidecar encoding are still open within this spec set, and `validation-rules.md` requires committed bytes to be preserved through the commitment-check stage.

### 4.5 `StateKey` SSZ encoding, `StatePatch` nesting, and `canonicalize_execution_address` placement

**`StateKey` SSZ encoding.**
`StateKey` is a Rust enum with mixed variant shapes (unit-tuple and named-field variants).  The `ssz_rs` derive macro does not support this shape; deriving `SimpleSerialize` on `StateKey` directly is not possible.  Implementations must use one of the following approaches:

1. **`StateKeyBytes` wrapper** — define a newtype that serializes `StateKey` to a canonical byte sequence (e.g. a tag byte followed by the variant fields), implements `SimpleSerialize` on the wrapper, and is the field type stored in `StateWitness` and `StatePatch` on the wire.  The ergonomic `StateKey` enum is then only used in memory after decoding.
2. **Custom `SimpleSerialize` impl** — write a hand-rolled `ssz_rs::Serialize` / `Deserialize` / `HashTreeRoot` impl for `StateKey` directly if the encoding shape is stable enough to commit to.

This repository now chooses the **`StateKeyBytes` wrapper** path at the first scaffold stage.  The canonical wire byte sequence is:

- `AccountHeader`: `0x00 || canonicalize_execution_address(address)`
- `StorageSlot`: `0x01 || canonicalize_execution_address(address) || slot`
- `CodeChunk`: `0x02 || canonicalize_execution_address(address) || chunk_index.to_be_bytes()`
- `RawTreeKey`: `0x03 || raw_tree_key`
- `Stem`: `0x04 || stem`

The canonical ordering comparator required by §4.3 operates on exactly this byte sequence.  The ergonomic `StateKey` enum remains the in-memory representation, while `StateKeyBytes` is the shared byte path reused by ordering checks and any future SSZ wrapper work.

**`StatePatch.new_values` nesting.**
`MockProgressiveList<MockProgressiveByteList>` expands to `List<List<u8, 1048576>, 8192>` — a variable-length list whose elements are themselves variable-length.  The SSZ specification allows this structure (outer list uses offset tables to encode variable-length elements), but `ssz_rs` does not support it via the derive macro.  `StatePatch` therefore requires a custom `SimpleSerialize` implementation.  The repository-local closure for the path shape is that `StatePatch.accesses` must use the shared `StateKeyBytes` encoding above, and `StatePatch.new_values` must remain a nested variable-length list handled by one shared custom implementation rather than per-struct re-derivations.  The same mock-container discipline from §2.1 applies: do not interpret `1048576` or `8192` as protocol budget constants.

**`canonicalize_execution_address` placement.**
This function performs the state-key derivation for execution addresses (left-padding a 20-byte address to a 32-byte tree key).  It belongs in `shell-state::keys` (see `crate-structure.md §3.3` and `§6`).  It must not be re-implemented inline elsewhere; all address-to-tree-key conversions in `shell-state`, `shell-execution`, and `shell-consensus` must call the same shared function.  Placing it outside `shell-state` in a lower crate (e.g. `shell-primitives`) is also acceptable if the function is needed there first, provided it remains a single implementation that higher crates re-use rather than re-derive.

## 5. Repository-local canonical block objects

Consensus, network, and vector work now share one repository-local concrete object family for the currently closed block-import boundary:

```rust
pub struct CanonicalBlockHeader {
    pub block_root: Root,
    pub block_number: u64,
    pub timestamp: u64,
    pub parent_root: Root,
    pub witness_bytes: u64,
    pub transactions_root: Root,
    pub execution_witnesses_root: Root,
    pub state_root: Root,
    pub receipts_root: Root,
    pub proposer_signature: MockProgressiveByteList,
    pub proposer_index_hint: Option<u64>,
}

pub struct CanonicalBlockBody {
    pub transactions: Vec<TransactionEnvelope>,
    pub transactions_root: Root,
}

pub struct CanonicalBlockSidecar {
    pub block_root: Root,
    pub execution_witnesses_root: Root,
    pub witnesses: Vec<StateWitness>,
}
```

Repository-local meaning:

- these structs close the **shared in-memory contract** used by consensus, network, and fixtures,
- they do **not** by themselves freeze a final SSZ block/header/body/sidecar codec,
- `block_root`, `transactions_root`, and `execution_witnesses_root` remain explicit committed values so decoders and fixtures can bind objects without inventing a premature canonical codec,
- `CanonicalBlockSidecar.witnesses` carries committed transport witnesses, while any optimized proof index remains derived and local-only.

The repository may still accept trait-based adapters at crate boundaries, but these concrete structs are the default local shape that downstream work should reuse instead of inventing per-test header/body/sidecar structs.

## 6. Practical implementation checklist

For future Rust work, the binding is in good shape if it satisfies all of the following:

- `TransactionPayload` encode/decode/root logic is centralized and tag-frozen.
- Unknown payload tags fail cleanly and early.
- `payload_root` uses the same canonical codec path everywhere.
- `TransactionEnvelope` delegates encode/decode/root for its payload field to `TransactionPayloadSsz`.
- `SigningData.domain_type` is exactly 4 bytes; `object_root` equals `Authorization.payload_root` when signing a transaction authorization.
- `U256` is imported from `shell-primitives`, not re-declared per crate.
- `BasicFeesPerGas::default()` is never used as an implicit protocol fee floor; fee-floor policy lives in `shell-mempool` configuration.
- `StateKey` SSZ encoding is implemented as a single shared path (wrapper or hand-rolled impl), not re-derived independently per struct.
- `StatePatch.new_values` nested list is handled by a custom SSZ implementation, not a plain derive.
- `canonicalize_execution_address` has exactly one implementation in `shell-state::keys` (or `shell-primitives` if needed lower) and is re-used rather than re-derived elsewhere.
- `StateKey` ordering is implemented once and reused for sidecar checks.
- `StateWitness` transport form is kept separate from any optimized proof index.
- Commitment verification always sees the committed sidecar bytes / order first.
- Temporary progressive mock bounds remain local implementation details, not consensus rules.
- Open witness-proof shape questions remain isolated behind wrappers or traits rather than leaking into public type assumptions.

That is the intended Rust-facing contract until upstream closes the remaining witness encoding details.
