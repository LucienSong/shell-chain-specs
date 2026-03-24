use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use shell_primitives::{compare_state_keys, encode_state_key, Root, StateKey, StateWitness};
use shell_state::{
    ensure_canonical_witness_order, ensure_reference_backend_proof_shape, InMemoryAccumulator,
    StateAccumulator, StateError, WitnessVerifier,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessVector {
    id: String,
    category: String,
    rule: String,
    description: String,
    input: WitnessInput,
    expected_outcome: String,
    #[serde(default)]
    expected_error: Option<WitnessExpectedError>,
    owned_by: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    state_keys: Option<Vec<String>>,
    #[serde(default)]
    proof_shape_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessInput {
    #[serde(default)]
    ordering_is_canonical: Option<bool>,
    #[serde(default)]
    proof_shape_kind: Option<String>,
    #[serde(default)]
    expected_state_root: Option<String>,
    #[serde(default)]
    witnesses: Option<Vec<WitnessFixture>>,
    #[serde(default)]
    witness: Option<WitnessFixture>,
    #[serde(default)]
    materialized_state: Option<Vec<MaterializedLeafFixture>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessFixture {
    key: StateKeyInput,
    leaf_value_hex: String,
    proof_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializedLeafFixture {
    key: StateKeyInput,
    leaf_value_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StateKeyInput {
    AccountHeader {
        address: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    StorageSlot {
        address: String,
        slot: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    CodeChunk {
        address: String,
        chunk_index: u32,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    RawTreeKey {
        raw_key: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    Stem {
        stem: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessExpectedError {
    kind: String,
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    context: Option<String>,
}

#[test]
fn witness_vectors_match_the_reference_proof_contract() {
    let mut paths = fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one witness fixture under vectors/witnesses"
    );

    for path in paths {
        let fixture = load_fixture(&path);

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "witness",
            "{} must declare category 'witness'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-state",
            "{} must be owned by shell-state",
            fixture.id
        );
        assert!(
            !fixture.rule.trim().is_empty(),
            "{} must declare the witness rule it covers",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "{} must document the invariant it covers",
            fixture.id
        );
        if let Some(notes) = &fixture.notes {
            assert!(
                !notes.trim().is_empty(),
                "{} notes field must not be blank when present",
                fixture.id
            );
        }
        if let Some(state_keys) = &fixture.state_keys {
            assert!(
                !state_keys.is_empty(),
                "{} state_keys must not be empty when present",
                fixture.id
            );
        }
        if let Some(proof_shape_kind) = &fixture.proof_shape_kind {
            assert!(
                !proof_shape_kind.trim().is_empty(),
                "{} top-level proof_shape_kind must not be blank when present",
                fixture.id
            );
        }
        if let Some(proof_shape_kind) = &fixture.input.proof_shape_kind {
            assert!(
                !proof_shape_kind.trim().is_empty(),
                "{} proof_shape_kind must not be blank when present",
                fixture.id
            );
        }
        assert_fixture_proof_shape_kind(&fixture);

        match fixture.expected_outcome.as_str() {
            "accept" => assert_accept(&fixture),
            "reject" => assert_reject(&fixture),
            other => panic!("unsupported expected_outcome {:?} in {}", other, fixture.id),
        }
    }
}

fn assert_accept(fixture: &WitnessVector) {
    match fixture.rule.as_str() {
        "canonical_state_key_ordering" => {
            let witnesses = build_witnesses(fixture);
            if let Some(expected) = fixture.input.ordering_is_canonical {
                assert!(
                    expected,
                    "{} expected accept path must declare canonical ordering",
                    fixture.id
                );
            }
            ensure_canonical_witness_order(&witnesses)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        "reference_proof_reconstruction" => {
            let (accumulator, witness) = build_reference_proof_case(fixture);
            ensure_reference_backend_proof_shape(&witness)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
            let expected_root = parse_root(
                fixture
                    .input
                    .expected_state_root
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} is missing expected_state_root", fixture.id)),
            );
            accumulator
                .verify_witness(&witness, &expected_root)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        rule => panic!("{} has unrecognised rule {:?}", fixture.id, rule),
    }
}

fn assert_reject(fixture: &WitnessVector) {
    let expected = fixture
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));

    match fixture.rule.as_str() {
        "canonical_state_key_ordering" => {
            let witnesses = build_witnesses(fixture);
            let err = ensure_canonical_witness_order(&witnesses)
                .expect_err(&format!("{} should reject but accepted", fixture.id));
            assert_state_error(fixture, expected, err);
        }
        "reference_proof_reconstruction" => {
            let (accumulator, witness) = build_reference_proof_case(fixture);
            let err = match ensure_reference_backend_proof_shape(&witness) {
                Ok(()) => {
                    let expected_root =
                        parse_root(fixture.input.expected_state_root.as_ref().unwrap_or_else(
                            || panic!("{} is missing expected_state_root", fixture.id),
                        ));
                    accumulator
                        .verify_witness(&witness, &expected_root)
                        .expect_err(&format!("{} should reject but accepted", fixture.id))
                }
                Err(err) => err,
            };
            assert_state_error(fixture, expected, err);
        }
        rule => panic!("{} has unrecognised rule {:?}", fixture.id, rule),
    }
}

fn assert_state_error(fixture: &WitnessVector, expected: &WitnessExpectedError, err: StateError) {
    match (&*expected.kind, err) {
        ("NonCanonicalWitnessOrdering", StateError::NonCanonicalWitnessOrdering(actual)) => {
            if let Some(expected_index) = expected.index {
                assert_eq!(
                    actual.index, expected_index,
                    "{} ordering index mismatch",
                    fixture.id
                );
            }
            if let Some(expected_context) = &expected.context {
                assert_eq!(
                    actual.context, expected_context,
                    "{} ordering context mismatch",
                    fixture.id
                );
            }
        }
        ("UnsupportedProofShape", StateError::UnsupportedProofShape(actual)) => {
            if let Some(expected_context) = &expected.context {
                assert_eq!(
                    actual, expected_context,
                    "{} proof-shape context mismatch",
                    fixture.id
                );
            }
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

fn build_reference_proof_case(fixture: &WitnessVector) -> (InMemoryAccumulator, StateWitness) {
    let mut accumulator = InMemoryAccumulator::new();
    let mut materialized = fixture
        .input
        .materialized_state
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing materialized_state", fixture.id))
        .iter()
        .map(|entry| {
            let key = entry.key.to_state_key();
            let value = parse_hex(&entry.leaf_value_hex);
            (key, value)
        })
        .collect::<Vec<_>>();
    materialized.sort_by(|left, right| compare_state_keys(&left.0, &right.0));

    if !materialized.is_empty() {
        let patch = shell_state::StatePatch {
            accesses: materialized.iter().map(|(key, _)| key.clone()).collect(),
            new_values: materialized
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
        };
        accumulator.apply_transition(&patch).unwrap_or_else(|err| {
            panic!(
                "{} failed to materialize reference state: {err:?}",
                fixture.id
            )
        });
    }

    let witness = fixture
        .input
        .witness
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing witness", fixture.id))
        .to_state_witness();

    (accumulator, witness)
}

fn build_witnesses(fixture: &WitnessVector) -> Vec<StateWitness> {
    fixture
        .input
        .witnesses
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing witnesses", fixture.id))
        .iter()
        .map(WitnessFixture::to_state_witness)
        .collect()
}

fn assert_fixture_proof_shape_kind(fixture: &WitnessVector) {
    let declared = fixture
        .input
        .proof_shape_kind
        .as_ref()
        .or(fixture.proof_shape_kind.as_ref());
    let Some(declared) = declared else {
        return;
    };

    let witnesses = fixture
        .input
        .witness
        .as_ref()
        .map(|witness| vec![witness.to_state_witness()])
        .or_else(|| {
            fixture.input.witnesses.as_ref().map(|witnesses| {
                witnesses
                    .iter()
                    .map(WitnessFixture::to_state_witness)
                    .collect()
            })
        })
        .unwrap_or_default();

    if witnesses.is_empty() {
        return;
    }

    let actual = if witnesses
        .iter()
        .all(|witness| witness.proof_shape().as_str() == "reference_empty")
    {
        "reference_empty"
    } else {
        "placeholder_committed_nodes"
    };

    assert_eq!(
        actual, declared,
        "{} proof_shape_kind does not match the committed witness shape",
        fixture.id
    );
}

fn fixture_paths() -> Vec<PathBuf> {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/witnesses");
    fs::read_dir(&vectors_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", vectors_dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect()
}

fn load_fixture(path: &Path) -> WitnessVector {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn parse_root(value: &str) -> Root {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte root, got {len} bytes in {value}"))
}

fn parse_address(value: &str) -> [u8; 20] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 20-byte address, got {len} bytes in {value}"))
}

fn parse_bytes32(value: &str) -> [u8; 32] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte hex string, got {len} bytes in {value}"))
}

fn parse_bytes31(value: &str) -> [u8; 31] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 31-byte hex string, got {len} bytes in {value}"))
}

fn parse_hex(value: &str) -> Vec<u8> {
    let hex = value
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("hex values must use a 0x prefix: {value}"));
    assert!(
        hex.len().is_multiple_of(2),
        "hex values must contain an even number of digits: {value}"
    );

    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex byte at offset {index} in {value}"))
        })
        .collect()
}

impl StateKeyInput {
    fn to_state_key(&self) -> StateKey {
        let key = match self {
            Self::AccountHeader { address, .. } => StateKey::AccountHeader(parse_address(address)),
            Self::StorageSlot { address, slot, .. } => StateKey::StorageSlot {
                address: parse_address(address),
                slot: parse_bytes32(slot),
            },
            Self::CodeChunk {
                address,
                chunk_index,
                ..
            } => StateKey::CodeChunk {
                address: parse_address(address),
                chunk_index: *chunk_index,
            },
            Self::RawTreeKey { raw_key, .. } => StateKey::RawTreeKey(parse_bytes32(raw_key)),
            Self::Stem { stem, .. } => StateKey::Stem(parse_bytes31(stem)),
        };

        if let Some(expected_hex) = self.canonical_key_hex() {
            assert_eq!(
                encode_state_key(&key).as_slice(),
                parse_hex(expected_hex).as_slice(),
                "canonical StateKey bytes mismatch for {:?}",
                self
            );
        }

        key
    }

    fn canonical_key_hex(&self) -> Option<&str> {
        match self {
            Self::AccountHeader {
                canonical_key_hex, ..
            }
            | Self::StorageSlot {
                canonical_key_hex, ..
            }
            | Self::CodeChunk {
                canonical_key_hex, ..
            }
            | Self::RawTreeKey {
                canonical_key_hex, ..
            }
            | Self::Stem {
                canonical_key_hex, ..
            } => canonical_key_hex.as_deref(),
        }
    }
}

impl WitnessFixture {
    fn to_state_witness(&self) -> StateWitness {
        StateWitness {
            key: self.key.to_state_key(),
            leaf_value: parse_hex(&self.leaf_value_hex),
            proof: self
                .proof_hex
                .iter()
                .map(|value| parse_bytes32(value))
                .collect(),
        }
    }
}
