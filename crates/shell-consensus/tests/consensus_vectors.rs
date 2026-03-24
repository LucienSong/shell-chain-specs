use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use shell_consensus::{
    execute_and_compare, prefilter_header, verify_body_binding, verify_sidecar_binding,
    BlockExecutionEngine, CanonicalBlockBody, CanonicalBlockHeader, CanonicalBlockSidecar,
    ConsensusBody, ConsensusError, ConsensusHeader, ConsensusSidecar, HeaderPrefilterConfig,
    WitnessPreparer,
};
use shell_execution::{BlockExecutionOutcome, ExecutionError, ExecutionReceipt};
use shell_primitives::Root;
use shell_state::StateError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsensusVector {
    id: String,
    category: String,
    rule: String,
    description: String,
    input: ConsensusInput,
    expected_outcome: String,
    #[serde(default)]
    expected_error: Option<ConsensusExpectedError>,
    owned_by: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    transactions_root: Option<String>,
    #[serde(default)]
    execution_witnesses_root: Option<String>,
    #[serde(default)]
    state_root: Option<String>,
    #[serde(default)]
    receipts_root: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsensusInput {
    header: HeaderInput,
    #[serde(default)]
    body: Option<BodyInput>,
    #[serde(default)]
    sidecar: Option<SidecarInput>,
    #[serde(default)]
    computed_transactions_root: Option<String>,
    #[serde(default)]
    computed_block_root: Option<String>,
    #[serde(default)]
    computed_sidecar_root: Option<String>,
    #[serde(default)]
    local_limits: Option<LocalLimitsInput>,
    #[serde(default)]
    execution_result: Option<ExecutionResultInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderInput {
    block_number: u64,
    timestamp: u64,
    proposer_index: u64,
    parent_root: String,
    transactions_root: String,
    execution_witnesses_root: String,
    state_root: String,
    receipts_root: String,
    witness_bytes: u64,
    proposer_signature_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyInput {
    transaction_vector_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarInput {
    block_root: String,
    witness_vector_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalLimitsInput {
    #[serde(default)]
    max_witness_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionResultInput {
    post_state_root: String,
    receipts_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsensusExpectedError {
    kind: String,
    #[serde(default)]
    expected_root: Option<String>,
    #[serde(default)]
    actual_root: Option<String>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    actual_bytes: Option<u64>,
}

struct NoopWitnessPreparer;

impl WitnessPreparer for NoopWitnessPreparer {
    fn prepare_witness(
        &self,
        _header: &dyn ConsensusHeader,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<(), StateError> {
        Ok(())
    }
}

struct FixedExecutionEngine {
    outcome: BlockExecutionOutcome,
}

impl BlockExecutionEngine for FixedExecutionEngine {
    fn execute_block(
        &self,
        _header: &dyn ConsensusHeader,
        _body: &dyn ConsensusBody,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<BlockExecutionOutcome, ExecutionError> {
        Ok(self.outcome.clone())
    }
}

#[test]
fn consensus_vectors_cover_minimal_block_header_sidecar_contracts() {
    let mut paths = fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one block fixture under vectors/blocks"
    );

    for path in paths {
        let fixture = load_fixture(&path);

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "block",
            "{} must declare category 'block'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-consensus",
            "{} must be owned by shell-consensus",
            fixture.id
        );
        assert!(
            !fixture.rule.trim().is_empty(),
            "{} must declare the consensus rule it covers",
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
        if let Some(root) = &fixture.transactions_root {
            assert_eq!(
                parse_root(root),
                parse_root(&fixture.input.header.transactions_root),
                "{} top-level transactions_root must match header.transactions_root",
                fixture.id
            );
        }
        if let Some(root) = &fixture.execution_witnesses_root {
            assert_eq!(
                parse_root(root),
                parse_root(&fixture.input.header.execution_witnesses_root),
                "{} top-level execution_witnesses_root must match header.execution_witnesses_root",
                fixture.id
            );
        }
        if let Some(root) = &fixture.state_root {
            assert_eq!(
                parse_root(root),
                parse_root(&fixture.input.header.state_root),
                "{} top-level state_root must match header.state_root",
                fixture.id
            );
        }
        if let Some(root) = &fixture.receipts_root {
            assert_eq!(
                parse_root(root),
                parse_root(&fixture.input.header.receipts_root),
                "{} top-level receipts_root must match header.receipts_root",
                fixture.id
            );
        }

        match fixture.expected_outcome.as_str() {
            "accept" => assert_accept(&fixture),
            "reject" => assert_reject(&fixture),
            other => panic!("unsupported expected_outcome {:?} in {}", other, fixture.id),
        }
    }
}

fn assert_accept(fixture: &ConsensusVector) {
    match fixture.rule.as_str() {
        "transactions_root_binding" => {
            let (header, body) = build_body_binding_case(fixture);
            verify_body_binding(&header, &body)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        "sidecar_commitment" => {
            let (header, sidecar) = build_sidecar_case(fixture);
            let block_root = parse_root(
                fixture
                    .input
                    .computed_block_root
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} is missing computed_block_root", fixture.id)),
            );
            verify_sidecar_binding(&header, &block_root, &sidecar, &NoopWitnessPreparer)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        "header_witness_bytes_prefilter" => {
            let header = build_header(fixture);
            let config = HeaderPrefilterConfig {
                max_witness_bytes: fixture
                    .input
                    .local_limits
                    .as_ref()
                    .and_then(|limits| limits.max_witness_bytes),
            };
            prefilter_header(&header, config)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        "execution_root_comparison" => {
            let (header, body, sidecar, engine) = build_execution_case(fixture);
            execute_and_compare(&header, &body, &sidecar, &engine)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        rule => panic!("{} has unrecognized rule {:?}", fixture.id, rule),
    }
}

fn assert_reject(fixture: &ConsensusVector) {
    let expected = fixture
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));

    let err = match fixture.rule.as_str() {
        "transactions_root_binding" => {
            let (header, body) = build_body_binding_case(fixture);
            verify_body_binding(&header, &body)
                .expect_err(&format!("{} should reject but accepted", fixture.id))
        }
        "sidecar_commitment" => {
            let (header, sidecar) = build_sidecar_case(fixture);
            let block_root = parse_root(
                fixture
                    .input
                    .computed_block_root
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} is missing computed_block_root", fixture.id)),
            );
            verify_sidecar_binding(&header, &block_root, &sidecar, &NoopWitnessPreparer)
                .expect_err(&format!("{} should reject but accepted", fixture.id))
        }
        "header_witness_bytes_prefilter" => {
            let header = build_header(fixture);
            let config = HeaderPrefilterConfig {
                max_witness_bytes: fixture
                    .input
                    .local_limits
                    .as_ref()
                    .and_then(|limits| limits.max_witness_bytes),
            };
            prefilter_header(&header, config)
                .expect_err(&format!("{} should reject but accepted", fixture.id))
        }
        "execution_root_comparison" => {
            let (header, body, sidecar, engine) = build_execution_case(fixture);
            execute_and_compare(&header, &body, &sidecar, &engine)
                .expect_err(&format!("{} should reject but accepted", fixture.id))
        }
        rule => panic!("{} has unrecognized rule {:?}", fixture.id, rule),
    };

    assert_consensus_error(fixture, expected, err);
}

fn assert_consensus_error(
    fixture: &ConsensusVector,
    expected: &ConsensusExpectedError,
    err: ConsensusError,
) {
    match (&*expected.kind, err) {
        ("TransactionsRootMismatch", ConsensusError::HeaderBodyRootMismatch(actual)) => {
            assert_root_mismatch(
                fixture,
                expected.expected_root.as_ref(),
                expected.actual_root.as_ref(),
                actual.expected,
                actual.actual,
            );
        }
        ("SidecarMismatch", ConsensusError::SidecarCommitmentMismatch(actual)) => {
            assert_root_mismatch(
                fixture,
                expected.expected_root.as_ref(),
                expected.actual_root.as_ref(),
                actual.expected,
                actual.actual,
            );
        }
        ("WitnessByteLimitExceeded", ConsensusError::WitnessByteLimitExceeded(actual)) => {
            if let Some(expected_max_bytes) = expected.max_bytes {
                assert_eq!(
                    actual.max_bytes, expected_max_bytes,
                    "{} max_bytes mismatch",
                    fixture.id
                );
            }
            if let Some(expected_actual_bytes) = expected.actual_bytes {
                assert_eq!(
                    actual.actual_bytes, expected_actual_bytes,
                    "{} actual_bytes mismatch",
                    fixture.id
                );
            }
        }
        (
            "PostStateRootMismatch",
            ConsensusError::Execution(ExecutionError::PostStateRootMismatch {
                expected: actual_expected,
                actual: actual_actual,
            }),
        ) => {
            assert_root_mismatch(
                fixture,
                expected.expected_root.as_ref(),
                expected.actual_root.as_ref(),
                actual_expected,
                actual_actual,
            );
        }
        (
            "ReceiptsRootMismatch",
            ConsensusError::Execution(ExecutionError::ReceiptsRootMismatch {
                expected: actual_expected,
                actual: actual_actual,
            }),
        ) => {
            assert_root_mismatch(
                fixture,
                expected.expected_root.as_ref(),
                expected.actual_root.as_ref(),
                actual_expected,
                actual_actual,
            );
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

fn assert_root_mismatch(
    fixture: &ConsensusVector,
    expected_root: Option<&String>,
    actual_root: Option<&String>,
    actual_expected: Root,
    actual_actual: Root,
) {
    if let Some(expected_root) = expected_root {
        assert_eq!(
            actual_expected,
            parse_root(expected_root),
            "{} expected_root mismatch",
            fixture.id
        );
    }
    if let Some(actual_root) = actual_root {
        assert_eq!(
            actual_actual,
            parse_root(actual_root),
            "{} actual_root mismatch",
            fixture.id
        );
    }
}

fn build_header(fixture: &ConsensusVector) -> CanonicalBlockHeader {
    let header = &fixture.input.header;

    assert!(
        header.block_number > 0,
        "{} block_number must stay positive in block fixtures",
        fixture.id
    );
    assert!(
        header.timestamp > 0,
        "{} timestamp must stay positive in block fixtures",
        fixture.id
    );
    assert_eq!(
        parse_root(&header.parent_root).len(),
        32,
        "{} parent_root must be a 32-byte root",
        fixture.id
    );

    CanonicalBlockHeader {
        block_root: fixture
            .input
            .computed_block_root
            .as_ref()
            .map_or([0u8; 32], |root| parse_root(root)),
        block_number: header.block_number,
        timestamp: header.timestamp,
        parent_root: parse_root(&header.parent_root),
        witness_bytes: header.witness_bytes,
        transactions_root: parse_root(&header.transactions_root),
        execution_witnesses_root: parse_root(&header.execution_witnesses_root),
        state_root: parse_root(&header.state_root),
        receipts_root: parse_root(&header.receipts_root),
        proposer_signature: parse_hex(&header.proposer_signature_hex),
        proposer_index_hint: Some(header.proposer_index),
    }
}

fn build_body_binding_case(
    fixture: &ConsensusVector,
) -> (CanonicalBlockHeader, CanonicalBlockBody) {
    let header = build_header(fixture);
    let body = fixture
        .input
        .body
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing body", fixture.id));

    assert!(
        !body.transaction_vector_ids.is_empty(),
        "{} body must reference at least one transaction fixture",
        fixture.id
    );
    assert!(
        body.transaction_vector_ids
            .iter()
            .all(|id| !id.trim().is_empty()),
        "{} transaction fixture ids must not be blank",
        fixture.id
    );

    (
        header,
        CanonicalBlockBody {
            transactions: Vec::new(),
            transactions_root: parse_root(
                fixture
                    .input
                    .computed_transactions_root
                    .as_ref()
                    .unwrap_or_else(|| {
                        panic!("{} is missing computed_transactions_root", fixture.id)
                    }),
            ),
        },
    )
}

fn build_sidecar_case(fixture: &ConsensusVector) -> (CanonicalBlockHeader, CanonicalBlockSidecar) {
    let header = build_header(fixture);
    let sidecar = fixture
        .input
        .sidecar
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing sidecar", fixture.id));

    assert!(
        !sidecar.witness_vector_ids.is_empty(),
        "{} sidecar must reference at least one witness fixture",
        fixture.id
    );
    assert!(
        sidecar
            .witness_vector_ids
            .iter()
            .all(|id| !id.trim().is_empty()),
        "{} witness fixture ids must not be blank",
        fixture.id
    );

    (
        header,
        CanonicalBlockSidecar {
            block_root: parse_root(&sidecar.block_root),
            execution_witnesses_root: parse_root(
                fixture
                    .input
                    .computed_sidecar_root
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} is missing computed_sidecar_root", fixture.id)),
            ),
            witnesses: Vec::new(),
        },
    )
}

fn build_execution_case(
    fixture: &ConsensusVector,
) -> (
    CanonicalBlockHeader,
    CanonicalBlockBody,
    CanonicalBlockSidecar,
    FixedExecutionEngine,
) {
    let (header, body) = build_body_binding_case(fixture);
    let (_, sidecar) = build_sidecar_case(fixture);
    let execution = fixture
        .input
        .execution_result
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing execution_result", fixture.id));

    (
        header,
        body,
        sidecar,
        FixedExecutionEngine {
            outcome: BlockExecutionOutcome {
                post_state_root: parse_root(&execution.post_state_root),
                receipts_root: parse_root(&execution.receipts_root),
                transaction_outcomes: vec![shell_execution::TransactionExecutionOutcome {
                    transaction_root: [0x11; 32],
                    post_state_root: parse_root(&execution.post_state_root),
                    receipt: ExecutionReceipt {
                        status_code: 1,
                        output: vec![0x22],
                    },
                }],
            },
        },
    )
}

fn fixture_paths() -> Vec<PathBuf> {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/blocks");
    fs::read_dir(&vectors_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", vectors_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect()
}

fn load_fixture(path: &Path) -> ConsensusVector {
    let bytes =
        fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn parse_root(value: &str) -> Root {
    let bytes = parse_hex(value);
    assert_eq!(
        bytes.len(),
        32,
        "expected 32-byte root, got {}",
        bytes.len()
    );
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}

fn parse_hex(value: &str) -> Vec<u8> {
    let hex = value
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("hex value must start with 0x: {value}"));
    assert!(
        hex.len().is_multiple_of(2),
        "hex value must have an even number of digits: {value}"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk).expect("hex chunk must stay utf8");
            u8::from_str_radix(text, 16)
                .unwrap_or_else(|err| panic!("invalid hex byte {text:?}: {err}"))
        })
        .collect()
}
