use std::cell::Cell;

use shell_consensus::{
    BlockExecutionEngine, BlockImportConfig, BlockImportPipeline, BlockImportServices,
    CanonicalBlockBody, CanonicalBlockHeader, CanonicalBlockSidecar, ConsensusBody, ConsensusError,
    ConsensusHeader, ConsensusSidecar, TransactionRevalidator, WitnessPreparer,
};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
    UnsupportedSchemeError,
};
use shell_execution::{
    BlockExecutionOutcome, ExecutionError, ExecutionReceipt, StatelessBlockExecutor,
    TransactionExecutionPlan, TransactionExecutor,
};
use shell_fixtures::{
    load_root_check_scenario, materialize_root_check_accumulator, parse_root,
    root_check_fixture_paths, RootCheckExpectedError, RootCheckScenario, RootCheckScenarioStep,
    RootCheckVector,
};
use shell_mempool::{MultiAuthorizationPolicy, ValidationError};
use shell_primitives::{
    ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver, ProtocolObject, Root, StateKey, StateWitness, TransactionEnvelope,
};
use shell_state::{ReferenceStateApplier, StatePatch, WitnessVerifier};

struct CanonicalBlock {
    header: CanonicalBlockHeader,
    body: CanonicalBlockBody,
    sidecar: CanonicalBlockSidecar,
}

struct CountingResolver {
    calls: Cell<usize>,
}

impl CountingResolver {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl ProposerCredentialResolver for CountingResolver {
    fn resolve_proposer_credential(
        &self,
        _query: ProposerCredentialQuery,
    ) -> Result<ProposerCredential, ProposerCredentialResolutionError> {
        self.calls.set(self.calls.get() + 1);
        Ok(ProposerCredential {
            scheme_id: 1,
            public_key_material: vec![0x11; 32],
        })
    }
}

struct AcceptingDispatcher {
    validator_calls: Cell<usize>,
}

impl AcceptingDispatcher {
    fn validator_calls(&self) -> usize {
        self.validator_calls.get()
    }
}

impl SignatureDispatcher for AcceptingDispatcher {
    fn register_verifier(
        &mut self,
        _verifier: Box<dyn SignatureVerifier>,
    ) -> Option<Box<dyn SignatureVerifier>> {
        None
    }

    fn verifier(&self, _scheme_id: u8) -> Option<&dyn SignatureVerifier> {
        None
    }

    fn verify_transaction_authorization(
        &self,
        scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedScheme(UnsupportedSchemeError {
            scheme_id,
        }))
    }

    fn verify_validator_message(
        &self,
        _scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.validator_calls.set(self.validator_calls.get() + 1);
        Ok(())
    }
}

struct CountingRevalidator {
    calls: Cell<usize>,
}

impl CountingRevalidator {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl TransactionRevalidator for CountingRevalidator {
    fn revalidate(
        &self,
        _transaction: &TransactionEnvelope,
        _multi_authorization_policy: MultiAuthorizationPolicy,
    ) -> Result<(), ValidationError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

struct FixtureWitnessPreparer {
    materialized_state: Vec<(StateKey, Vec<u8>)>,
    witnesses: Vec<StateWitness>,
    pre_state_root: Root,
    calls: Cell<usize>,
}

impl FixtureWitnessPreparer {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl WitnessPreparer for FixtureWitnessPreparer {
    fn prepare_witness(
        &self,
        _header: &dyn ConsensusHeader,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<(), shell_state::StateError> {
        self.calls.set(self.calls.get() + 1);
        let accumulator = materialize_root_check_accumulator(
            &self.materialized_state,
            "root-check witness preparation",
        );
        accumulator.verify_witnesses(&self.witnesses, &self.pre_state_root)
    }
}

struct FixtureExecutionEngine {
    materialized_state: Vec<(StateKey, Vec<u8>)>,
    pre_state_root: Root,
    steps: Vec<RootCheckScenarioStep>,
    calls: Cell<usize>,
}

impl FixtureExecutionEngine {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl BlockExecutionEngine for FixtureExecutionEngine {
    fn execute_block(
        &self,
        _header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<BlockExecutionOutcome, ExecutionError> {
        self.calls.set(self.calls.get() + 1);

        let executor = StatelessBlockExecutor::new();
        let planner = FixtureTransactionExecutor {
            steps: self.steps.clone(),
            cursor: Cell::new(0),
        };
        let applier = ReferenceStateApplier::new(materialize_root_check_accumulator(
            &self.materialized_state,
            "root-check execution",
        ));

        executor.execute_block(
            &self.pre_state_root,
            body.transactions(),
            &planner,
            &applier,
        )
    }
}

struct FixtureTransactionExecutor {
    steps: Vec<RootCheckScenarioStep>,
    cursor: Cell<usize>,
}

impl TransactionExecutor for FixtureTransactionExecutor {
    fn execute_transaction(
        &self,
        _pre_state_root: &Root,
        transaction: &TransactionEnvelope,
    ) -> Result<TransactionExecutionPlan, ExecutionError> {
        let index = self.cursor.get();
        let step = self
            .steps
            .get(index)
            .unwrap_or_else(|| panic!("missing execution step for transaction index {index}"));
        let transaction_root = transaction
            .canonical_root()
            .map_err(ExecutionError::TransactionRoot)?;
        assert_eq!(
            transaction_root, step.transaction_root,
            "execution step transaction_root drifted"
        );
        self.cursor.set(index + 1);

        Ok(TransactionExecutionPlan {
            state_patch: StatePatch {
                accesses: vec![step.key.clone()],
                new_values: vec![step.new_leaf_value.clone()],
            },
            receipt: ExecutionReceipt {
                status_code: step.receipt_status_code,
                output: step.receipt_output.clone(),
            },
        })
    }
}

#[test]
fn root_check_vectors_cover_consensus_execution_comparison_end_to_end() {
    let mut paths = root_check_fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one root-check fixture under vectors/root-checks"
    );

    for path in paths {
        let loaded = load_root_check_scenario(&path);
        let fixture: RootCheckVector = loaded.fixture;
        let resolved = loaded.scenario;
        let block = canonical_block_from_scenario(&resolved);
        let pipeline = BlockImportPipeline::new(BlockImportConfig::default());
        let resolver = CountingResolver {
            calls: Cell::new(0),
        };
        let dispatcher = AcceptingDispatcher {
            validator_calls: Cell::new(0),
        };
        let revalidator = CountingRevalidator {
            calls: Cell::new(0),
        };
        let preparer = FixtureWitnessPreparer {
            materialized_state: resolved.materialized_state.clone(),
            witnesses: resolved.witnesses.clone(),
            pre_state_root: resolved.pre_state_root,
            calls: Cell::new(0),
        };
        let engine = FixtureExecutionEngine {
            materialized_state: resolved.materialized_state.clone(),
            pre_state_root: resolved.pre_state_root,
            steps: resolved.steps.clone(),
            calls: Cell::new(0),
        };

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "root-check",
            "{} must declare category 'root-check'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-consensus",
            "{} must stay owned by shell-consensus",
            fixture.id
        );

        let result = pipeline.import_block(
            &block.header,
            &block.body,
            &block.sidecar,
            BlockImportServices {
                resolver: &resolver,
                dispatcher: &dispatcher,
                revalidator: &revalidator,
                preparer: &preparer,
                execution_engine: &engine,
            },
        );

        match fixture.expected_outcome.as_str() {
            "accept" => {
                let outcome = result
                    .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
                assert_eq!(outcome.block_root, block.header.block_root);
                assert_eq!(outcome.post_state_root, block.header.state_root);
                assert_eq!(outcome.receipts_root, block.header.receipts_root);
            }
            "reject" => {
                let expected = fixture
                    .expected_error
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));
                let err = result.expect_err(&format!("{} should reject but accepted", fixture.id));
                assert_consensus_error(&fixture, expected, err);
            }
            other => panic!("unsupported expected_outcome {other:?} in {}", fixture.id),
        }

        assert_eq!(resolver.calls(), 1, "{} resolver calls drifted", fixture.id);
        assert_eq!(
            dispatcher.validator_calls(),
            1,
            "{} validator signature verifications drifted",
            fixture.id
        );
        assert_eq!(
            revalidator.calls(),
            block.body.transactions.len(),
            "{} transaction revalidations drifted",
            fixture.id
        );
        assert_eq!(
            preparer.calls(),
            1,
            "{} witness preparation count drifted",
            fixture.id
        );
        assert_eq!(
            engine.calls(),
            1,
            "{} execution call count drifted",
            fixture.id
        );
    }
}

fn canonical_block_from_scenario(resolved: &RootCheckScenario) -> CanonicalBlock {
    CanonicalBlock {
        header: CanonicalBlockHeader {
            block_root: resolved.header.block_root,
            block_number: resolved.header.block_number,
            timestamp: resolved.header.timestamp,
            parent_root: resolved.header.parent_root,
            witness_bytes: resolved.header.witness_bytes,
            transactions_root: resolved.header.transactions_root,
            execution_witnesses_root: resolved.header.execution_witnesses_root,
            state_root: resolved.header.state_root,
            receipts_root: resolved.header.receipts_root,
            proposer_signature: resolved.header.proposer_signature.clone(),
            proposer_index_hint: Some(resolved.header.proposer_index),
        },
        body: CanonicalBlockBody {
            transactions: resolved.transactions.clone(),
            transactions_root: resolved.header.transactions_root,
        },
        sidecar: CanonicalBlockSidecar {
            block_root: resolved.sidecar.block_root,
            execution_witnesses_root: resolved.header.execution_witnesses_root,
            witnesses: resolved.witnesses.clone(),
        },
    }
}

fn assert_consensus_error(
    fixture: &RootCheckVector,
    expected: &RootCheckExpectedError,
    err: ConsensusError,
) {
    match (&*expected.kind, err) {
        (
            "PostStateRootMismatch",
            ConsensusError::Execution(ExecutionError::PostStateRootMismatch {
                expected: actual_expected,
                actual: actual_actual,
            }),
        )
        | (
            "ReceiptsRootMismatch",
            ConsensusError::Execution(ExecutionError::ReceiptsRootMismatch {
                expected: actual_expected,
                actual: actual_actual,
            }),
        ) => {
            assert_eq!(
                actual_expected,
                parse_root(&expected.expected_root),
                "{} expected_root mismatch",
                fixture.id
            );
            assert_eq!(
                actual_actual,
                parse_root(&expected.actual_root),
                "{} actual_root mismatch",
                fixture.id
            );
        }
        (kind, actual) => panic!(
            "{} expected consensus error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}
