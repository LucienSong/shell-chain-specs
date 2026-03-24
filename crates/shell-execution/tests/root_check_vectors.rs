use std::cell::{Cell, RefCell};

use shell_execution::{
    BlockExecutionOutcome, CommittedExecutionRoots, ExecutionError, ExecutionReceipt,
    StatelessBlockExecutor, TransactionExecutionPlan, TransactionExecutor,
};
use shell_fixtures::{
    compute_execution_witnesses_root, compute_transactions_root, load_fixture,
    load_transaction_fixture_by_id, load_witness_fixture_by_id, parse_hex, parse_root,
    root_check_fixture_paths, RootCheckExpectedError, RootCheckVector,
};
use shell_primitives::{ProtocolObject, Root, StateKey, StateWitness, TransactionEnvelope};
use shell_state::{
    compare_state_keys, InMemoryAccumulator, StateAccumulator, StatePatch, StateTransitionApplier,
    StateTransitionOutcome, WitnessVerifier,
};

#[derive(Clone)]
struct ResolvedStep {
    transaction_root: Root,
    key: StateKey,
    new_leaf_value: Vec<u8>,
    receipt_status_code: u8,
    receipt_output: Vec<u8>,
}

struct ResolvedRootCheck {
    transactions: Vec<TransactionEnvelope>,
    witnesses: Vec<StateWitness>,
    materialized_state: Vec<(StateKey, Vec<u8>)>,
    pre_state_root: Root,
    steps: Vec<ResolvedStep>,
}

struct FixtureTransactionExecutor {
    steps: Vec<ResolvedStep>,
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

struct FixtureStateTransitionApplier {
    accumulator: RefCell<InMemoryAccumulator>,
}

impl StateTransitionApplier for FixtureStateTransitionApplier {
    fn apply_transition(
        &self,
        pre_state_root: &Root,
        patch: &StatePatch,
    ) -> Result<StateTransitionOutcome, shell_state::StateError> {
        let mut accumulator = self.accumulator.borrow_mut();
        assert_eq!(
            accumulator.state_root(),
            *pre_state_root,
            "execution pre_state_root drifted from the fixture accumulator"
        );
        let post_state_root = accumulator.apply_transition(patch)?;
        Ok(StateTransitionOutcome { post_state_root })
    }
}

#[test]
fn end_to_end_root_check_vectors_cover_execution_commitments() {
    let mut paths = root_check_fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one root-check fixture under vectors/root-checks"
    );

    for path in paths {
        let fixture: RootCheckVector = load_fixture(&path);
        let resolved = resolve_fixture(&fixture);
        let outcome = execute_fixture(&resolved);
        let committed = CommittedExecutionRoots {
            state_root: parse_root(&fixture.input.header.state_root),
            receipts_root: parse_root(&fixture.input.header.receipts_root),
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
            fixture.rule, "witness_execution_consensus_root_check",
            "{} must declare the end-to-end root-check rule",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-consensus",
            "{} must stay owned by shell-consensus",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "{} must document the invariant it covers",
            fixture.id
        );

        match fixture.expected_outcome.as_str() {
            "accept" => outcome
                .ensure_matches(&committed)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id)),
            "reject" => {
                let expected = fixture
                    .expected_error
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));
                let err = outcome
                    .ensure_matches(&committed)
                    .expect_err(&format!("{} should reject but accepted", fixture.id));
                assert_execution_error(&fixture, expected, err);
            }
            other => panic!("unsupported expected_outcome {other:?} in {}", fixture.id),
        }
    }
}

fn resolve_fixture(fixture: &RootCheckVector) -> ResolvedRootCheck {
    let transactions = fixture
        .input
        .body
        .transaction_vector_ids
        .iter()
        .map(|id| {
            let vector = load_transaction_fixture_by_id(id);
            assert_eq!(
                vector.expected_outcome, "accept",
                "{} references non-accept transaction fixture {}",
                fixture.id, id
            );
            vector.envelope()
        })
        .collect::<Vec<_>>();
    let computed_transactions_root =
        compute_transactions_root(&transactions).unwrap_or_else(|err| {
            panic!(
                "{} failed to compute transactions_root: {err:?}",
                fixture.id
            )
        });
    let expected_transactions_root = parse_root(&fixture.transactions_root);
    assert_eq!(
        computed_transactions_root, expected_transactions_root,
        "{} computed transactions_root drifted from the fixture root",
        fixture.id
    );
    assert_eq!(
        parse_root(&fixture.input.header.transactions_root),
        expected_transactions_root,
        "{} header transactions_root drifted from the fixture root",
        fixture.id
    );

    let witness_vectors = fixture
        .input
        .sidecar
        .witness_vector_ids
        .iter()
        .map(|id| {
            let vector = load_witness_fixture_by_id(id);
            assert_eq!(
                vector.expected_outcome, "accept",
                "{} references non-accept witness fixture {}",
                fixture.id, id
            );
            vector
        })
        .collect::<Vec<_>>();
    let witnesses = witness_vectors
        .iter()
        .map(|vector| {
            vector.witness().unwrap_or_else(|| {
                panic!(
                    "{} witness fixture must contain a single witness",
                    vector.id
                )
            })
        })
        .collect::<Vec<_>>();
    let computed_witnesses_root = compute_execution_witnesses_root(&witnesses);
    let expected_witnesses_root = parse_root(&fixture.execution_witnesses_root);
    assert_eq!(
        computed_witnesses_root, expected_witnesses_root,
        "{} computed execution_witnesses_root drifted from the fixture root",
        fixture.id
    );
    assert_eq!(
        parse_root(&fixture.input.header.execution_witnesses_root),
        expected_witnesses_root,
        "{} header execution_witnesses_root drifted from the fixture root",
        fixture.id
    );

    let base_materialized = canonical_materialized_state(
        &fixture.id,
        &witness_vectors
            .first()
            .unwrap_or_else(|| panic!("{} must reference at least one witness fixture", fixture.id))
            .materialized_state(),
    );
    let pre_state_root = witness_vectors
        .first()
        .and_then(|vector| vector.expected_state_root())
        .unwrap_or_else(|| {
            panic!(
                "{} witness fixture must declare expected_state_root",
                fixture.id
            )
        });
    let witness_accumulator = materialize_accumulator(&base_materialized, &fixture.id);
    assert_eq!(
        witness_accumulator.state_root(),
        pre_state_root,
        "{} witness pre-state root drifted from the witness fixtures",
        fixture.id
    );
    witness_accumulator
        .verify_witnesses(&witnesses, &pre_state_root)
        .unwrap_or_else(|err| panic!("{} witness verification failed: {err:?}", fixture.id));

    for vector in witness_vectors.iter().skip(1) {
        assert_eq!(
            vector.expected_state_root(),
            Some(pre_state_root),
            "{} witness fixtures must agree on expected_state_root",
            fixture.id
        );
        assert_eq!(
            canonical_materialized_state(&fixture.id, &vector.materialized_state()),
            base_materialized,
            "{} witness fixtures must agree on materialized_state",
            fixture.id
        );
    }

    let steps = fixture
        .input
        .execution
        .steps
        .iter()
        .zip(fixture.input.body.transaction_vector_ids.iter())
        .zip(transactions.iter())
        .map(|((step, transaction_id), transaction)| {
            assert_eq!(
                &step.transaction_vector_id, transaction_id,
                "{} execution steps must stay aligned with body.transaction_vector_ids",
                fixture.id
            );
            let witness = witness_vectors
                .iter()
                .find(|vector| vector.id == step.witness_vector_id)
                .and_then(|vector| vector.witness())
                .unwrap_or_else(|| {
                    panic!(
                        "{} execution step references missing witness fixture {}",
                        fixture.id, step.witness_vector_id
                    )
                });
            let transaction_root = transaction
                .canonical_root()
                .unwrap_or_else(|err| panic!("{} transaction root failed: {err:?}", fixture.id));

            ResolvedStep {
                transaction_root,
                key: witness.key,
                new_leaf_value: parse_hex(&step.new_leaf_value_hex),
                receipt_status_code: step.receipt_status_code,
                receipt_output: parse_hex(&step.receipt_output_hex),
            }
        })
        .collect::<Vec<_>>();

    assert_eq!(
        steps.len(),
        transactions.len(),
        "{} execution steps must cover each transaction exactly once",
        fixture.id
    );

    ResolvedRootCheck {
        transactions,
        witnesses,
        materialized_state: base_materialized,
        pre_state_root,
        steps,
    }
}

fn execute_fixture(resolved: &ResolvedRootCheck) -> BlockExecutionOutcome {
    let executor = StatelessBlockExecutor::new();
    let planner = FixtureTransactionExecutor {
        steps: resolved.steps.clone(),
        cursor: Cell::new(0),
    };
    let applier = FixtureStateTransitionApplier {
        accumulator: RefCell::new(materialize_accumulator(
            &resolved.materialized_state,
            "root-check execution",
        )),
    };
    let witness_accumulator = materialize_accumulator(
        &resolved.materialized_state,
        "root-check witness verification",
    );
    witness_accumulator
        .verify_witnesses(&resolved.witnesses, &resolved.pre_state_root)
        .expect("resolved witnesses must verify before execution");

    executor
        .execute_block(
            &resolved.pre_state_root,
            &resolved.transactions,
            &planner,
            &applier,
        )
        .expect("fixture execution should succeed")
}

fn canonical_materialized_state(
    fixture_id: &str,
    materialized_state: &[(StateKey, Vec<u8>)],
) -> Vec<(StateKey, Vec<u8>)> {
    let mut canonical = materialized_state.to_vec();
    canonical.sort_by(|left, right| compare_state_keys(&left.0, &right.0));
    assert!(
        !canonical.is_empty(),
        "{} must materialize at least one pre-state leaf",
        fixture_id
    );
    canonical
}

fn materialize_accumulator(
    materialized_state: &[(StateKey, Vec<u8>)],
    fixture_id: &str,
) -> InMemoryAccumulator {
    let mut accumulator = InMemoryAccumulator::new();
    accumulator
        .apply_transition(&StatePatch {
            accesses: materialized_state
                .iter()
                .map(|(key, _)| key.clone())
                .collect(),
            new_values: materialized_state
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
        })
        .unwrap_or_else(|err| {
            panic!("{fixture_id} failed to materialize reference state: {err:?}")
        });
    accumulator
}

fn assert_execution_error(
    fixture: &RootCheckVector,
    expected: &RootCheckExpectedError,
    err: ExecutionError,
) {
    match (&*expected.kind, err) {
        (
            "PostStateRootMismatch",
            ExecutionError::PostStateRootMismatch {
                expected: actual_expected,
                actual: actual_actual,
            },
        )
        | (
            "ReceiptsRootMismatch",
            ExecutionError::ReceiptsRootMismatch {
                expected: actual_expected,
                actual: actual_actual,
            },
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
            "{} expected execution error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}
