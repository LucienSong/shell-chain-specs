use shell_execution::{
    BlockExecutionOutcome, CommittedExecutionRoots, ExecutionError, ExecutionReceipt,
    PlannedTransaction, PlannedTransactionExecutor, StatelessBlockExecutor,
    TransactionExecutionPlan,
};
use shell_fixtures::{
    load_root_check_scenario, materialize_root_check_accumulator, parse_root,
    root_check_fixture_paths, RootCheckExpectedError, RootCheckScenario, RootCheckVector,
};
use shell_state::{ReferenceStateApplier, StatePatch, WitnessVerifier};

#[test]
fn end_to_end_root_check_vectors_cover_execution_commitments() {
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
        let outcome = execute_fixture(&resolved);
        let committed = CommittedExecutionRoots {
            state_root: resolved.header.state_root,
            receipts_root: resolved.header.receipts_root,
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

fn execute_fixture(resolved: &RootCheckScenario) -> BlockExecutionOutcome {
    let executor = StatelessBlockExecutor::new();
    let planner = PlannedTransactionExecutor::new(
        resolved
            .steps
            .iter()
            .map(|step| PlannedTransaction {
                transaction_root: step.transaction_root,
                plan: TransactionExecutionPlan {
                    state_patch: StatePatch {
                        accesses: vec![step.key.clone()],
                        new_values: vec![step.new_leaf_value.clone()],
                    },
                    receipt: ExecutionReceipt {
                        status_code: step.receipt_status_code,
                        output: step.receipt_output.clone(),
                    },
                },
            })
            .collect(),
    );
    let applier = ReferenceStateApplier::new(materialize_root_check_accumulator(
        &resolved.materialized_state,
        "root-check execution",
    ));
    let witness_accumulator = materialize_root_check_accumulator(
        &resolved.materialized_state,
        "root-check witness verification",
    );
    witness_accumulator
        .verify_witnesses(&resolved.witnesses, &resolved.pre_state_root)
        .expect("resolved witnesses must verify before execution");

    let outcome = executor
        .execute_block(
            &resolved.pre_state_root,
            &resolved.transactions,
            &planner,
            &applier,
        )
        .expect("fixture execution should succeed");
    planner
        .ensure_exhausted()
        .expect("fixture execution must consume every planned step");
    outcome
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
