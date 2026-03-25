use shell_execution::{
    compute_receipts_root, BlockExecutionOutcome, ExecutionError, ExecutionReceipt,
    PlannedTransaction, PlannedTransactionExecutor, StatelessBlockExecutor,
    TransactionExecutionPlan,
};
use shell_fixtures::{
    execution_semantics_fixture_paths, load_fixture, load_transaction_fixture_by_id,
    materialize_root_check_accumulator, parse_root, ExecutionSemanticsExpectedError,
    ExecutionSemanticsVector,
};
use shell_primitives::ProtocolObject;
use shell_state::{ReferenceStateApplier, StateAccumulator, StateError, StateTransitionApplier};

#[test]
fn execution_semantics_vectors_cover_reference_local_execution_contracts() {
    let mut paths = execution_semantics_fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one execution-semantics fixture under vectors/execution-semantics"
    );

    for path in paths {
        let fixture: ExecutionSemanticsVector = load_fixture(&path);
        let execution = execute_fixture(&fixture);

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "execution-semantics",
            "{} category drifted",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-execution",
            "{} owner drifted",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "{} must document the invariant it covers",
            fixture.id
        );

        match fixture.expected_outcome.as_str() {
            "accept" => assert_accept_fixture(&fixture, execution),
            "reject" => assert_reject_fixture(&fixture, execution),
            other => panic!("unsupported expected_outcome {other:?} in {}", fixture.id),
        }
    }
}

struct FixtureExecution {
    pre_state_root: [u8; 32],
    planner_exhausted: bool,
    final_applier_root: [u8; 32],
    manual_post_state_roots: Vec<[u8; 32]>,
    manual_receipt_roots: Vec<[u8; 32]>,
    outcome: Result<BlockExecutionOutcome, ExecutionError>,
}

fn execute_fixture(fixture: &ExecutionSemanticsVector) -> FixtureExecution {
    let initial_materialized_state = fixture.materialized_state();
    let pre_state_root =
        materialize_root_check_accumulator(&initial_materialized_state, &fixture.id).state_root();
    let transactions = fixture
        .input
        .transaction_vector_ids
        .iter()
        .map(|id| load_transaction_fixture_by_id(id).envelope())
        .collect::<Vec<_>>();
    let planned_transactions = fixture
        .input
        .steps
        .iter()
        .map(|step| {
            let transaction =
                load_transaction_fixture_by_id(&step.transaction_vector_id).envelope();
            PlannedTransaction::from_transaction(
                &transaction,
                TransactionExecutionPlan {
                    state_patch: step.state_patch(),
                    receipt: ExecutionReceipt {
                        status_code: step.receipt_status_code,
                        output: step.receipt_output(),
                    },
                },
            )
            .unwrap_or_else(|err| {
                panic!("{} could not hash planned transaction: {err:?}", fixture.id)
            })
        })
        .collect::<Vec<_>>();
    let planner = PlannedTransactionExecutor::new(planned_transactions);
    let applier = ReferenceStateApplier::new(materialize_root_check_accumulator(
        &initial_materialized_state,
        &fixture.id,
    ));
    let outcome = StatelessBlockExecutor::new().execute_block(
        &pre_state_root,
        &transactions,
        &planner,
        &applier,
    );
    let planner_exhausted = planner.is_exhausted();
    let final_applier_root = applier.state_root();

    let manual_applier = ReferenceStateApplier::new(materialize_root_check_accumulator(
        &initial_materialized_state,
        &format!("{} manual", fixture.id),
    ));
    let mut current_state_root = pre_state_root;
    let mut manual_post_state_roots = Vec::with_capacity(fixture.input.steps.len());
    let mut manual_receipt_roots = Vec::with_capacity(fixture.input.steps.len());

    for step in &fixture.input.steps {
        let receipt = ExecutionReceipt {
            status_code: step.receipt_status_code,
            output: step.receipt_output(),
        };
        manual_receipt_roots.push(receipt.canonical_root());
        let transition_outcome =
            manual_applier.apply_transition(&current_state_root, &step.state_patch());

        match transition_outcome {
            Ok(transition_outcome) => {
                current_state_root = transition_outcome.post_state_root;
                manual_post_state_roots.push(current_state_root);
            }
            Err(_) => break,
        }
    }

    FixtureExecution {
        pre_state_root,
        planner_exhausted,
        final_applier_root,
        manual_post_state_roots,
        manual_receipt_roots,
        outcome,
    }
}

fn assert_accept_fixture(fixture: &ExecutionSemanticsVector, execution: FixtureExecution) {
    let outcome = execution
        .outcome
        .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
    let expected_pre_state_root = parse_root(&fixture.pre_state_root);
    let expected_post_state_root = parse_root(
        fixture
            .post_state_root
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing post_state_root", fixture.id)),
    );
    let expected_receipts_root = parse_root(
        fixture
            .receipts_root
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing receipts_root", fixture.id)),
    );

    assert_eq!(
        execution.pre_state_root, expected_pre_state_root,
        "{} pre_state_root mismatch",
        fixture.id
    );
    assert_eq!(
        fixture.input.transaction_vector_ids.len(),
        fixture.input.steps.len(),
        "{} transaction list must stay aligned with execution steps",
        fixture.id
    );
    assert_eq!(
        fixture.input.transaction_vector_ids,
        fixture
            .input
            .steps
            .iter()
            .map(|step| step.transaction_vector_id.clone())
            .collect::<Vec<_>>(),
        "{} transaction_vector_ids must match step order",
        fixture.id
    );
    assert_eq!(
        execution.planner_exhausted,
        fixture.planner_exhausted.unwrap_or(true),
        "{} planner exhaustion drifted",
        fixture.id
    );
    assert_eq!(
        execution.final_applier_root, expected_post_state_root,
        "{} applier root mismatch",
        fixture.id
    );
    assert_eq!(
        outcome.post_state_root, expected_post_state_root,
        "{} post_state_root mismatch",
        fixture.id
    );
    assert_eq!(
        outcome.receipts_root, expected_receipts_root,
        "{} receipts_root mismatch",
        fixture.id
    );
    assert_eq!(
        compute_receipts_root(
            &fixture
                .input
                .steps
                .iter()
                .map(|step| ExecutionReceipt {
                    status_code: step.receipt_status_code,
                    output: step.receipt_output(),
                })
                .collect::<Vec<_>>()
        ),
        expected_receipts_root,
        "{} fixture receipts_root drifted from canonical receipt hashing",
        fixture.id
    );
    assert_eq!(
        outcome.transaction_outcomes.len(),
        fixture.input.steps.len(),
        "{} transaction outcome count mismatch",
        fixture.id
    );
    assert_eq!(
        execution.manual_post_state_roots.len(),
        fixture.input.steps.len(),
        "{} manual state progression should cover every step",
        fixture.id
    );

    for (index, (step, transaction_outcome)) in fixture
        .input
        .steps
        .iter()
        .zip(outcome.transaction_outcomes.iter())
        .enumerate()
    {
        let transaction = load_transaction_fixture_by_id(&step.transaction_vector_id).envelope();
        let expected_transaction_root = transaction.canonical_root().unwrap_or_else(|err| {
            panic!(
                "{} failed to hash transaction at step {index}: {err:?}",
                fixture.id
            )
        });
        let expected_post_state_root =
            parse_root(step.expected_post_state_root.as_deref().unwrap_or_else(|| {
                panic!(
                    "{} step {index} is missing expected_post_state_root",
                    fixture.id
                )
            }));
        let expected_receipt_root =
            parse_root(step.expected_receipt_root.as_deref().unwrap_or_else(|| {
                panic!(
                    "{} step {index} is missing expected_receipt_root",
                    fixture.id
                )
            }));

        assert_eq!(
            transaction_outcome.transaction_root, expected_transaction_root,
            "{} step {index} transaction_root mismatch",
            fixture.id
        );
        assert_eq!(
            transaction_outcome.post_state_root, expected_post_state_root,
            "{} step {index} post_state_root mismatch",
            fixture.id
        );
        assert_eq!(
            execution.manual_post_state_roots[index], expected_post_state_root,
            "{} step {index} manual post_state_root mismatch",
            fixture.id
        );
        assert_eq!(
            transaction_outcome.receipt.status_code, step.receipt_status_code,
            "{} step {index} receipt status drifted",
            fixture.id
        );
        assert_eq!(
            transaction_outcome.receipt.output,
            step.receipt_output(),
            "{} step {index} receipt output drifted",
            fixture.id
        );
        assert_eq!(
            transaction_outcome.receipt.canonical_root(),
            expected_receipt_root,
            "{} step {index} receipt root mismatch",
            fixture.id
        );
        assert_eq!(
            execution.manual_receipt_roots[index], expected_receipt_root,
            "{} step {index} manual receipt root mismatch",
            fixture.id
        );
    }
}

fn assert_reject_fixture(fixture: &ExecutionSemanticsVector, execution: FixtureExecution) {
    let err = execution
        .outcome
        .expect_err(&format!("{} should reject but accepted", fixture.id));
    let expected = fixture
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));
    let expected_pre_state_root = parse_root(&fixture.pre_state_root);
    let expected_post_state_root = parse_root(
        fixture
            .post_state_root
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing post_state_root", fixture.id)),
    );

    assert_eq!(
        execution.pre_state_root, expected_pre_state_root,
        "{} pre_state_root mismatch",
        fixture.id
    );
    assert_eq!(
        execution.final_applier_root, expected_post_state_root,
        "{} error path state root mismatch",
        fixture.id
    );
    assert_eq!(
        execution.planner_exhausted,
        fixture.planner_exhausted.unwrap_or(false),
        "{} planner exhaustion mismatch on reject path",
        fixture.id
    );
    assert_execution_error(fixture, expected, err);
}

fn assert_execution_error(
    fixture: &ExecutionSemanticsVector,
    expected: &ExecutionSemanticsExpectedError,
    err: ExecutionError,
) {
    match (&*expected.kind, err) {
        (
            "NonCanonicalWitnessOrdering",
            ExecutionError::StateTransition(StateError::NonCanonicalWitnessOrdering(actual)),
        ) => {
            assert_eq!(
                Some(actual.index),
                expected.index,
                "{} index mismatch",
                fixture.id
            );
            assert_eq!(
                Some(actual.context),
                expected.context.as_deref(),
                "{} context mismatch",
                fixture.id
            );
        }
        (kind, actual) => panic!(
            "{} expected execution error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}
