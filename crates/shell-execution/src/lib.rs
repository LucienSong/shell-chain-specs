#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod engine;
pub mod errors;
pub mod outputs;
pub mod state_view;

pub use crate::engine::{StatelessBlockExecutor, TransactionExecutionPlan, TransactionExecutor};
pub use crate::errors::ExecutionError;
pub use crate::outputs::{
    compute_receipts_root, BlockExecutionOutcome, CommittedExecutionRoots, ExecutionReceipt,
    TransactionExecutionOutcome,
};
pub use crate::state_view::ExecutionStateView;

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use sha2::{Digest, Sha256};

    use super::*;
    use shell_primitives::{
        BasicTransactionPayload, ExecutionAddress, ProtocolObject, StateKey, StateMetadata,
        TransactionEnvelope, TransactionPayload, TransactionPayloadSsz, U256,
    };
    use shell_state::{StateError, StatePatch, StateTransitionApplier, StateTransitionOutcome};

    struct StubExecutionStateView {
        root: [u8; 32],
    }

    impl StateMetadata for StubExecutionStateView {
        fn account_nonce(&self, _address: &ExecutionAddress) -> Option<u64> {
            Some(9)
        }

        fn account_balance(&self, _address: &ExecutionAddress) -> Option<U256> {
            Some(U256([7; 32]))
        }
    }

    impl ExecutionStateView for StubExecutionStateView {
        fn state_root(&self) -> [u8; 32] {
            self.root
        }
    }

    struct StubTransactionExecutor;

    impl TransactionExecutor for StubTransactionExecutor {
        fn execute_transaction(
            &self,
            pre_state_root: &[u8; 32],
            transaction: &TransactionEnvelope,
        ) -> Result<TransactionExecutionPlan, ExecutionError> {
            let transaction_root = transaction
                .canonical_root()
                .map_err(ExecutionError::TransactionRoot)?;
            let marker = pre_state_root[0] ^ transaction_root[0];

            Ok(TransactionExecutionPlan {
                state_patch: StatePatch {
                    accesses: vec![StateKey::RawTreeKey(transaction_root)],
                    new_values: vec![vec![marker, transaction_root[1]]],
                },
                receipt: ExecutionReceipt {
                    status_code: 1,
                    output: vec![marker, transaction_root[2]],
                },
            })
        }
    }

    struct StubStateTransitionApplier;

    impl StateTransitionApplier for StubStateTransitionApplier {
        fn apply_transition(
            &self,
            pre_state_root: &[u8; 32],
            patch: &StatePatch,
        ) -> Result<StateTransitionOutcome, StateError> {
            let mut hasher = Sha256::new();
            hasher.update(b"shell-execution/test-transition-v1");
            hasher.update(pre_state_root);

            for (index, key) in patch.accesses.iter().enumerate() {
                let encoded_key = shell_primitives::encode_state_key(key);
                hasher.update((index as u64).to_be_bytes());
                hasher.update((encoded_key.as_slice().len() as u64).to_be_bytes());
                hasher.update(encoded_key.as_slice());
                hasher.update((patch.new_values[index].len() as u64).to_be_bytes());
                hasher.update(&patch.new_values[index]);
            }

            Ok(StateTransitionOutcome {
                post_state_root: hasher.finalize().into(),
            })
        }
    }

    fn sample_transaction(nonce: u64) -> TransactionEnvelope {
        TransactionEnvelope {
            payload: TransactionPayloadSsz::new(TransactionPayload::Basic(
                BasicTransactionPayload {
                    nonce,
                    gas_limit: 21_000 + nonce,
                    ..BasicTransactionPayload::default()
                },
            )),
            authorizations: vec![],
        }
    }

    #[test]
    fn transaction_executor_trait_is_object_safe() {
        let _: Box<dyn TransactionExecutor> = Box::new(StubTransactionExecutor);
    }

    #[test]
    fn execution_state_view_trait_is_object_safe() {
        let view: Box<dyn ExecutionStateView> = Box::new(StubExecutionStateView { root: [3; 32] });
        let address: ExecutionAddress = [0xAA; 20];

        assert_eq!(view.state_root(), [3; 32]);
        assert_eq!(view.account_nonce(&address), Some(9));
        assert_eq!(view.account_balance(&address), Some(U256([7; 32])));
    }

    #[test]
    fn block_execution_is_deterministic_for_identical_inputs() {
        let executor = StatelessBlockExecutor::new();
        let planner = StubTransactionExecutor;
        let applier = StubStateTransitionApplier;
        let transactions = [sample_transaction(1), sample_transaction(2)];

        let first = executor
            .execute_block(&[0; 32], &transactions, &planner, &applier)
            .expect("reference execution should succeed");
        let second = executor
            .execute_block(&[0; 32], &transactions, &planner, &applier)
            .expect("same inputs should stay deterministic");

        assert_eq!(first, second);
    }

    #[test]
    fn block_execution_preserves_block_order() {
        let executor = StatelessBlockExecutor::new();
        let planner = StubTransactionExecutor;
        let applier = StubStateTransitionApplier;
        let first = sample_transaction(1);
        let second = sample_transaction(2);

        let ordered = executor
            .execute_block(
                &[0; 32],
                &[first.clone(), second.clone()],
                &planner,
                &applier,
            )
            .expect("ordered block should execute");
        let reversed = executor
            .execute_block(&[0; 32], &[second, first], &planner, &applier)
            .expect("reordered block should also execute");

        assert_ne!(ordered.receipts_root, reversed.receipts_root);
        assert_ne!(ordered.post_state_root, reversed.post_state_root);
    }

    #[test]
    fn execution_outcome_compares_against_committed_roots() {
        let executor = StatelessBlockExecutor::new();
        let planner = StubTransactionExecutor;
        let applier = StubStateTransitionApplier;
        let outcome = executor
            .execute_block(&[0; 32], &[sample_transaction(7)], &planner, &applier)
            .expect("single-transaction execution should succeed");

        outcome
            .ensure_matches(&CommittedExecutionRoots {
                state_root: outcome.post_state_root,
                receipts_root: outcome.receipts_root,
            })
            .expect("matching committed roots should pass");

        let err = outcome
            .ensure_matches(&CommittedExecutionRoots {
                state_root: [0xFF; 32],
                receipts_root: outcome.receipts_root,
            })
            .expect_err("mismatched state root must fail");

        assert_eq!(
            err,
            ExecutionError::PostStateRootMismatch {
                expected: [0xFF; 32],
                actual: outcome.post_state_root,
            }
        );
    }
}
