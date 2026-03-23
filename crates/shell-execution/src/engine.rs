use alloc::vec::Vec;

use shell_primitives::{ProtocolObject, Root, TransactionEnvelope};
use shell_state::{StatePatch, StateTransitionApplier};

use crate::errors::ExecutionError;
use crate::outputs::{
    compute_receipts_root, BlockExecutionOutcome, ExecutionReceipt, TransactionExecutionOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionExecutionPlan {
    pub state_patch: StatePatch,
    pub receipt: ExecutionReceipt,
}

pub trait TransactionExecutor {
    fn execute_transaction(
        &self,
        pre_state_root: &Root,
        transaction: &TransactionEnvelope,
    ) -> Result<TransactionExecutionPlan, ExecutionError>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StatelessBlockExecutor;

impl StatelessBlockExecutor {
    pub fn new() -> Self {
        Self
    }

    pub fn execute_block(
        &self,
        pre_state_root: &Root,
        transactions: &[TransactionEnvelope],
        executor: &dyn TransactionExecutor,
        state_applier: &dyn StateTransitionApplier,
    ) -> Result<BlockExecutionOutcome, ExecutionError> {
        let mut current_state_root = *pre_state_root;
        let mut receipts = Vec::with_capacity(transactions.len());
        let mut transaction_outcomes = Vec::with_capacity(transactions.len());

        for transaction in transactions {
            let transaction_root = transaction
                .canonical_root()
                .map_err(ExecutionError::TransactionRoot)?;
            let plan = executor.execute_transaction(&current_state_root, transaction)?;
            let transition_outcome = state_applier
                .apply_transition(&current_state_root, &plan.state_patch)
                .map_err(ExecutionError::StateTransition)?;

            current_state_root = transition_outcome.post_state_root;
            receipts.push(plan.receipt.clone());
            transaction_outcomes.push(TransactionExecutionOutcome {
                transaction_root,
                post_state_root: current_state_root,
                receipt: plan.receipt,
            });
        }

        Ok(BlockExecutionOutcome {
            post_state_root: current_state_root,
            receipts_root: compute_receipts_root(&receipts),
            transaction_outcomes,
        })
    }
}
