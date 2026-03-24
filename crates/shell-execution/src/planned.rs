use alloc::vec::Vec;
use core::cell::Cell;

use shell_primitives::{ProtocolObject, Root, TransactionEnvelope};

use crate::{ExecutionError, TransactionExecutionPlan, TransactionExecutor};

/// Reference executor for documented or scripted transaction scenarios.
///
/// This replays preplanned transaction outcomes in order and is intended for
/// fixtures, harnesses, and other deterministic scenario drivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTransaction {
    pub transaction_root: Root,
    pub plan: TransactionExecutionPlan,
}

impl PlannedTransaction {
    pub fn from_transaction(
        transaction: &TransactionEnvelope,
        plan: TransactionExecutionPlan,
    ) -> Result<Self, ExecutionError> {
        let transaction_root = transaction
            .canonical_root()
            .map_err(ExecutionError::TransactionRoot)?;
        Ok(Self {
            transaction_root,
            plan,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PlannedTransactionExecutor {
    planned_transactions: Vec<PlannedTransaction>,
    next_index: Cell<usize>,
}

impl PlannedTransactionExecutor {
    pub fn new(planned_transactions: Vec<PlannedTransaction>) -> Self {
        Self {
            planned_transactions,
            next_index: Cell::new(0),
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.next_index.get() == self.planned_transactions.len()
    }

    pub fn ensure_exhausted(&self) -> Result<(), ExecutionError> {
        if self.is_exhausted() {
            return Ok(());
        }

        Err(ExecutionError::Executor(
            "unconsumed planned transaction steps",
        ))
    }
}

impl TransactionExecutor for PlannedTransactionExecutor {
    fn execute_transaction(
        &self,
        _pre_state_root: &Root,
        transaction: &TransactionEnvelope,
    ) -> Result<TransactionExecutionPlan, ExecutionError> {
        let index = self.next_index.get();
        let planned = self
            .planned_transactions
            .get(index)
            .ok_or(ExecutionError::Executor("missing planned transaction step"))?;
        let transaction_root = transaction
            .canonical_root()
            .map_err(ExecutionError::TransactionRoot)?;

        if transaction_root != planned.transaction_root {
            return Err(ExecutionError::Executor(
                "planned transaction root mismatch",
            ));
        }

        self.next_index.set(index + 1);
        Ok(planned.plan.clone())
    }
}
