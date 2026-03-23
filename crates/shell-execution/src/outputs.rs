use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use shell_primitives::{MockProgressiveByteList, Root};

use crate::errors::ExecutionError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionReceipt {
    pub status_code: u8,
    pub output: MockProgressiveByteList,
}

impl ExecutionReceipt {
    pub fn canonical_root(&self) -> Root {
        let mut hasher = Sha256::new();
        hasher.update(b"shell-execution/receipt-v1");
        hasher.update([self.status_code]);
        hasher.update((self.output.len() as u64).to_be_bytes());
        hasher.update(&self.output);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionExecutionOutcome {
    pub transaction_root: Root,
    pub post_state_root: Root,
    pub receipt: ExecutionReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionOutcome {
    pub post_state_root: Root,
    pub receipts_root: Root,
    pub transaction_outcomes: Vec<TransactionExecutionOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedExecutionRoots {
    pub state_root: Root,
    pub receipts_root: Root,
}

pub fn compute_receipts_root(receipts: &[ExecutionReceipt]) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(b"shell-execution/receipts-root-v1");
    hasher.update((receipts.len() as u64).to_be_bytes());

    for receipt in receipts {
        hasher.update(receipt.canonical_root());
    }

    hasher.finalize().into()
}

impl BlockExecutionOutcome {
    pub fn ensure_matches(
        &self,
        committed_roots: &CommittedExecutionRoots,
    ) -> Result<(), ExecutionError> {
        if self.post_state_root != committed_roots.state_root {
            return Err(ExecutionError::PostStateRootMismatch {
                expected: committed_roots.state_root,
                actual: self.post_state_root,
            });
        }

        if self.receipts_root != committed_roots.receipts_root {
            return Err(ExecutionError::ReceiptsRootMismatch {
                expected: committed_roots.receipts_root,
                actual: self.receipts_root,
            });
        }

        Ok(())
    }
}
