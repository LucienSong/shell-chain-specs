use shell_consensus::{
    CanonicalBlock, CanonicalBlockBody, CanonicalBlockHeader, CanonicalBlockSidecar,
};
use shell_execution::{ExecutionReceipt, PlannedTransaction, TransactionExecutionPlan};
use shell_fixtures::RootCheckScenario;
use shell_primitives::{Authorization, TransactionEnvelope};
use shell_state::StatePatch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedAuthorizationMaterial {
    pub public_key_material: Vec<u8>,
}

impl OwnedAuthorizationMaterial {
    pub fn new(public_key_material: Vec<u8>) -> Self {
        Self {
            public_key_material,
        }
    }

    pub fn reference_default() -> Self {
        Self::new(vec![0; 32])
    }

    pub(crate) fn as_borrowed(&self) -> shell_mempool::AuthorizationMaterial<'_> {
        shell_mempool::AuthorizationMaterial {
            public_key_material: &self.public_key_material,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalReferenceScenario {
    pub block: CanonicalBlock,
    pub admission_transactions: Vec<TransactionEnvelope>,
    pub pre_state_root: shell_primitives::Root,
    pub materialized_state: Vec<(shell_primitives::StateKey, Vec<u8>)>,
    pub planned_transactions: Vec<PlannedTransaction>,
    pub transaction_authorization_materials: Vec<Vec<OwnedAuthorizationMaterial>>,
}

impl LocalReferenceScenario {
    pub fn from_root_check_scenario(scenario: &RootCheckScenario) -> Self {
        let block = CanonicalBlock {
            header: CanonicalBlockHeader {
                block_root: scenario.header.block_root,
                block_number: scenario.header.block_number,
                timestamp: scenario.header.timestamp,
                parent_root: scenario.header.parent_root,
                witness_bytes: scenario.header.witness_bytes,
                transactions_root: scenario.header.transactions_root,
                execution_witnesses_root: scenario.header.execution_witnesses_root,
                state_root: scenario.header.state_root,
                receipts_root: scenario.header.receipts_root,
                proposer_signature: scenario.header.proposer_signature.clone(),
                proposer_index_hint: Some(scenario.header.proposer_index),
            },
            body: CanonicalBlockBody {
                transactions: scenario.transactions.clone(),
                transactions_root: scenario.header.transactions_root,
            },
            sidecar: CanonicalBlockSidecar {
                block_root: scenario.sidecar.block_root,
                execution_witnesses_root: scenario.header.execution_witnesses_root,
                witnesses: scenario.witnesses.clone(),
            },
        };
        let planned_transactions = scenario
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
            .collect();
        let admission_transactions = scenario
            .transactions
            .iter()
            .map(synthesize_reference_admission_transaction)
            .collect();
        let transaction_authorization_materials = scenario
            .transactions
            .iter()
            .map(|transaction| {
                let authorization_count = if transaction.authorizations.is_empty() {
                    1
                } else {
                    transaction.authorizations.len()
                };
                (0..authorization_count)
                    .map(|_| OwnedAuthorizationMaterial::reference_default())
                    .collect()
            })
            .collect();

        Self {
            block,
            admission_transactions,
            pre_state_root: scenario.pre_state_root,
            materialized_state: scenario.materialized_state.clone(),
            planned_transactions,
            transaction_authorization_materials,
        }
    }
}

fn synthesize_reference_admission_transaction(
    transaction: &TransactionEnvelope,
) -> TransactionEnvelope {
    if !transaction.authorizations.is_empty() {
        return transaction.clone();
    }

    let payload_root = transaction
        .payload_root()
        .expect("root-check scenarios only load canonical transaction payloads");
    let mut reference_transaction = transaction.clone();
    reference_transaction.authorizations = vec![Authorization {
        scheme_id: 0,
        payload_root,
        signature: vec![0xA5; 64],
    }];
    reference_transaction
}
