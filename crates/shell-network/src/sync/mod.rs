use shell_consensus::{ConsensusBody, ConsensusError, ConsensusHeader, ConsensusSidecar};
use shell_mempool::ValidationError;
use shell_primitives::{TransactionEnvelope, ValidationOutcome};

use crate::NetworkOrigin;

pub trait NetworkMempoolAdapter {
    fn validate_gossip_transaction(
        &self,
        origin: &NetworkOrigin,
        envelope: &TransactionEnvelope,
    ) -> Result<ValidationOutcome, ValidationError>;
}

pub trait NetworkConsensusAdapter {
    fn validate_gossip_block(
        &self,
        origin: &NetworkOrigin,
        header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        sidecar: &dyn ConsensusSidecar,
    ) -> Result<ValidationOutcome, ConsensusError>;
}
