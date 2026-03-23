use shell_execution::{BlockExecutionOutcome, CommittedExecutionRoots, ExecutionError};

use crate::header_checks::ConsensusHeader;
use crate::import::ConsensusBody;
use crate::outcomes::ConsensusError;
use crate::sidecars::ConsensusSidecar;

pub trait BlockExecutionEngine {
    fn execute_block(
        &self,
        header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        sidecar: &dyn ConsensusSidecar,
    ) -> Result<BlockExecutionOutcome, ExecutionError>;
}

pub fn execute_and_compare(
    header: &dyn ConsensusHeader,
    body: &dyn ConsensusBody,
    sidecar: &dyn ConsensusSidecar,
    engine: &dyn BlockExecutionEngine,
) -> Result<BlockExecutionOutcome, ConsensusError> {
    let outcome = engine.execute_block(header, body, sidecar)?;
    outcome.ensure_matches(&CommittedExecutionRoots {
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
    })?;
    Ok(outcome)
}
