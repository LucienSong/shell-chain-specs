use shell_primitives::Root;
use shell_state::StateError;

use crate::header_checks::ConsensusHeader;
use crate::outcomes::{
    ConsensusError, SidecarBlockRootMismatchError, SidecarCommitmentMismatchError,
};

pub trait ConsensusSidecar {
    fn block_root(&self) -> Root;
    fn committed_root(&self) -> Root;
}

pub trait WitnessPreparer {
    fn prepare_witness(
        &self,
        header: &dyn ConsensusHeader,
        sidecar: &dyn ConsensusSidecar,
    ) -> Result<(), StateError>;
}

pub fn verify_sidecar_binding(
    header: &dyn ConsensusHeader,
    block_root: &Root,
    sidecar: &dyn ConsensusSidecar,
    preparer: &dyn WitnessPreparer,
) -> Result<(), ConsensusError> {
    if sidecar.block_root() != *block_root {
        return Err(ConsensusError::SidecarBlockRootMismatch(
            SidecarBlockRootMismatchError {
                expected: *block_root,
                actual: sidecar.block_root(),
            },
        ));
    }

    if sidecar.committed_root() != header.execution_witnesses_root() {
        return Err(ConsensusError::SidecarCommitmentMismatch(
            SidecarCommitmentMismatchError {
                expected: header.execution_witnesses_root(),
                actual: sidecar.committed_root(),
            },
        ));
    }

    preparer.prepare_witness(header, sidecar)?;
    Ok(())
}
