use shell_crypto::CryptoError;
use shell_execution::ExecutionError;
use shell_mempool::ValidationError;
use shell_primitives::{
    DomainError, PrimitiveError, ProposerCredentialResolutionError, Root, ValidationOutcome,
};
use shell_state::StateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessByteLimitExceededError {
    pub max_bytes: u64,
    pub actual_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderBodyRootMismatchError {
    pub expected: Root,
    pub actual: Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarBlockRootMismatchError {
    pub expected: Root,
    pub actual: Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarCommitmentMismatchError {
    pub expected: Root,
    pub actual: Root,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    Primitive(PrimitiveError),
    Domain(DomainError),
    Crypto(CryptoError),
    TransactionValidation(ValidationError),
    Execution(ExecutionError),
    State(StateError),
    ProposerCredentialResolution(ProposerCredentialResolutionError),
    WitnessByteLimitExceeded(WitnessByteLimitExceededError),
    HeaderBodyRootMismatch(HeaderBodyRootMismatchError),
    SidecarBlockRootMismatch(SidecarBlockRootMismatchError),
    SidecarCommitmentMismatch(SidecarCommitmentMismatchError),
}

impl From<PrimitiveError> for ConsensusError {
    fn from(value: PrimitiveError) -> Self {
        Self::Primitive(value)
    }
}

impl From<DomainError> for ConsensusError {
    fn from(value: DomainError) -> Self {
        Self::Domain(value)
    }
}

impl From<CryptoError> for ConsensusError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<ValidationError> for ConsensusError {
    fn from(value: ValidationError) -> Self {
        Self::TransactionValidation(value)
    }
}

impl From<ExecutionError> for ConsensusError {
    fn from(value: ExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<StateError> for ConsensusError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<ProposerCredentialResolutionError> for ConsensusError {
    fn from(value: ProposerCredentialResolutionError) -> Self {
        Self::ProposerCredentialResolution(value)
    }
}

impl ConsensusError {
    pub const fn network_validation_outcome(&self) -> Option<ValidationOutcome> {
        match self {
            Self::Primitive(error) => error.network_validation_outcome(),
            Self::Domain(_) => None,
            Self::Crypto(error) => error.network_validation_outcome(),
            Self::TransactionValidation(error) => error.network_validation_outcome(),
            Self::Execution(_)
            | Self::State(_)
            | Self::HeaderBodyRootMismatch(_)
            | Self::SidecarBlockRootMismatch(_)
            | Self::SidecarCommitmentMismatch(_) => Some(ValidationOutcome::Reject),
            Self::ProposerCredentialResolution(error) => {
                if error.is_consensus_invalid() {
                    Some(ValidationOutcome::Reject)
                } else {
                    None
                }
            }
            Self::WitnessByteLimitExceeded(_) => Some(ValidationOutcome::PolicyReject),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockImportOutcome {
    pub block_root: Root,
    pub post_state_root: Root,
    pub receipts_root: Root,
}
