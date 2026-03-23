use shell_consensus::ConsensusError;
use shell_mempool::ValidationError;
use shell_primitives::PrimitiveError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkError {
    Primitive(PrimitiveError),
    Validation(ValidationError),
    Consensus(ConsensusError),
    Storage(&'static str),
    Unavailable(&'static str),
}

impl From<PrimitiveError> for NetworkError {
    fn from(value: PrimitiveError) -> Self {
        Self::Primitive(value)
    }
}

impl From<ValidationError> for NetworkError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}

impl From<ConsensusError> for NetworkError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
