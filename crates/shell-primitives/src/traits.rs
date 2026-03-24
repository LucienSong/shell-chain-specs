use crate::errors::{PrimitiveError, ProposerCredentialResolutionError};
use crate::types::{ChainId, ExecutionAddress, MockProgressiveByteList, Root, U256};

pub trait ProtocolObject {
    fn canonical_root(&self) -> Result<Root, PrimitiveError>;
}

pub trait TransactionMetadata {
    fn chain_id(&self) -> &ChainId;
    fn nonce(&self) -> u64;
    fn gas_limit(&self) -> u64;
}

pub trait StateMetadata {
    fn account_nonce(&self, address: &ExecutionAddress) -> Option<u64>;
    fn account_balance(&self, address: &ExecutionAddress) -> Option<U256>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerCredential {
    pub scheme_id: u8,
    pub public_key_material: MockProgressiveByteList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposerCredentialQuery {
    pub block_root: Root,
    pub proposer_index_hint: Option<u64>,
}

pub trait ProposerCredentialResolver {
    fn resolve_proposer_credential(
        &self,
        query: ProposerCredentialQuery,
    ) -> Result<ProposerCredential, ProposerCredentialResolutionError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    Accept,
    Reject,
    PolicyReject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    T0,
    T1,
    T2,
    T3,
    T4,
    B0,
    B1,
    B2,
    B3,
    B4,
    B5,
}
