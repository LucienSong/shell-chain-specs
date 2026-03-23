use shell_crypto::{SignatureDispatcher, SignatureVerificationRequest};
use shell_primitives::{
    build_signing_data, ssz, DomainSelector, ProposerCredentialResolver, ProtocolObject, Root,
};

use crate::outcomes::{ConsensusError, WitnessByteLimitExceededError};

pub trait ConsensusHeader: ProtocolObject {
    fn witness_bytes(&self) -> u64;
    fn transactions_root(&self) -> Root;
    fn execution_witnesses_root(&self) -> Root;
    fn state_root(&self) -> Root;
    fn receipts_root(&self) -> Root;
    fn proposer_signature(&self) -> &[u8];

    fn proposer_index_hint(&self) -> Option<u64> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeaderPrefilterConfig {
    pub max_witness_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderCheckOutcome {
    pub block_root: Root,
}

pub fn prefilter_header(
    header: &dyn ConsensusHeader,
    config: HeaderPrefilterConfig,
) -> Result<HeaderCheckOutcome, ConsensusError> {
    let block_root = header.canonical_root()?;

    if let Some(max_bytes) = config.max_witness_bytes {
        let actual_bytes = header.witness_bytes();
        if actual_bytes > max_bytes {
            return Err(ConsensusError::WitnessByteLimitExceeded(
                WitnessByteLimitExceededError {
                    max_bytes,
                    actual_bytes,
                },
            ));
        }
    }

    Ok(HeaderCheckOutcome { block_root })
}

pub fn verify_header_signature(
    header: &dyn ConsensusHeader,
    block_root: &Root,
    resolver: &dyn ProposerCredentialResolver,
    dispatcher: &dyn SignatureDispatcher,
) -> Result<(), ConsensusError> {
    let credential =
        resolver.resolve_proposer_credential(block_root, header.proposer_index_hint())?;
    let signing_data = build_signing_data(*block_root, DomainSelector::ValidatorMessage)?;
    let signing_root = ssz::signing_root(&signing_data)?;
    let request = SignatureVerificationRequest {
        public_key_material: &credential.public_key_material,
        signing_root,
        signature: header.proposer_signature(),
    };

    dispatcher.verify_validator_message(credential.scheme_id, &request)?;
    Ok(())
}
