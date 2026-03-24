use shell_mempool::{MultiAuthorizationPolicy, ValidationError};
use shell_primitives::{PrimitiveError, Root, TransactionEnvelope};

use crate::execution_bridge::{execute_and_compare, BlockExecutionEngine};
use crate::header_checks::{
    prefilter_header, verify_header_signature, ConsensusHeader, HeaderPrefilterConfig,
};
use crate::outcomes::{BlockImportOutcome, ConsensusError, HeaderBodyRootMismatchError};
use crate::sidecars::{verify_sidecar_binding, ConsensusSidecar, WitnessPreparer};

pub trait ConsensusBody {
    fn transactions_root(&self) -> Result<Root, PrimitiveError>;
    fn transactions(&self) -> &[TransactionEnvelope];
}

pub trait TransactionRevalidator {
    fn revalidate(
        &self,
        transaction: &TransactionEnvelope,
        multi_authorization_policy: MultiAuthorizationPolicy,
    ) -> Result<(), ValidationError>;
}

#[derive(Clone, Copy)]
pub struct BlockImportServices<'a> {
    pub resolver: &'a dyn shell_primitives::ProposerCredentialResolver,
    pub dispatcher: &'a dyn shell_crypto::SignatureDispatcher,
    pub revalidator: &'a dyn TransactionRevalidator,
    pub preparer: &'a dyn WitnessPreparer,
    pub execution_engine: &'a dyn BlockExecutionEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockImportConfig {
    pub header_prefilter: HeaderPrefilterConfig,
    pub multi_authorization_policy: MultiAuthorizationPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockImportPipeline {
    config: BlockImportConfig,
}

impl BlockImportPipeline {
    pub fn new(config: BlockImportConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> BlockImportConfig {
        self.config
    }

    pub fn import_block(
        &self,
        header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        sidecar: &dyn ConsensusSidecar,
        services: BlockImportServices<'_>,
    ) -> Result<BlockImportOutcome, ConsensusError> {
        let header_outcome = prefilter_header(header, self.config.header_prefilter)?;
        verify_body_binding(header, body)?;
        verify_header_signature(
            header,
            &header_outcome.block_root,
            services.resolver,
            services.dispatcher,
        )?;
        revalidate_body_transactions(
            body,
            services.revalidator,
            self.config.multi_authorization_policy,
        )?;
        verify_sidecar_binding(
            header,
            &header_outcome.block_root,
            sidecar,
            services.preparer,
        )?;
        let execution_outcome =
            execute_and_compare(header, body, sidecar, services.execution_engine)?;

        Ok(BlockImportOutcome {
            block_root: header_outcome.block_root,
            post_state_root: execution_outcome.post_state_root,
            receipts_root: execution_outcome.receipts_root,
        })
    }
}

pub fn verify_body_binding(
    header: &dyn ConsensusHeader,
    body: &dyn ConsensusBody,
) -> Result<(), ConsensusError> {
    let actual = body.transactions_root()?;
    let expected = header.transactions_root();

    if actual != expected {
        return Err(ConsensusError::HeaderBodyRootMismatch(
            HeaderBodyRootMismatchError { expected, actual },
        ));
    }

    Ok(())
}

pub fn revalidate_body_transactions(
    body: &dyn ConsensusBody,
    revalidator: &dyn TransactionRevalidator,
    multi_authorization_policy: MultiAuthorizationPolicy,
) -> Result<(), ConsensusError> {
    for transaction in body.transactions() {
        revalidator.revalidate(transaction, multi_authorization_policy)?;
    }

    Ok(())
}
