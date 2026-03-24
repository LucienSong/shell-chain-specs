use alloc::vec::Vec;

use shell_primitives::{PrimitiveError, ProtocolObject, Root, StateWitness, TransactionEnvelope};

use crate::header_checks::ConsensusHeader;
use crate::import::ConsensusBody;
use crate::sidecars::ConsensusSidecar;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBlockHeader {
    pub block_root: Root,
    pub block_number: u64,
    pub timestamp: u64,
    pub parent_root: Root,
    pub witness_bytes: u64,
    pub transactions_root: Root,
    pub execution_witnesses_root: Root,
    pub state_root: Root,
    pub receipts_root: Root,
    pub proposer_signature: Vec<u8>,
    pub proposer_index_hint: Option<u64>,
}

impl ProtocolObject for CanonicalBlockHeader {
    fn canonical_root(&self) -> Result<Root, PrimitiveError> {
        Ok(self.block_root)
    }
}

impl ConsensusHeader for CanonicalBlockHeader {
    fn witness_bytes(&self) -> u64 {
        self.witness_bytes
    }

    fn transactions_root(&self) -> Root {
        self.transactions_root
    }

    fn execution_witnesses_root(&self) -> Root {
        self.execution_witnesses_root
    }

    fn state_root(&self) -> Root {
        self.state_root
    }

    fn receipts_root(&self) -> Root {
        self.receipts_root
    }

    fn proposer_signature(&self) -> &[u8] {
        &self.proposer_signature
    }

    fn proposer_index_hint(&self) -> Option<u64> {
        self.proposer_index_hint
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalBlockBody {
    pub transactions: Vec<TransactionEnvelope>,
    pub transactions_root: Root,
}

impl ConsensusBody for CanonicalBlockBody {
    fn transactions_root(&self) -> Result<Root, PrimitiveError> {
        Ok(self.transactions_root)
    }

    fn transactions(&self) -> &[TransactionEnvelope] {
        &self.transactions
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalBlockSidecar {
    pub block_root: Root,
    pub execution_witnesses_root: Root,
    pub witnesses: Vec<StateWitness>,
}

impl ConsensusSidecar for CanonicalBlockSidecar {
    fn block_root(&self) -> Root {
        self.block_root
    }

    fn committed_root(&self) -> Root {
        self.execution_witnesses_root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBlock {
    pub header: CanonicalBlockHeader,
    pub body: CanonicalBlockBody,
    pub sidecar: CanonicalBlockSidecar,
}

impl CanonicalBlock {
    pub fn split(
        &self,
    ) -> (
        &CanonicalBlockHeader,
        &CanonicalBlockBody,
        &CanonicalBlockSidecar,
    ) {
        (&self.header, &self.body, &self.sidecar)
    }
}
