mod filtering;

use shell_consensus::{ConsensusBody, ConsensusHeader, ConsensusSidecar};
use shell_primitives::{PrimitiveError, TransactionEnvelope};

pub use self::filtering::AnnouncementFilter;

pub trait AnnouncementDecoder {
    type Header: ConsensusHeader;
    type Body: ConsensusBody;
    type Sidecar: ConsensusSidecar;

    fn decode_transaction_envelope(
        &self,
        encoded: &[u8],
    ) -> Result<TransactionEnvelope, PrimitiveError>;

    fn decode_header(&self, encoded: &[u8]) -> Result<Self::Header, PrimitiveError>;

    fn decode_body(&self, encoded: &[u8]) -> Result<Self::Body, PrimitiveError>;

    fn decode_sidecar(&self, encoded: &[u8]) -> Result<Self::Sidecar, PrimitiveError>;
}
