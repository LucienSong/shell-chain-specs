use shell_consensus::ConsensusHeader;

use crate::fetch::FetchDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SidecarFetchPolicy {
    pub max_witness_bytes: Option<u64>,
    pub require_explicit_request: bool,
}

impl SidecarFetchPolicy {
    pub fn decide_for_header(
        &self,
        header: &dyn ConsensusHeader,
        was_requested: bool,
    ) -> FetchDecision {
        match self.max_witness_bytes {
            Some(limit) if header.witness_bytes() > limit => FetchDecision::Skip,
            _ if self.require_explicit_request && !was_requested => FetchDecision::Defer,
            _ => FetchDecision::Fetch,
        }
    }
}

#[cfg(test)]
mod tests {
    use shell_consensus::ConsensusHeader;
    use shell_primitives::{PrimitiveError, ProtocolObject, Root};

    use super::*;

    struct StubHeader {
        witness_bytes: u64,
        block_root: Root,
    }

    impl ProtocolObject for StubHeader {
        fn canonical_root(&self) -> Result<Root, PrimitiveError> {
            Ok(self.block_root)
        }
    }

    impl ConsensusHeader for StubHeader {
        fn witness_bytes(&self) -> u64 {
            self.witness_bytes
        }

        fn transactions_root(&self) -> Root {
            [0; 32]
        }

        fn execution_witnesses_root(&self) -> Root {
            [0; 32]
        }

        fn state_root(&self) -> Root {
            [0; 32]
        }

        fn receipts_root(&self) -> Root {
            [0; 32]
        }

        fn proposer_signature(&self) -> &[u8] {
            &[]
        }
    }

    #[test]
    fn oversized_witness_headers_skip_sidecar_fetch() {
        let policy = SidecarFetchPolicy {
            max_witness_bytes: Some(512),
            require_explicit_request: false,
        };
        let header = StubHeader {
            witness_bytes: 1_024,
            block_root: [7; 32],
        };

        assert_eq!(policy.decide_for_header(&header, true), FetchDecision::Skip);
    }

    #[test]
    fn explicit_request_can_be_required_before_fetching_sidecars() {
        let policy = SidecarFetchPolicy {
            max_witness_bytes: Some(2_048),
            require_explicit_request: true,
        };
        let header = StubHeader {
            witness_bytes: 256,
            block_root: [9; 32],
        };

        assert_eq!(
            policy.decide_for_header(&header, false),
            FetchDecision::Defer
        );
        assert_eq!(
            policy.decide_for_header(&header, true),
            FetchDecision::Fetch
        );
    }
}
