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
    use alloc::vec::Vec;

    use shell_consensus::CanonicalBlockHeader;

    use super::*;

    #[test]
    fn oversized_witness_headers_skip_sidecar_fetch() {
        let policy = SidecarFetchPolicy {
            max_witness_bytes: Some(512),
            require_explicit_request: false,
        };
        let header = CanonicalBlockHeader {
            block_number: 1,
            timestamp: 1,
            parent_root: [0; 32],
            witness_bytes: 1_024,
            block_root: [7; 32],
            transactions_root: [0; 32],
            execution_witnesses_root: [0; 32],
            state_root: [0; 32],
            receipts_root: [0; 32],
            proposer_signature: Vec::new(),
            proposer_index_hint: None,
        };

        assert_eq!(policy.decide_for_header(&header, true), FetchDecision::Skip);
    }

    #[test]
    fn explicit_request_can_be_required_before_fetching_sidecars() {
        let policy = SidecarFetchPolicy {
            max_witness_bytes: Some(2_048),
            require_explicit_request: true,
        };
        let header = CanonicalBlockHeader {
            block_number: 1,
            timestamp: 1,
            parent_root: [0; 32],
            witness_bytes: 256,
            block_root: [9; 32],
            transactions_root: [0; 32],
            execution_witnesses_root: [0; 32],
            state_root: [0; 32],
            receipts_root: [0; 32],
            proposer_signature: Vec::new(),
            proposer_index_hint: None,
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
