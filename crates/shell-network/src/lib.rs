#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub mod errors;
pub mod fetch;
pub mod gossip;
pub mod reputation;
pub mod sync;

pub use crate::errors::NetworkError;
pub use crate::fetch::{FetchDecision, FetchScheduler, SidecarFetchPolicy};
pub use crate::gossip::{AnnouncementDecoder, AnnouncementFilter};
pub use crate::reputation::{
    peer_action_for_consensus_error, peer_action_for_mempool_error,
    peer_action_for_validation_outcome, PeerAction, PeerActionHint, PeerStore, ReputationDelta,
    ReputationStore,
};
pub use crate::sync::{NetworkConsensusAdapter, NetworkMempoolAdapter};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PeerId(Vec<u8>);

impl PeerId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; 32]> for PeerId {
    fn from(value: [u8; 32]) -> Self {
        Self(value.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkOrigin {
    Gossip { peer_id: PeerId },
    Fetch { peer_id: PeerId },
    Sync { peer_id: PeerId },
    LocalRpc,
    LocalBuilder,
    TestHarness,
}

impl NetworkOrigin {
    pub fn peer_id(&self) -> Option<&PeerId> {
        match self {
            Self::Gossip { peer_id } | Self::Fetch { peer_id } | Self::Sync { peer_id } => {
                Some(peer_id)
            }
            Self::LocalRpc | Self::LocalBuilder | Self::TestHarness => None,
        }
    }

    pub const fn penalizes_peer(&self) -> bool {
        matches!(
            self,
            Self::Gossip { .. } | Self::Fetch { .. } | Self::Sync { .. }
        )
    }
}
