mod scoring;

use crate::{NetworkError, PeerId};

pub use self::scoring::{
    peer_action_for_consensus_error, peer_action_for_mempool_error,
    peer_action_for_validation_outcome,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerActionHint {
    RejectedObject,
    MalformedAnnouncement,
    InvalidTransaction,
    InvalidBlock,
    InvalidSignature,
    OversizedObject,
    PolicyRejected,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationDelta {
    pub value: i32,
    pub hint: PeerActionHint,
}

impl ReputationDelta {
    pub const fn new(value: i32, hint: PeerActionHint) -> Self {
        Self { value, hint }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAction {
    Accept,
    Ignore { hint: PeerActionHint },
    AdjustReputation(ReputationDelta),
    Disconnect { hint: PeerActionHint },
}

pub trait PeerStore {
    fn is_known_peer(&self, peer_id: &PeerId) -> bool;
    fn is_connected(&self, peer_id: &PeerId) -> bool;
}

pub trait ReputationStore {
    fn apply_reputation(
        &self,
        peer_id: &PeerId,
        delta: ReputationDelta,
    ) -> Result<(), NetworkError>;
    fn reputation(&self, peer_id: &PeerId) -> i32;
}
