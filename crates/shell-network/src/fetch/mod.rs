mod policy;

use shell_primitives::Root;

use crate::{NetworkError, PeerId};

pub use self::policy::SidecarFetchPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchDecision {
    Fetch,
    Skip,
    Defer,
}

pub trait FetchScheduler {
    fn schedule_transaction_fetch(
        &self,
        peer_id: &PeerId,
        transaction_root: &Root,
    ) -> Result<FetchDecision, NetworkError>;

    fn schedule_sidecar_fetch(
        &self,
        peer_id: &PeerId,
        block_root: &Root,
    ) -> Result<FetchDecision, NetworkError>;
}
