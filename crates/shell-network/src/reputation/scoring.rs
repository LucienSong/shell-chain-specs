use shell_consensus::ConsensusError;
use shell_mempool::ValidationError;
use shell_primitives::{PrimitiveError, ValidationOutcome, ValidationStage};

use crate::{
    reputation::{PeerAction, PeerActionHint, ReputationDelta},
    NetworkOrigin,
};

const POLICY_REPUTATION_DELTA: i32 = -10;
const OVERSIZED_REPUTATION_DELTA: i32 = -5;

pub fn peer_action_for_validation_outcome(
    origin: &NetworkOrigin,
    outcome: ValidationOutcome,
) -> PeerAction {
    match outcome {
        ValidationOutcome::Accept => PeerAction::Accept,
        ValidationOutcome::Reject => disconnect_action(origin, PeerActionHint::RejectedObject),
        ValidationOutcome::PolicyReject => policy_action(
            origin,
            POLICY_REPUTATION_DELTA,
            PeerActionHint::PolicyRejected,
        ),
    }
}

pub fn peer_action_for_mempool_error(
    origin: &NetworkOrigin,
    stage: ValidationStage,
    error: &ValidationError,
) -> PeerAction {
    match error {
        ValidationError::Primitive(primitive) => match primitive {
            PrimitiveError::MalformedSsz(_) if matches!(stage, ValidationStage::T0) => {
                disconnect_action(origin, PeerActionHint::MalformedAnnouncement)
            }
            PrimitiveError::MalformedSsz(_)
            | PrimitiveError::UnsupportedPayloadVariant(_)
            | PrimitiveError::PayloadRootMismatch(_)
            | PrimitiveError::AuthorizationCount(_)
            | PrimitiveError::SignatureSizeExceeded(_) => {
                disconnect_action(origin, PeerActionHint::InvalidTransaction)
            }
            PrimitiveError::SigningRootConstruction(_) | PrimitiveError::Unimplemented(_) => {
                PeerAction::Ignore {
                    hint: PeerActionHint::InternalError,
                }
            }
        },
        ValidationError::UnsupportedScheme(_)
        | ValidationError::SignatureSizeExceeded(_)
        | ValidationError::SignatureVerification(_) => {
            disconnect_action(origin, PeerActionHint::InvalidSignature)
        }
        ValidationError::FeeFloor(_) | ValidationError::NoncePolicy(_) => policy_action(
            origin,
            POLICY_REPUTATION_DELTA,
            PeerActionHint::PolicyRejected,
        ),
        ValidationError::SigningRootUnavailable(_)
        | ValidationError::AuthorizationMaterialCount(_) => PeerAction::Ignore {
            hint: PeerActionHint::InternalError,
        },
    }
}

pub fn peer_action_for_consensus_error(
    origin: &NetworkOrigin,
    error: &ConsensusError,
) -> PeerAction {
    match error {
        ConsensusError::Primitive(_) => {
            disconnect_action(origin, PeerActionHint::MalformedAnnouncement)
        }
        ConsensusError::Domain(_) | ConsensusError::ProposerCredentialResolution(_) => {
            PeerAction::Ignore {
                hint: PeerActionHint::InternalError,
            }
        }
        ConsensusError::Crypto(_) => disconnect_action(origin, PeerActionHint::InvalidSignature),
        ConsensusError::TransactionValidation(error) => {
            peer_action_for_mempool_error(origin, ValidationStage::B3, error)
        }
        ConsensusError::Execution(_) | ConsensusError::State(_) => {
            disconnect_action(origin, PeerActionHint::InvalidBlock)
        }
        ConsensusError::WitnessByteLimitExceeded(_) => policy_action(
            origin,
            OVERSIZED_REPUTATION_DELTA,
            PeerActionHint::OversizedObject,
        ),
        ConsensusError::HeaderBodyRootMismatch(_)
        | ConsensusError::SidecarBlockRootMismatch(_)
        | ConsensusError::SidecarCommitmentMismatch(_) => {
            disconnect_action(origin, PeerActionHint::InvalidBlock)
        }
    }
}

fn disconnect_action(origin: &NetworkOrigin, hint: PeerActionHint) -> PeerAction {
    if origin.penalizes_peer() {
        PeerAction::Disconnect { hint }
    } else {
        PeerAction::Ignore { hint }
    }
}

fn policy_action(origin: &NetworkOrigin, value: i32, hint: PeerActionHint) -> PeerAction {
    if origin.penalizes_peer() {
        PeerAction::AdjustReputation(ReputationDelta::new(value, hint))
    } else {
        PeerAction::Ignore { hint }
    }
}

#[cfg(test)]
mod tests {
    use shell_consensus::{
        ConsensusError, HeaderBodyRootMismatchError, WitnessByteLimitExceededError,
    };
    use shell_mempool::{FeeFloorError, FeeLane, ValidationError};
    use shell_primitives::{
        GasPrice, MalformedSszError, PrimitiveError, Root, ValidationOutcome, ValidationStage, U256,
    };

    use super::*;
    use crate::PeerId;

    fn peer_origin() -> NetworkOrigin {
        NetworkOrigin::Gossip {
            peer_id: PeerId::from([3; 32]),
        }
    }

    fn zero_gas_price() -> GasPrice {
        GasPrice(U256([0; 32]))
    }

    #[test]
    fn reject_outcomes_disconnect_remote_peers() {
        assert_eq!(
            peer_action_for_validation_outcome(&peer_origin(), ValidationOutcome::Reject),
            PeerAction::Disconnect {
                hint: PeerActionHint::RejectedObject,
            }
        );
    }

    #[test]
    fn local_policy_rejects_do_not_penalize_local_origins() {
        assert_eq!(
            peer_action_for_validation_outcome(
                &NetworkOrigin::LocalRpc,
                ValidationOutcome::PolicyReject
            ),
            PeerAction::Ignore {
                hint: PeerActionHint::PolicyRejected,
            }
        );
    }

    #[test]
    fn malformed_t0_transactions_disconnect_remote_peers() {
        let error = ValidationError::Primitive(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "truncated tx announcement",
        }));

        assert_eq!(
            peer_action_for_mempool_error(&peer_origin(), ValidationStage::T0, &error),
            PeerAction::Disconnect {
                hint: PeerActionHint::MalformedAnnouncement,
            }
        );
    }

    #[test]
    fn fee_floor_failures_lower_remote_peer_reputation() {
        let error = ValidationError::FeeFloor(FeeFloorError {
            lane: FeeLane::Payload,
            required: zero_gas_price(),
            actual: zero_gas_price(),
        });

        assert_eq!(
            peer_action_for_mempool_error(&peer_origin(), ValidationStage::T2, &error),
            PeerAction::AdjustReputation(ReputationDelta::new(
                POLICY_REPUTATION_DELTA,
                PeerActionHint::PolicyRejected,
            ))
        );
    }

    #[test]
    fn header_body_mismatch_disconnects_remote_peers() {
        let error = ConsensusError::HeaderBodyRootMismatch(HeaderBodyRootMismatchError {
            expected: Root::default(),
            actual: [9; 32],
        });

        assert_eq!(
            peer_action_for_consensus_error(&peer_origin(), &error),
            PeerAction::Disconnect {
                hint: PeerActionHint::InvalidBlock,
            }
        );
    }

    #[test]
    fn oversized_headers_are_scored_without_disconnect() {
        let error = ConsensusError::WitnessByteLimitExceeded(WitnessByteLimitExceededError {
            max_bytes: 512,
            actual_bytes: 1_024,
        });

        assert_eq!(
            peer_action_for_consensus_error(&peer_origin(), &error),
            PeerAction::AdjustReputation(ReputationDelta::new(
                OVERSIZED_REPUTATION_DELTA,
                PeerActionHint::OversizedObject,
            ))
        );
    }
}
