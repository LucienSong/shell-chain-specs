use std::boxed::Box;

use shell_consensus::{ConsensusError, WitnessByteLimitExceededError};
use shell_crypto::{CryptoError, VerificationFailure};
use shell_fixtures::{
    load_fixture, peer_action_fixture_paths, ConsensusPeerErrorInput, ExpectedPeerAction,
    FeeLaneInput, MempoolPeerErrorInput, NetworkOriginInput, OutcomeClass, PeerActionHintInput,
    PeerActionInput, PeerActionVector, ValidationStageInput,
};
use shell_mempool::{FeeFloorError, FeeLane, ValidationError};
use shell_network::{
    peer_action_for_consensus_error, peer_action_for_mempool_error,
    peer_action_for_validation_outcome, NetworkOrigin, PeerAction, PeerActionHint, PeerId,
    ReputationDelta,
};
use shell_primitives::{
    GasPrice, MalformedSszError, PrimitiveError, ValidationOutcome, ValidationStage, U256,
};

#[test]
fn shared_peer_action_vectors_cover_network_mapping_contract() {
    let mut paths = peer_action_fixture_paths();
    paths.sort();

    let mut seen = 0;
    for path in paths {
        let fixture: PeerActionVector = load_fixture(&path);
        seen += 1;

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "peer-action",
            "{} must declare category 'peer-action'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-network",
            "{} must be owned by shell-network",
            fixture.id
        );
        assert!(
            !fixture.rule.trim().is_empty(),
            "{} must declare the mapping rule it covers",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "{} must document the mapping invariant",
            fixture.id
        );

        let actual_action = peer_action_from_fixture(&fixture);
        let expected_action = expected_action_from_fixture(&fixture.expected_action);
        assert_eq!(
            actual_action, expected_action,
            "{} peer-action mapping drifted",
            fixture.id
        );
        assert_eq!(
            outcome_class_for_action(actual_action),
            fixture.expected_outcome,
            "{} outcome class drifted",
            fixture.id
        );
    }

    assert!(
        seen > 0,
        "expected at least one shared peer-action fixture for shell-network"
    );
}

fn peer_action_from_fixture(fixture: &PeerActionVector) -> PeerAction {
    match &fixture.input {
        PeerActionInput::ValidationOutcome { origin, outcome } => {
            let origin = network_origin(*origin);
            peer_action_for_validation_outcome(&origin, validation_outcome(*outcome))
        }
        PeerActionInput::MempoolError {
            origin,
            stage,
            error,
        } => {
            let origin = network_origin(*origin);
            let error = mempool_error(error);
            peer_action_for_mempool_error(&origin, validation_stage(*stage), &error)
        }
        PeerActionInput::ConsensusError { origin, error } => {
            let origin = network_origin(*origin);
            let error = consensus_error(error);
            peer_action_for_consensus_error(&origin, &error)
        }
    }
}

fn network_origin(origin: NetworkOriginInput) -> NetworkOrigin {
    let peer_id = PeerId::from([0x33; 32]);
    match origin {
        NetworkOriginInput::Gossip => NetworkOrigin::Gossip { peer_id },
        NetworkOriginInput::Fetch => NetworkOrigin::Fetch { peer_id },
        NetworkOriginInput::Sync => NetworkOrigin::Sync { peer_id },
        NetworkOriginInput::LocalRpc => NetworkOrigin::LocalRpc,
        NetworkOriginInput::LocalBuilder => NetworkOrigin::LocalBuilder,
        NetworkOriginInput::TestHarness => NetworkOrigin::TestHarness,
    }
}

fn validation_outcome(outcome: OutcomeClass) -> ValidationOutcome {
    match outcome {
        OutcomeClass::Accept => ValidationOutcome::Accept,
        OutcomeClass::Reject => ValidationOutcome::Reject,
        OutcomeClass::PolicyReject => ValidationOutcome::PolicyReject,
    }
}

fn validation_stage(stage: ValidationStageInput) -> ValidationStage {
    match stage {
        ValidationStageInput::T0 => ValidationStage::T0,
        ValidationStageInput::T1 => ValidationStage::T1,
        ValidationStageInput::T2 => ValidationStage::T2,
        ValidationStageInput::T3 => ValidationStage::T3,
        ValidationStageInput::T4 => ValidationStage::T4,
        ValidationStageInput::B0 => ValidationStage::B0,
        ValidationStageInput::B1 => ValidationStage::B1,
        ValidationStageInput::B2 => ValidationStage::B2,
        ValidationStageInput::B3 => ValidationStage::B3,
        ValidationStageInput::B4 => ValidationStage::B4,
        ValidationStageInput::B5 => ValidationStage::B5,
    }
}

fn mempool_error(error: &MempoolPeerErrorInput) -> ValidationError {
    match error {
        MempoolPeerErrorInput::MalformedSsz { context } => {
            ValidationError::Primitive(PrimitiveError::MalformedSsz(MalformedSszError {
                context: leak_str(context),
            }))
        }
        MempoolPeerErrorInput::FeeFloor {
            lane,
            required,
            actual,
        } => ValidationError::FeeFloor(FeeFloorError {
            lane: match lane {
                FeeLaneInput::Payload => FeeLane::Payload,
                FeeLaneInput::Witness => FeeLane::Witness,
            },
            required: gas_price(*required),
            actual: gas_price(*actual),
        }),
    }
}

fn consensus_error(error: &ConsensusPeerErrorInput) -> ConsensusError {
    match error {
        ConsensusPeerErrorInput::CryptoVerificationFailed { scheme_id, context } => {
            ConsensusError::Crypto(CryptoError::VerificationFailed(VerificationFailure {
                scheme_id: *scheme_id,
                context: leak_str(context),
            }))
        }
        ConsensusPeerErrorInput::WitnessByteLimitExceeded {
            max_bytes,
            actual_bytes,
        } => ConsensusError::WitnessByteLimitExceeded(WitnessByteLimitExceededError {
            max_bytes: *max_bytes,
            actual_bytes: *actual_bytes,
        }),
    }
}

fn gas_price(value: u64) -> GasPrice {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    GasPrice(U256(bytes))
}

fn expected_action_from_fixture(action: &ExpectedPeerAction) -> PeerAction {
    match action {
        ExpectedPeerAction::Accept => PeerAction::Accept,
        ExpectedPeerAction::Ignore { hint } => PeerAction::Ignore {
            hint: peer_action_hint(*hint),
        },
        ExpectedPeerAction::AdjustReputation { delta, hint } => {
            PeerAction::AdjustReputation(ReputationDelta::new(*delta, peer_action_hint(*hint)))
        }
        ExpectedPeerAction::Disconnect { hint } => PeerAction::Disconnect {
            hint: peer_action_hint(*hint),
        },
    }
}

fn peer_action_hint(hint: PeerActionHintInput) -> PeerActionHint {
    match hint {
        PeerActionHintInput::RejectedObject => PeerActionHint::RejectedObject,
        PeerActionHintInput::MalformedAnnouncement => PeerActionHint::MalformedAnnouncement,
        PeerActionHintInput::InvalidTransaction => PeerActionHint::InvalidTransaction,
        PeerActionHintInput::InvalidBlock => PeerActionHint::InvalidBlock,
        PeerActionHintInput::InvalidSignature => PeerActionHint::InvalidSignature,
        PeerActionHintInput::OversizedObject => PeerActionHint::OversizedObject,
        PeerActionHintInput::PolicyRejected => PeerActionHint::PolicyRejected,
        PeerActionHintInput::InternalError => PeerActionHint::InternalError,
    }
}

fn outcome_class_for_action(action: PeerAction) -> OutcomeClass {
    match action {
        PeerAction::Accept => OutcomeClass::Accept,
        PeerAction::AdjustReputation(_) => OutcomeClass::PolicyReject,
        PeerAction::Ignore { hint } => match hint {
            PeerActionHint::PolicyRejected | PeerActionHint::OversizedObject => {
                OutcomeClass::PolicyReject
            }
            PeerActionHint::RejectedObject
            | PeerActionHint::MalformedAnnouncement
            | PeerActionHint::InvalidTransaction
            | PeerActionHint::InvalidBlock
            | PeerActionHint::InvalidSignature => OutcomeClass::Reject,
            PeerActionHint::InternalError => OutcomeClass::Reject,
            _ => OutcomeClass::Reject,
        },
        PeerAction::Disconnect { .. } => OutcomeClass::Reject,
        _ => OutcomeClass::Reject,
    }
}

fn leak_str(value: &str) -> &'static str {
    Box::leak(value.to_owned().into_boxed_str())
}
