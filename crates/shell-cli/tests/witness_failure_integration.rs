use std::path::PathBuf;

use shell_cli::{
    LocalReferenceError, LocalReferenceNetworkConsensusAdapter, LocalReferenceRuntime,
    LocalReferenceScenario,
};
use shell_consensus::{BlockImportConfig, ConsensusError};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
};
use shell_fixtures::{
    compute_execution_witnesses_root, load_root_check_scenario, load_witness_fixture_by_id,
};
use shell_mempool::AdmissionPolicy;
use shell_network::{
    peer_action_for_consensus_error, peer_action_for_validation_outcome, NetworkConsensusAdapter,
    NetworkOrigin, PeerAction, PeerActionHint, PeerId,
};
use shell_primitives::{
    ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver, ValidationOutcome,
};
use shell_state::{StateError, REFERENCE_BACKEND_PROOF_SHAPE_CONTEXT};

struct PermissiveDispatcher;

impl SignatureDispatcher for PermissiveDispatcher {
    fn register_verifier(
        &mut self,
        _verifier: Box<dyn SignatureVerifier>,
    ) -> Option<Box<dyn SignatureVerifier>> {
        None
    }

    fn verifier(&self, _scheme_id: u8) -> Option<&dyn SignatureVerifier> {
        None
    }

    fn verify_transaction_authorization(
        &self,
        _scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn verify_validator_message(
        &self,
        _scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

struct FixedResolver;

impl ProposerCredentialResolver for FixedResolver {
    fn resolve_proposer_credential(
        &self,
        _query: ProposerCredentialQuery,
    ) -> Result<ProposerCredential, ProposerCredentialResolutionError> {
        Ok(ProposerCredential {
            scheme_id: 0,
            public_key_material: vec![0x44; 32],
        })
    }
}

#[test]
fn local_reference_harness_preserves_noncanonical_witness_order_vectors_as_typed_rejects() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    let vector = load_witness_fixture_by_id("witness-order-noncanonical-002");
    scenario.block.sidecar.witnesses = vector.witnesses();
    rebind_execution_witnesses_root(&mut scenario);

    assert_witness_failure(
        scenario,
        StateError::NonCanonicalWitnessOrdering(shell_state::WitnessOrderingError {
            index: 1,
            context: "witness keys must be strictly increasing in canonical StateKey order",
        }),
    );
}

#[test]
fn local_reference_harness_preserves_shared_witness_leaf_boundary_vectors_as_typed_rejects() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    let vector = load_witness_fixture_by_id("witness-proof-invalid-002");
    scenario.block.sidecar.witnesses[0] = vector.witness().expect("single witness fixture");
    rebind_execution_witnesses_root(&mut scenario);

    assert_witness_failure(
        scenario,
        StateError::WitnessVerificationFailed("reference proof leaf does not match witness value"),
    );
}

#[test]
fn local_reference_harness_maps_invalid_committed_witness_shapes_to_invalid_block_rejects() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    let vector = load_witness_fixture_by_id("witness-proof-invalid-001");
    scenario.block.sidecar.witnesses[0] = vector.witness().expect("single witness fixture");
    rebind_execution_witnesses_root(&mut scenario);

    assert_witness_failure(
        scenario,
        StateError::UnsupportedProofShape(REFERENCE_BACKEND_PROOF_SHAPE_CONTEXT),
    );
}

fn rebind_execution_witnesses_root(scenario: &mut LocalReferenceScenario) {
    let committed_root = compute_execution_witnesses_root(&scenario.block.sidecar.witnesses);
    scenario.block.sidecar.execution_witnesses_root = committed_root;
    scenario.block.header.execution_witnesses_root = committed_root;
}

fn assert_witness_failure(scenario: LocalReferenceScenario, expected_state_error: StateError) {
    let dispatcher = PermissiveDispatcher;
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let consensus_adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");
    let peer_origin = peer_origin();

    let error = runtime
        .run(&scenario)
        .expect_err("corrupted witness scenarios should fail closed");
    let consensus_error = match &error {
        LocalReferenceError::Consensus(error) => error,
        other => panic!("expected consensus error, got {other:?}"),
    };
    assert_eq!(
        consensus_error,
        &ConsensusError::State(expected_state_error)
    );

    let typed_peer_action = peer_action_for_consensus_error(&peer_origin, consensus_error);
    assert_eq!(
        typed_peer_action,
        PeerAction::Disconnect {
            hint: PeerActionHint::InvalidBlock,
        }
    );

    let outcome = consensus_adapter
        .validate_gossip_block(
            &peer_origin,
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("witness failures should normalize to typed validation outcomes");
    assert_eq!(outcome, ValidationOutcome::Reject);
    assert_eq!(
        peer_action_for_validation_outcome(&peer_origin, outcome),
        PeerAction::Disconnect {
            hint: PeerActionHint::RejectedObject,
        }
    );
}

fn load_scenario(name: &str) -> LocalReferenceScenario {
    let loaded = load_root_check_scenario(&fixture_path(name));
    LocalReferenceScenario::from_root_check_scenario(&loaded.scenario)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/root-checks")
        .join(name)
}

fn peer_origin() -> NetworkOrigin {
    NetworkOrigin::Gossip {
        peer_id: PeerId::from([0x21; 32]),
    }
}
