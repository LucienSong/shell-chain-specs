use std::cell::Cell;
use std::path::PathBuf;

use shell_cli::{
    LocalReferenceError, LocalReferenceNetworkConsensusAdapter,
    LocalReferenceNetworkMempoolAdapter, LocalReferenceRuntime, LocalReferenceScenario,
};
use shell_consensus::{BlockImportConfig, ConsensusError};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
};
use shell_execution::ExecutionError;
use shell_fixtures::load_root_check_scenario;
use shell_mempool::AdmissionPolicy;
use shell_network::{
    peer_action_for_consensus_error, peer_action_for_validation_outcome, NetworkConsensusAdapter,
    NetworkMempoolAdapter, NetworkOrigin, PeerAction, PeerActionHint, PeerId,
};
use shell_primitives::{
    ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver, ValidationOutcome,
};

struct PermissiveDispatcher {
    transaction_calls: Cell<usize>,
    validator_calls: Cell<usize>,
}

impl PermissiveDispatcher {
    fn new() -> Self {
        Self {
            transaction_calls: Cell::new(0),
            validator_calls: Cell::new(0),
        }
    }

    fn transaction_calls(&self) -> usize {
        self.transaction_calls.get()
    }

    fn validator_calls(&self) -> usize {
        self.validator_calls.get()
    }
}

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
        self.transaction_calls.set(self.transaction_calls.get() + 1);
        Ok(())
    }

    fn verify_validator_message(
        &self,
        _scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.validator_calls.set(self.validator_calls.get() + 1);
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
fn local_reference_harness_runs_fixture_backed_happy_path_end_to_end() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let mempool_adapter =
        LocalReferenceNetworkMempoolAdapter::try_new(&runtime, &scenario).expect("adapter builds");
    let consensus_adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");
    let peer_origin = peer_origin();

    let runtime_outcome = runtime
        .run(&scenario)
        .expect("fixture-backed reference flow should import successfully");

    assert_eq!(
        runtime_outcome.admissions.len(),
        scenario.admission_transactions.len()
    );
    for (admission, transaction) in runtime_outcome
        .admissions
        .iter()
        .zip(scenario.admission_transactions.iter())
    {
        assert_eq!(admission.payload_root, transaction.payload_root().unwrap());
        assert_eq!(
            admission.verified_authorization_count,
            transaction.authorizations.len()
        );
    }
    assert_eq!(
        runtime_outcome.import_outcome.block_root,
        scenario.block.header.block_root
    );
    assert_eq!(
        runtime_outcome.import_outcome.post_state_root,
        scenario.block.header.state_root
    );
    assert_eq!(
        runtime_outcome.import_outcome.receipts_root,
        scenario.block.header.receipts_root
    );

    for transaction in &scenario.admission_transactions {
        let outcome = mempool_adapter
            .validate_gossip_transaction(&peer_origin, transaction)
            .expect("fixture transaction should admit via the harness adapter");
        assert_eq!(outcome, ValidationOutcome::Accept);
        assert_eq!(
            peer_action_for_validation_outcome(&peer_origin, outcome),
            PeerAction::Accept
        );
    }

    let block_outcome = consensus_adapter
        .validate_gossip_block(
            &peer_origin,
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("fixture block should import via the harness adapter");
    assert_eq!(block_outcome, ValidationOutcome::Accept);
    assert_eq!(
        peer_action_for_validation_outcome(&peer_origin, block_outcome),
        PeerAction::Accept
    );

    let authorization_count = scenario
        .admission_transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum::<usize>();
    assert_eq!(dispatcher.transaction_calls(), authorization_count * 4);
    assert_eq!(dispatcher.validator_calls(), 2);
}

#[test]
fn local_reference_harness_keeps_invalid_block_rejections_coherent_for_peers() {
    let scenario = load_scenario("root-check-end-to-end-state-mismatch-001.json");
    let dispatcher = PermissiveDispatcher::new();
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
        .expect_err("fixture state-root mismatch should fail closed");
    let consensus_error = match &error {
        LocalReferenceError::Consensus(error) => error,
        other => panic!("expected consensus error, got {other:?}"),
    };
    assert!(matches!(
        consensus_error,
        ConsensusError::Execution(ExecutionError::PostStateRootMismatch { .. })
    ));

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
        .expect("invalid fixture blocks should still normalize to typed reject outcomes");
    assert_eq!(outcome, ValidationOutcome::Reject);

    let outcome_peer_action = peer_action_for_validation_outcome(&peer_origin, outcome);
    assert_eq!(
        outcome_peer_action,
        PeerAction::Disconnect {
            hint: PeerActionHint::RejectedObject,
        }
    );
    assert!(matches!(typed_peer_action, PeerAction::Disconnect { .. }));
    assert!(matches!(outcome_peer_action, PeerAction::Disconnect { .. }));
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
