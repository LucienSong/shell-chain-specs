use std::cell::Cell;
use std::path::PathBuf;

use shell_cli::{
    LocalReferenceNetworkConsensusAdapter, LocalReferenceNetworkMempoolAdapter,
    LocalReferenceRuntime, LocalReferenceScenario, OwnedAuthorizationMaterial,
};
use shell_consensus::BlockImportConfig;
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
    VerificationFailure,
};
use shell_fixtures::load_root_check_scenario;
use shell_mempool::AdmissionPolicy;
use shell_network::{NetworkConsensusAdapter, NetworkMempoolAdapter, NetworkOrigin, PeerId};
use shell_primitives::{
    Authorization, ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver, ValidationOutcome,
};

const SECOND_AUTH_SIGNATURE_BYTE: u8 = 0x5A;

struct HarnessDispatcher {
    transaction_calls: Cell<usize>,
    validator_calls: Cell<usize>,
    rejected_signature: Option<Vec<u8>>,
}

impl HarnessDispatcher {
    fn permissive() -> Self {
        Self {
            transaction_calls: Cell::new(0),
            validator_calls: Cell::new(0),
            rejected_signature: None,
        }
    }

    fn reject_signature(signature: Vec<u8>) -> Self {
        Self {
            rejected_signature: Some(signature),
            ..Self::permissive()
        }
    }

    fn transaction_calls(&self) -> usize {
        self.transaction_calls.get()
    }

    fn validator_calls(&self) -> usize {
        self.validator_calls.get()
    }
}

impl SignatureDispatcher for HarnessDispatcher {
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
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.transaction_calls.set(self.transaction_calls.get() + 1);
        if self
            .rejected_signature
            .as_ref()
            .is_some_and(|signature| signature.as_slice() == request.signature)
        {
            return Err(CryptoError::VerificationFailed(VerificationFailure {
                scheme_id,
                context: "mock dispatcher rejected the extra required authorization",
            }));
        }
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
fn local_reference_harness_accepts_multi_authorization_transactions_under_require_all() {
    let scenario = multi_authorization_scenario();
    let dispatcher = HarnessDispatcher::permissive();
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

    let outcome = runtime
        .run(&scenario)
        .expect("multi-authorization reference flow should import successfully");

    assert_eq!(outcome.admissions[0].verified_authorization_count, 2);

    for transaction in &scenario.admission_transactions {
        let validation = mempool_adapter
            .validate_gossip_transaction(&peer_origin, transaction)
            .expect("multi-authorization transaction should validate");
        assert_eq!(validation, ValidationOutcome::Accept);
    }

    let block_validation = consensus_adapter
        .validate_gossip_block(
            &peer_origin,
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("fixture block should accept with all required authorizations present");
    assert_eq!(block_validation, ValidationOutcome::Accept);

    let authorization_count = scenario
        .admission_transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum::<usize>();
    assert_eq!(dispatcher.transaction_calls(), authorization_count * 4);
    assert_eq!(dispatcher.validator_calls(), 2);
}

#[test]
fn local_reference_harness_rejects_when_any_required_authorization_fails() {
    let scenario = multi_authorization_scenario();
    let dispatcher = HarnessDispatcher::reject_signature(vec![SECOND_AUTH_SIGNATURE_BYTE; 64]);
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

    let transaction_validation = mempool_adapter
        .validate_gossip_transaction(&peer_origin, &scenario.admission_transactions[0])
        .expect("signature failures should stay typed as reject");
    assert_eq!(transaction_validation, ValidationOutcome::Reject);

    let block_validation = consensus_adapter
        .validate_gossip_block(
            &peer_origin,
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("block validation should fail closed as a typed reject");
    assert_eq!(block_validation, ValidationOutcome::Reject);
    assert_eq!(dispatcher.transaction_calls(), 4);
    assert_eq!(dispatcher.validator_calls(), 1);
}

fn multi_authorization_scenario() -> LocalReferenceScenario {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    add_required_authorization(
        &mut scenario.admission_transactions[0],
        &mut scenario.transaction_authorization_materials[0],
    );
    scenario
}

fn add_required_authorization(
    transaction: &mut shell_primitives::TransactionEnvelope,
    materials: &mut Vec<OwnedAuthorizationMaterial>,
) {
    let payload_root = transaction
        .payload_root()
        .expect("fixture transactions should have canonical payload roots");
    transaction.authorizations.push(Authorization {
        scheme_id: 0,
        payload_root,
        signature: vec![SECOND_AUTH_SIGNATURE_BYTE; 64],
    });
    materials.push(OwnedAuthorizationMaterial::reference_default());
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
        peer_id: PeerId::from([0x2A; 32]),
    }
}
