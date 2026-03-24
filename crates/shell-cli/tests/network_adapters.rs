use std::cell::Cell;
use std::path::PathBuf;

use shell_cli::{
    LocalReferenceNetworkConsensusAdapter, LocalReferenceNetworkMempoolAdapter,
    LocalReferenceRuntime, LocalReferenceScenario,
};
use shell_consensus::{BlockImportConfig, ConsensusError, HeaderPrefilterConfig};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
    VerificationFailure,
};
use shell_fixtures::load_root_check_scenario;
use shell_mempool::{
    AdmissionPolicy, AuthorizationMaterialCountError, FeeSchedule, ValidationError,
};
use shell_network::{NetworkConsensusAdapter, NetworkMempoolAdapter, NetworkOrigin, PeerId};
use shell_primitives::{
    GasPrice, ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver, TransactionEnvelope, TransactionPayload, TransactionPayloadSsz,
    ValidationOutcome, U256,
};

struct TestDispatcher {
    transaction_calls: Cell<usize>,
    validator_calls: Cell<usize>,
    transaction_error: Option<CryptoError>,
    validator_error: Option<CryptoError>,
}

impl TestDispatcher {
    fn permissive() -> Self {
        Self {
            transaction_calls: Cell::new(0),
            validator_calls: Cell::new(0),
            transaction_error: None,
            validator_error: None,
        }
    }

    fn reject_transaction_signature() -> Self {
        Self {
            transaction_error: Some(CryptoError::VerificationFailed(VerificationFailure {
                scheme_id: 0,
                context: "mock dispatcher rejected the transaction authorization",
            })),
            ..Self::permissive()
        }
    }

    fn transaction_calls(&self) -> usize {
        self.transaction_calls.get()
    }
}

impl SignatureDispatcher for TestDispatcher {
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
        self.transaction_error.map_or(Ok(()), Err)
    }

    fn verify_validator_message(
        &self,
        _scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.validator_calls.set(self.validator_calls.get() + 1);
        self.validator_error.map_or(Ok(()), Err)
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

struct UnavailableResolver;

impl ProposerCredentialResolver for UnavailableResolver {
    fn resolve_proposer_credential(
        &self,
        _query: ProposerCredentialQuery,
    ) -> Result<ProposerCredential, ProposerCredentialResolutionError> {
        Err(ProposerCredentialResolutionError::ResolverUnavailable)
    }
}

#[test]
fn mempool_adapter_accepts_reference_transactions() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter =
        LocalReferenceNetworkMempoolAdapter::try_new(&runtime, &scenario).expect("adapter builds");

    let outcome = adapter
        .validate_gossip_transaction(&peer_origin(), &scenario.admission_transactions[0])
        .expect("reference transaction should validate");

    assert_eq!(outcome, ValidationOutcome::Accept);
}

#[test]
fn mempool_adapter_maps_fee_policy_failures_to_policy_reject() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy {
            fee_schedule: FeeSchedule {
                payload_lane_base_fee: gas_price(10_000),
                witness_lane_base_fee: gas_price(10_000),
            },
            ..AdmissionPolicy::default()
        },
        BlockImportConfig::default(),
    );
    let adapter =
        LocalReferenceNetworkMempoolAdapter::try_new(&runtime, &scenario).expect("adapter builds");

    let outcome = adapter
        .validate_gossip_transaction(&peer_origin(), &scenario.admission_transactions[0])
        .expect("policy failures should stay typed outcomes");

    assert_eq!(outcome, ValidationOutcome::PolicyReject);
}

#[test]
fn mempool_adapter_maps_invalid_signatures_to_reject() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::reject_transaction_signature();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter =
        LocalReferenceNetworkMempoolAdapter::try_new(&runtime, &scenario).expect("adapter builds");

    let outcome = adapter
        .validate_gossip_transaction(&peer_origin(), &scenario.admission_transactions[0])
        .expect("invalid remote transactions should map to reject");

    assert_eq!(outcome, ValidationOutcome::Reject);
}

#[test]
fn mempool_adapter_preserves_missing_authorization_material_errors() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    scenario.transaction_authorization_materials[0].clear();
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter =
        LocalReferenceNetworkMempoolAdapter::try_new(&runtime, &scenario).expect("adapter builds");

    let error = adapter
        .validate_gossip_transaction(&peer_origin(), &scenario.admission_transactions[0])
        .expect_err("missing authorization material should stay an internal error");

    assert_eq!(
        error,
        ValidationError::AuthorizationMaterialCount(AuthorizationMaterialCountError {
            expected: scenario.admission_transactions[0].authorizations.len(),
            actual: 0,
        })
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
}

#[test]
fn mempool_adapter_fails_closed_for_altered_gossip_payloads() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter =
        LocalReferenceNetworkMempoolAdapter::try_new(&runtime, &scenario).expect("adapter builds");
    let mut altered_transaction = scenario.admission_transactions[0].clone();
    alter_transaction_payload(&mut altered_transaction);

    let error = adapter
        .validate_gossip_transaction(&peer_origin(), &altered_transaction)
        .expect_err("altered gossip payloads should fail closed");

    assert_eq!(
        error,
        ValidationError::AuthorizationMaterialCount(AuthorizationMaterialCountError {
            expected: altered_transaction.authorizations.len(),
            actual: 0,
        })
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
}

#[test]
fn consensus_adapter_accepts_reference_blocks() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");

    let outcome = adapter
        .validate_gossip_block(
            &peer_origin(),
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("reference block should validate");

    assert_eq!(outcome, ValidationOutcome::Accept);
}

#[test]
fn consensus_adapter_maps_header_prefilter_failures_to_policy_reject() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    assert!(
        scenario.block.header.witness_bytes > 0,
        "fixture should exercise witness-byte limits"
    );
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig {
            header_prefilter: HeaderPrefilterConfig {
                max_witness_bytes: Some(scenario.block.header.witness_bytes - 1),
            },
            ..BlockImportConfig::default()
        },
    );
    let adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");

    let outcome = adapter
        .validate_gossip_block(
            &peer_origin(),
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("policy failures should stay typed outcomes");

    assert_eq!(outcome, ValidationOutcome::PolicyReject);
}

#[test]
fn consensus_adapter_maps_invalid_reference_blocks_to_reject() {
    let scenario = load_scenario("root-check-end-to-end-state-mismatch-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");

    let outcome = adapter
        .validate_gossip_block(
            &peer_origin(),
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect("invalid remote blocks should map to reject");

    assert_eq!(outcome, ValidationOutcome::Reject);
}

#[test]
fn consensus_adapter_preserves_missing_authorization_material_errors() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    scenario.transaction_authorization_materials[0].clear();
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");

    let error = adapter
        .validate_gossip_block(
            &peer_origin(),
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect_err("missing authorization material should stay an internal consensus error");

    assert_eq!(
        error,
        ConsensusError::TransactionValidation(ValidationError::AuthorizationMaterialCount(
            AuthorizationMaterialCountError {
                expected: 1,
                actual: 0,
            }
        ))
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
}

#[test]
fn consensus_adapter_rejects_altered_gossip_block_inputs() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");
    let mut altered_body = scenario.block.body.clone();
    altered_body.transactions_root[0] ^= 0xFF;

    let outcome = adapter
        .validate_gossip_block(
            &peer_origin(),
            &scenario.block.header,
            &altered_body,
            &scenario.block.sidecar,
        )
        .expect("altered block bindings should still normalize to reject");

    assert_eq!(outcome, ValidationOutcome::Reject);
    assert_eq!(dispatcher.transaction_calls(), 0);
}

#[test]
fn consensus_adapter_preserves_internal_resolution_errors() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = TestDispatcher::permissive();
    let resolver = UnavailableResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );
    let adapter = LocalReferenceNetworkConsensusAdapter::try_new(&runtime, &scenario)
        .expect("adapter builds");

    let error = adapter
        .validate_gossip_block(
            &peer_origin(),
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
        )
        .expect_err("internal resolver failures should stay typed errors");

    assert_eq!(
        error,
        ConsensusError::ProposerCredentialResolution(
            ProposerCredentialResolutionError::ResolverUnavailable
        )
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
        peer_id: PeerId::from([7; 32]),
    }
}

fn gas_price(value: u64) -> GasPrice {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    GasPrice(U256(bytes))
}

fn alter_transaction_payload(transaction: &mut TransactionEnvelope) {
    let altered_payload = match transaction.payload.payload().clone() {
        TransactionPayload::Basic(mut payload) => {
            payload.nonce = payload.nonce.wrapping_add(1);
            TransactionPayload::Basic(payload)
        }
        TransactionPayload::Create(mut payload) => {
            payload.nonce = payload.nonce.wrapping_add(1);
            TransactionPayload::Create(payload)
        }
    };
    transaction.payload = TransactionPayloadSsz::from(altered_payload);
}
