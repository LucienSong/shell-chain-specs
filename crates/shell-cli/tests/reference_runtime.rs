use std::cell::Cell;
use std::path::PathBuf;

use shell_cli::{
    LocalReferenceError, LocalReferenceRuntime, LocalReferenceScenario, ScenarioShapeError,
};
use shell_consensus::{BlockImportConfig, ConsensusError};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
};
use shell_execution::ExecutionError;
use shell_fixtures::load_root_check_scenario;
use shell_mempool::{AdmissionPolicy, AdmissionStateView, NoncePolicy, ValidationError};
use shell_primitives::{
    ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver, TransactionEnvelope, TransactionPayload,
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

#[derive(Clone, Copy)]
enum DerivedNonceMode {
    Exact,
    ReplayReject,
    FutureGapReject,
}

struct DerivedNonceView {
    mode: DerivedNonceMode,
}

impl AdmissionStateView for DerivedNonceView {
    fn observed_nonce(&self, envelope: &TransactionEnvelope) -> Option<u64> {
        let nonce = transaction_nonce(envelope);
        Some(match self.mode {
            DerivedNonceMode::Exact => nonce,
            DerivedNonceMode::ReplayReject => nonce.saturating_add(1),
            DerivedNonceMode::FutureGapReject => nonce.saturating_sub(1),
        })
    }
}

#[test]
fn local_reference_runtime_imports_the_documented_match_flow() {
    let loaded = load_root_check_scenario(&fixture_path("root-check-end-to-end-match-001.json"));
    let scenario = LocalReferenceScenario::from_root_check_scenario(&loaded.scenario);
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let outcome = runtime
        .run(&scenario)
        .expect("the documented match fixture should import successfully");

    assert_eq!(
        outcome.admissions.len(),
        scenario.block.body.transactions.len()
    );
    assert_eq!(
        outcome.import_outcome.block_root,
        scenario.block.header.block_root
    );
    assert_eq!(
        outcome.import_outcome.post_state_root,
        scenario.block.header.state_root
    );
    assert_eq!(
        outcome.import_outcome.receipts_root,
        scenario.block.header.receipts_root
    );

    let authorization_count = scenario
        .admission_transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum::<usize>();
    assert_eq!(dispatcher.transaction_calls(), authorization_count * 2);
    assert_eq!(dispatcher.validator_calls(), 1);
}

#[test]
fn local_reference_runtime_accepts_reference_flow_with_admission_state_nonce_checks() {
    let loaded = load_root_check_scenario(&fixture_path("root-check-end-to-end-match-001.json"));
    let scenario = LocalReferenceScenario::from_root_check_scenario(&loaded.scenario);
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let nonce_view = DerivedNonceView {
        mode: DerivedNonceMode::Exact,
    };
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    )
    .with_admission_state_view(&nonce_view);

    let outcome = runtime
        .run(&scenario)
        .expect("matching observed nonces should preserve the documented flow");

    assert_eq!(
        outcome.admissions.len(),
        scenario.block.body.transactions.len()
    );
    assert_eq!(
        outcome.import_outcome.block_root,
        scenario.block.header.block_root
    );

    let authorization_count = scenario
        .admission_transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum::<usize>();
    assert_eq!(dispatcher.transaction_calls(), authorization_count * 2);
    assert_eq!(dispatcher.validator_calls(), 1);
}

#[test]
fn local_reference_runtime_preserves_state_root_mismatch_failures() {
    let loaded = load_root_check_scenario(&fixture_path(
        "root-check-end-to-end-state-mismatch-001.json",
    ));
    let scenario = LocalReferenceScenario::from_root_check_scenario(&loaded.scenario);
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let error = runtime
        .run(&scenario)
        .expect_err("state-root mismatch should fail closed");

    assert!(matches!(
        error,
        LocalReferenceError::Consensus(ConsensusError::Execution(
            ExecutionError::PostStateRootMismatch { .. }
        ))
    ));
}

#[test]
fn local_reference_runtime_preserves_receipts_root_mismatch_failures() {
    let loaded = load_root_check_scenario(&fixture_path(
        "root-check-end-to-end-receipts-mismatch-001.json",
    ));
    let scenario = LocalReferenceScenario::from_root_check_scenario(&loaded.scenario);
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let error = runtime
        .run(&scenario)
        .expect_err("receipts-root mismatch should fail closed");

    assert!(matches!(
        error,
        LocalReferenceError::Consensus(ConsensusError::Execution(
            ExecutionError::ReceiptsRootMismatch { .. }
        ))
    ));
}

#[test]
fn local_reference_runtime_rejects_admission_transaction_shape_mismatches_before_validation() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    let expected = scenario.block.body.transactions.len();
    scenario.admission_transactions.pop();
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let error = runtime
        .run(&scenario)
        .expect_err("shape mismatches should fail before transaction validation");

    assert_eq!(
        error,
        LocalReferenceError::ScenarioShape(ScenarioShapeError {
            expected,
            actual: expected - 1,
            context: "admission transactions must align one-to-one with block body transactions",
        })
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
    assert_eq!(dispatcher.validator_calls(), 0);
}

#[test]
fn local_reference_runtime_rejects_planned_transaction_shape_mismatches_before_execution() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    let expected = scenario.block.body.transactions.len();
    scenario.planned_transactions.pop();
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let error = runtime
        .run(&scenario)
        .expect_err("planned transaction shape mismatches should fail closed");

    assert_eq!(
        error,
        LocalReferenceError::ScenarioShape(ScenarioShapeError {
            expected,
            actual: expected - 1,
            context: "planned transactions must align one-to-one with block body transactions",
        })
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
    assert_eq!(dispatcher.validator_calls(), 0);
}

#[test]
fn local_reference_runtime_rejects_authorization_material_shape_mismatches_before_admission() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    let expected = scenario.block.body.transactions.len();
    scenario.transaction_authorization_materials.pop();
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let error = runtime
        .run(&scenario)
        .expect_err("authorization material shape mismatches should fail closed");

    assert_eq!(
        error,
        LocalReferenceError::ScenarioShape(ScenarioShapeError {
            expected,
            actual: expected - 1,
            context:
                "authorization material entries must align one-to-one with block body transactions",
        })
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
    assert_eq!(dispatcher.validator_calls(), 0);
}

#[test]
fn local_reference_runtime_rejects_duplicate_admission_payload_roots_before_import() {
    let mut scenario = load_scenario("root-check-end-to-end-match-001.json");
    assert!(
        scenario.admission_transactions.len() >= 2,
        "fixture should contain at least two transactions"
    );
    let authorization_count = scenario
        .admission_transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum::<usize>();
    let duplicate_root = scenario.admission_transactions[0]
        .payload_root()
        .expect("fixture transactions should have canonical payload roots");
    scenario.admission_transactions[1] = scenario.admission_transactions[0].clone();
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    );

    let error = runtime
        .run(&scenario)
        .expect_err("duplicate payload roots should fail before import");

    assert_eq!(
        error,
        LocalReferenceError::DuplicateAdmissionPayloadRoot(duplicate_root)
    );
    assert_eq!(dispatcher.transaction_calls(), authorization_count);
    assert_eq!(dispatcher.validator_calls(), 0);
}

#[test]
fn local_reference_runtime_rejects_replayed_nonces_via_admission_state_view() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let nonce_view = DerivedNonceView {
        mode: DerivedNonceMode::ReplayReject,
    };
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy::default(),
        BlockImportConfig::default(),
    )
    .with_admission_state_view(&nonce_view);

    let error = runtime
        .run(&scenario)
        .expect_err("replayed nonces should fail closed before authorization verification");

    assert_eq!(
        error,
        LocalReferenceError::Admission(ValidationError::NoncePolicy(
            shell_mempool::NoncePolicyError {
                context: "transaction nonce is lower than the observed replay lane nonce",
            }
        ))
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
    assert_eq!(dispatcher.validator_calls(), 0);
}

#[test]
fn local_reference_runtime_rejects_future_nonce_gap_via_admission_state_view() {
    let scenario = load_scenario("root-check-end-to-end-match-001.json");
    let dispatcher = PermissiveDispatcher::new();
    let resolver = FixedResolver;
    let nonce_view = DerivedNonceView {
        mode: DerivedNonceMode::FutureGapReject,
    };
    let runtime = LocalReferenceRuntime::new(
        &dispatcher,
        &resolver,
        AdmissionPolicy {
            nonce_policy: NoncePolicy {
                max_future_nonce_gap: 0,
            },
            ..AdmissionPolicy::default()
        },
        BlockImportConfig::default(),
    )
    .with_admission_state_view(&nonce_view);

    let error = runtime
        .run(&scenario)
        .expect_err("future nonce gaps should fail closed before authorization verification");

    assert_eq!(
        error,
        LocalReferenceError::Admission(ValidationError::NoncePolicy(
            shell_mempool::NoncePolicyError {
                context: "transaction nonce exceeds the configured future replay lane gap",
            }
        ))
    );
    assert_eq!(dispatcher.transaction_calls(), 0);
    assert_eq!(dispatcher.validator_calls(), 0);
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

fn transaction_nonce(envelope: &TransactionEnvelope) -> u64 {
    match envelope.payload.payload() {
        TransactionPayload::Basic(payload) => payload.nonce,
        TransactionPayload::Create(payload) => payload.nonce,
    }
}
