use std::cell::Cell;
use std::path::PathBuf;

use shell_cli::{LocalReferenceError, LocalReferenceRuntime, LocalReferenceScenario};
use shell_consensus::{BlockImportConfig, ConsensusError};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
};
use shell_execution::ExecutionError;
use shell_fixtures::load_root_check_scenario;
use shell_mempool::AdmissionPolicy;
use shell_primitives::{
    ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
    ProposerCredentialResolver,
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

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/root-checks")
        .join(name)
}
