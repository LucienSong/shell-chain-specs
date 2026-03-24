use std::cell::Cell;

use shell_consensus::{
    BlockExecutionEngine, BlockImportPipeline, BlockImportServices, ConsensusBody, ConsensusError,
    ConsensusHeader, ConsensusSidecar, TransactionRevalidator, WitnessPreparer,
};
use shell_crypto::{
    CryptoError, DispatcherConfig, Ed25519Verifier, SignatureDispatcher, SignatureLimitKind,
    SignatureSizeExceededError, SignatureVerificationRequest, SignatureVerifier,
    UnsupportedSchemeError, VerificationPath, VerifierRegistry,
};
use shell_execution::{BlockExecutionOutcome, ExecutionError};
use shell_fixtures::{
    crypto_fixture_paths, load_fixture, parse_hex, CryptoExpectedError, CryptoVector,
    VerificationPathInput,
};
use shell_mempool::{MultiAuthorizationPolicy, ValidationError};
use shell_primitives::{
    BasicTransactionPayload, PrimitiveError, ProposerCredential, ProposerCredentialQuery,
    ProposerCredentialResolutionError, ProtocolObject, Root, TransactionEnvelope,
    TransactionPayload, TransactionPayloadSsz,
};
use shell_state::StateError;

#[derive(Clone)]
struct StubHeader {
    block_root: Root,
    transactions_root: Root,
    execution_witnesses_root: Root,
    state_root: Root,
    receipts_root: Root,
    proposer_signature: Vec<u8>,
}

impl ProtocolObject for StubHeader {
    fn canonical_root(&self) -> Result<Root, PrimitiveError> {
        Ok(self.block_root)
    }
}

impl ConsensusHeader for StubHeader {
    fn witness_bytes(&self) -> u64 {
        128
    }

    fn transactions_root(&self) -> Root {
        self.transactions_root
    }

    fn execution_witnesses_root(&self) -> Root {
        self.execution_witnesses_root
    }

    fn state_root(&self) -> Root {
        self.state_root
    }

    fn receipts_root(&self) -> Root {
        self.receipts_root
    }

    fn proposer_signature(&self) -> &[u8] {
        &self.proposer_signature
    }

    fn proposer_index_hint(&self) -> Option<u64> {
        Some(7)
    }
}

struct StubBody {
    transactions: Vec<TransactionEnvelope>,
    transactions_root: Root,
}

impl ConsensusBody for StubBody {
    fn transactions_root(&self) -> Result<Root, PrimitiveError> {
        Ok(self.transactions_root)
    }

    fn transactions(&self) -> &[TransactionEnvelope] {
        &self.transactions
    }
}

struct StubSidecar {
    block_root: Root,
    committed_root: Root,
}

impl ConsensusSidecar for StubSidecar {
    fn block_root(&self) -> Root {
        self.block_root
    }

    fn committed_root(&self) -> Root {
        self.committed_root
    }
}

struct CountingResolver {
    calls: Cell<usize>,
    credential: ProposerCredential,
}

impl CountingResolver {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl shell_primitives::ProposerCredentialResolver for CountingResolver {
    fn resolve_proposer_credential(
        &self,
        _query: ProposerCredentialQuery,
    ) -> Result<ProposerCredential, ProposerCredentialResolutionError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.credential.clone())
    }
}

struct CountingDispatcher {
    calls: Cell<usize>,
    registry: VerifierRegistry,
}

impl CountingDispatcher {
    fn from_fixture(fixture: &CryptoVector) -> Self {
        let mut registry = if let Some(config) = &fixture.input.dispatcher_config {
            VerifierRegistry::with_config(DispatcherConfig {
                user_path_max_signature_size: config
                    .user_path_max_signature_size
                    .unwrap_or(shell_crypto::DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE),
                validator_path_max_signature_size: config.validator_path_max_signature_size,
            })
        } else {
            VerifierRegistry::default()
        };
        registry.register_verifier(Box::new(Ed25519Verifier::new()));

        Self {
            calls: Cell::new(0),
            registry,
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl SignatureDispatcher for CountingDispatcher {
    fn register_verifier(
        &mut self,
        verifier: Box<dyn SignatureVerifier>,
    ) -> Option<Box<dyn SignatureVerifier>> {
        self.registry.register_verifier(verifier)
    }

    fn verifier(&self, scheme_id: u8) -> Option<&dyn SignatureVerifier> {
        self.registry.verifier(scheme_id)
    }

    fn verify_transaction_authorization(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.registry
            .verify_transaction_authorization(scheme_id, request)
    }

    fn verify_validator_message(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.calls.set(self.calls.get() + 1);
        self.registry.verify_validator_message(scheme_id, request)
    }
}

struct CountingRevalidator {
    calls: Cell<usize>,
}

impl CountingRevalidator {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl TransactionRevalidator for CountingRevalidator {
    fn revalidate(
        &self,
        _transaction: &TransactionEnvelope,
        _multi_authorization_policy: MultiAuthorizationPolicy,
    ) -> Result<(), ValidationError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

struct CountingWitnessPreparer {
    calls: Cell<usize>,
}

impl CountingWitnessPreparer {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl WitnessPreparer for CountingWitnessPreparer {
    fn prepare_witness(
        &self,
        _header: &dyn ConsensusHeader,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<(), StateError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

struct CountingExecutionEngine {
    calls: Cell<usize>,
}

impl CountingExecutionEngine {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl BlockExecutionEngine for CountingExecutionEngine {
    fn execute_block(
        &self,
        _header: &dyn ConsensusHeader,
        _body: &dyn ConsensusBody,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<BlockExecutionOutcome, ExecutionError> {
        self.calls.set(self.calls.get() + 1);
        unreachable!("validator-path negative fixtures should never execute blocks")
    }
}

#[test]
fn validator_path_negative_crypto_vectors_stop_consensus_at_b1() {
    let mut paths = crypto_fixture_paths();
    paths.sort();

    let mut seen = 0;
    for path in paths {
        let fixture: CryptoVector = load_fixture(&path);
        if fixture.expected_outcome != "reject"
            || fixture.input.verification_path != VerificationPathInput::ValidatorMessage
        {
            continue;
        }

        seen += 1;

        let header = StubHeader {
            block_root: [0x11; 32],
            transactions_root: [0x22; 32],
            execution_witnesses_root: [0x33; 32],
            state_root: [0x44; 32],
            receipts_root: [0x55; 32],
            proposer_signature: parse_hex(&fixture.input.signature_hex),
        };
        let body = StubBody {
            transactions_root: header.transactions_root,
            transactions: vec![sample_transaction()],
        };
        let sidecar = StubSidecar {
            block_root: header.block_root,
            committed_root: header.execution_witnesses_root,
        };
        let resolver = CountingResolver {
            calls: Cell::new(0),
            credential: ProposerCredential {
                scheme_id: fixture.input.scheme_id,
                public_key_material: parse_hex(&fixture.input.public_key_hex),
            },
        };
        let dispatcher = CountingDispatcher::from_fixture(&fixture);
        let revalidator = CountingRevalidator {
            calls: Cell::new(0),
        };
        let preparer = CountingWitnessPreparer {
            calls: Cell::new(0),
        };
        let engine = CountingExecutionEngine {
            calls: Cell::new(0),
        };

        let error = BlockImportPipeline::default()
            .import_block(
                &header,
                &body,
                &sidecar,
                BlockImportServices {
                    resolver: &resolver,
                    dispatcher: &dispatcher,
                    revalidator: &revalidator,
                    preparer: &preparer,
                    execution_engine: &engine,
                },
            )
            .expect_err(&format!(
                "{} should fail during validator-path signature verification",
                fixture.id
            ));

        let actual = match error {
            ConsensusError::Crypto(actual) => actual,
            other => panic!(
                "{} expected ConsensusError::Crypto, got {other:?}",
                fixture.id
            ),
        };
        assert_crypto_error(&fixture, fixture.expected_error.as_ref().unwrap(), actual);
        assert_eq!(resolver.calls(), 1, "{} resolver count drifted", fixture.id);
        assert_eq!(
            dispatcher.calls(),
            1,
            "{} dispatcher count drifted",
            fixture.id
        );
        assert_eq!(
            revalidator.calls(),
            0,
            "{} revalidator count drifted",
            fixture.id
        );
        assert_eq!(
            preparer.calls(),
            0,
            "{} witness stage count drifted",
            fixture.id
        );
        assert_eq!(
            engine.calls(),
            0,
            "{} execution stage count drifted",
            fixture.id
        );
    }

    assert!(
        seen > 0,
        "expected validator-path reject fixtures under vectors/crypto"
    );
}

fn sample_transaction() -> TransactionEnvelope {
    TransactionEnvelope {
        payload: TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
            nonce: 1,
            gas_limit: 21_000,
            ..Default::default()
        })),
        authorizations: vec![],
    }
}

fn assert_crypto_error(fixture: &CryptoVector, expected: &CryptoExpectedError, err: CryptoError) {
    match (&*expected.kind, err) {
        ("UnsupportedScheme", CryptoError::UnsupportedScheme(actual)) => {
            if let Some(scheme_id) = expected.scheme_id {
                assert_eq!(
                    actual,
                    UnsupportedSchemeError { scheme_id },
                    "{}",
                    fixture.id
                );
            }
        }
        ("SignatureSizeExceeded", CryptoError::SignatureSizeExceeded(actual)) => {
            assert_signature_size_exceeded(fixture, expected, actual);
        }
        ("VerificationFailed", CryptoError::VerificationFailed(actual)) => {
            if let Some(scheme_id) = expected.scheme_id {
                assert_eq!(
                    actual.scheme_id, scheme_id,
                    "{} scheme_id drifted",
                    fixture.id
                );
            }
            if let Some(context) = &expected.context {
                assert_eq!(actual.context, context, "{} context drifted", fixture.id);
            }
        }
        (kind, actual) => panic!(
            "{} expected crypto error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

fn assert_signature_size_exceeded(
    fixture: &CryptoVector,
    expected: &CryptoExpectedError,
    actual: SignatureSizeExceededError,
) {
    if let Some(max_size) = expected.max_size {
        assert_eq!(actual.max_size, max_size, "{} max_size drifted", fixture.id);
    }
    if let Some(actual_size) = expected.actual_size {
        assert_eq!(
            actual.actual_size, actual_size,
            "{} actual_size drifted",
            fixture.id
        );
    }
    if let Some(path) = &expected.path {
        assert_eq!(
            actual.path,
            parse_verification_path(path),
            "{} path drifted",
            fixture.id
        );
    }
    if let Some(kind) = &expected.limit_kind {
        assert_eq!(
            actual.kind,
            parse_signature_limit_kind(kind),
            "{} limit kind drifted",
            fixture.id
        );
    }
}

fn parse_verification_path(value: &str) -> VerificationPath {
    match value {
        "transaction_authorization" => VerificationPath::TransactionAuthorization,
        "validator_message" => VerificationPath::ValidatorMessage,
        other => panic!("unsupported verification path {other:?}"),
    }
}

fn parse_signature_limit_kind(value: &str) -> SignatureLimitKind {
    match value {
        "repository_rule" => SignatureLimitKind::RepositoryRule,
        "local_transport_guard" => SignatureLimitKind::LocalTransportGuard,
        "scheme" => SignatureLimitKind::Scheme,
        other => panic!("unsupported signature limit kind {other:?}"),
    }
}
