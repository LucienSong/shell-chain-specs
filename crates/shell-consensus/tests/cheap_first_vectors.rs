use std::cell::Cell;

use shell_consensus::{
    BlockExecutionEngine, BlockImportConfig, BlockImportPipeline, BlockImportServices,
    ConsensusBody, ConsensusError, ConsensusHeader, ConsensusSidecar, HeaderBodyRootMismatchError,
    HeaderPrefilterConfig, SidecarCommitmentMismatchError, TransactionRevalidator,
    WitnessByteLimitExceededError, WitnessPreparer,
};
use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
    UnsupportedSchemeError, VerificationFailure,
};
use shell_execution::{BlockExecutionOutcome, ExecutionError, ExecutionReceipt};
use shell_fixtures::{
    load_fixture, parse_hex, parse_root, validation_order_fixture_paths, CheapFirstInput,
    CheapFirstVector, ConsensusInput, SignatureOutcome,
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
    witness_bytes: u64,
    transactions_root: Root,
    execution_witnesses_root: Root,
    state_root: Root,
    receipts_root: Root,
    proposer_signature: Vec<u8>,
    proposer_index_hint: Option<u64>,
}

impl ProtocolObject for StubHeader {
    fn canonical_root(&self) -> Result<Root, PrimitiveError> {
        Ok(self.block_root)
    }
}

impl ConsensusHeader for StubHeader {
    fn witness_bytes(&self) -> u64 {
        self.witness_bytes
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
        self.proposer_index_hint
    }
}

struct StubBody {
    root: Root,
    transactions: Vec<TransactionEnvelope>,
}

impl ConsensusBody for StubBody {
    fn transactions_root(&self) -> Result<Root, PrimitiveError> {
        Ok(self.root)
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
    outcome: SignatureOutcome,
}

impl CountingDispatcher {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl SignatureDispatcher for CountingDispatcher {
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
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedScheme(UnsupportedSchemeError {
            scheme_id,
        }))
    }

    fn verify_validator_message(
        &self,
        scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.calls.set(self.calls.get() + 1);
        match self.outcome {
            SignatureOutcome::Accept => Ok(()),
            SignatureOutcome::Reject => Err(CryptoError::VerificationFailed(VerificationFailure {
                scheme_id,
                context: "shared cheap-first consensus fixture rejected the proposer signature",
            })),
        }
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

struct FixedExecutionEngine {
    calls: Cell<usize>,
    outcome: BlockExecutionOutcome,
}

impl FixedExecutionEngine {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl BlockExecutionEngine for FixedExecutionEngine {
    fn execute_block(
        &self,
        _header: &dyn ConsensusHeader,
        _body: &dyn ConsensusBody,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<BlockExecutionOutcome, ExecutionError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.outcome.clone())
    }
}

#[test]
fn shared_cheap_first_vectors_cover_consensus_ordering_contract() {
    let mut paths = validation_order_fixture_paths();
    paths.sort();

    let mut seen = 0;
    for path in paths {
        let fixture: CheapFirstVector = load_fixture(&path);
        let CheapFirstInput::Consensus(input) = &fixture.input else {
            continue;
        };
        seen += 1;

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "validation-order",
            "{} must declare category 'validation-order'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-consensus",
            "{} must be owned by shell-consensus",
            fixture.id
        );

        assert_rejects_in_stage_order(&fixture, input);
    }

    assert!(
        seen > 0,
        "expected at least one shared cheap-first fixture for shell-consensus"
    );
}

fn assert_rejects_in_stage_order(fixture: &CheapFirstVector, input: &ConsensusInput) {
    let header = build_header(input);
    let body = build_body(input, &header);
    let sidecar = build_sidecar(input, &header);
    let pipeline = BlockImportPipeline::new(BlockImportConfig {
        header_prefilter: HeaderPrefilterConfig {
            max_witness_bytes: input
                .prefilter
                .as_ref()
                .and_then(|prefilter| prefilter.max_witness_bytes),
        },
        multi_authorization_policy: MultiAuthorizationPolicy::RequireAll,
    });
    let resolver = CountingResolver {
        calls: Cell::new(0),
        credential: ProposerCredential {
            scheme_id: input.resolver.scheme_id,
            public_key_material: parse_hex(&input.resolver.public_key_hex),
        },
    };
    let dispatcher = CountingDispatcher {
        calls: Cell::new(0),
        outcome: input.dispatcher.validator_signature,
    };
    let revalidator = CountingRevalidator {
        calls: Cell::new(0),
    };
    let preparer = CountingWitnessPreparer {
        calls: Cell::new(0),
    };
    let engine = FixedExecutionEngine {
        calls: Cell::new(0),
        outcome: build_execution_outcome(input, &header),
    };

    let error = pipeline
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
            "{} should reject before a later stage runs",
            fixture.id
        ));

    match fixture.expected_error.kind.as_str() {
        "WitnessByteLimitExceeded" => {
            let ConsensusError::WitnessByteLimitExceeded(actual) = error else {
                panic!(
                    "{} expected WitnessByteLimitExceeded, got {:?}",
                    fixture.id, error
                );
            };
            let max_bytes = input
                .prefilter
                .as_ref()
                .and_then(|prefilter| prefilter.max_witness_bytes)
                .expect("prefilter vectors must declare max_witness_bytes");
            assert_eq!(
                actual,
                WitnessByteLimitExceededError {
                    max_bytes,
                    actual_bytes: header.witness_bytes,
                },
                "{} witness byte guard mismatch",
                fixture.id
            );
            assert_eq!(fixture.expected_outcome, "policy_reject");
        }
        "TransactionsRootMismatch" => {
            let ConsensusError::HeaderBodyRootMismatch(actual) = error else {
                panic!(
                    "{} expected TransactionsRootMismatch, got {:?}",
                    fixture.id, error
                );
            };
            assert_eq!(
                actual,
                HeaderBodyRootMismatchError {
                    expected: header.transactions_root,
                    actual: body.root,
                },
                "{} body-root mismatch drifted",
                fixture.id
            );
            assert_eq!(fixture.expected_outcome, "reject");
        }
        "SignatureVerification" => {
            assert!(matches!(
                error,
                ConsensusError::Crypto(CryptoError::VerificationFailed(_))
            ));
            assert_eq!(fixture.expected_outcome, "reject");
        }
        "SidecarMismatch" => {
            let ConsensusError::SidecarCommitmentMismatch(actual) = error else {
                panic!("{} expected SidecarMismatch, got {:?}", fixture.id, error);
            };
            assert_eq!(
                actual,
                SidecarCommitmentMismatchError {
                    expected: header.execution_witnesses_root,
                    actual: sidecar.committed_root,
                },
                "{} sidecar mismatch drifted",
                fixture.id
            );
            assert_eq!(fixture.expected_outcome, "reject");
        }
        kind => panic!(
            "{} has unsupported expected_error kind {:?}",
            fixture.id, kind
        ),
    }

    assert_optional_effect(
        fixture.expected_effects.proposer_credential_resolutions,
        resolver.calls(),
        fixture,
        "resolver call",
    );
    assert_optional_effect(
        fixture.expected_effects.validator_signature_verifications,
        dispatcher.calls(),
        fixture,
        "validator verification",
    );
    assert_optional_effect(
        fixture.expected_effects.transaction_revalidations,
        revalidator.calls(),
        fixture,
        "transaction revalidation",
    );
    assert_optional_effect(
        fixture.expected_effects.witness_preparations,
        preparer.calls(),
        fixture,
        "witness preparation",
    );
    assert_optional_effect(
        fixture.expected_effects.execution_calls,
        engine.calls(),
        fixture,
        "execution",
    );
}

fn assert_optional_effect(
    expected: Option<usize>,
    actual: usize,
    fixture: &CheapFirstVector,
    label: &str,
) {
    if let Some(expected) = expected {
        assert_eq!(actual, expected, "{} {} count mismatch", fixture.id, label);
    }
}

fn build_header(input: &ConsensusInput) -> StubHeader {
    StubHeader {
        block_root: parse_root(&input.header.block_root),
        witness_bytes: input.header.witness_bytes,
        transactions_root: parse_root(&input.header.transactions_root),
        execution_witnesses_root: parse_root(&input.header.execution_witnesses_root),
        state_root: parse_root(&input.header.state_root),
        receipts_root: parse_root(&input.header.receipts_root),
        proposer_signature: parse_hex(&input.header.proposer_signature_hex),
        proposer_index_hint: Some(input.header.proposer_index),
    }
}

fn build_body(input: &ConsensusInput, header: &StubHeader) -> StubBody {
    StubBody {
        root: input
            .body
            .transactions_root_mode
            .apply(header.transactions_root),
        transactions: (0..input.body.transaction_count)
            .map(|index| sample_transaction(index as u64 + 1))
            .collect(),
    }
}

fn build_sidecar(input: &ConsensusInput, header: &StubHeader) -> StubSidecar {
    StubSidecar {
        block_root: input.sidecar.block_root_mode.apply(header.block_root),
        committed_root: input
            .sidecar
            .committed_root_mode
            .apply(header.execution_witnesses_root),
    }
}

fn build_execution_outcome(input: &ConsensusInput, header: &StubHeader) -> BlockExecutionOutcome {
    let post_state_root = input
        .execution
        .post_state_root_mode
        .apply(header.state_root);
    let receipts_root = input
        .execution
        .receipts_root_mode
        .apply(header.receipts_root);
    BlockExecutionOutcome {
        post_state_root,
        receipts_root,
        transaction_outcomes: vec![shell_execution::TransactionExecutionOutcome {
            transaction_root: [0x11; 32],
            post_state_root,
            receipt: ExecutionReceipt {
                status_code: 1,
                output: vec![0x22],
            },
        }],
    }
}

fn sample_transaction(nonce: u64) -> TransactionEnvelope {
    TransactionEnvelope {
        payload: TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
            nonce,
            gas_limit: 21_000,
            ..Default::default()
        })),
        authorizations: vec![],
    }
}
