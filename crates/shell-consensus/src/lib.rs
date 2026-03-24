#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod execution_bridge;
pub mod header_checks;
pub mod import;
pub mod objects;
pub mod outcomes;
pub mod sidecars;

pub use crate::execution_bridge::{execute_and_compare, BlockExecutionEngine};
pub use crate::header_checks::{
    prefilter_header, verify_header_signature, ConsensusHeader, HeaderCheckOutcome,
    HeaderPrefilterConfig,
};
pub use crate::import::{
    revalidate_body_transactions, verify_body_binding, BlockImportConfig, BlockImportPipeline,
    BlockImportServices, ConsensusBody, TransactionRevalidator,
};
pub use crate::objects::{
    CanonicalBlock, CanonicalBlockBody, CanonicalBlockHeader, CanonicalBlockSidecar,
};
pub use crate::outcomes::{
    BlockImportOutcome, ConsensusError, HeaderBodyRootMismatchError, SidecarBlockRootMismatchError,
    SidecarCommitmentMismatchError, WitnessByteLimitExceededError,
};
pub use crate::sidecars::{verify_sidecar_binding, ConsensusSidecar, WitnessPreparer};

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec, vec::Vec};
    use core::cell::Cell;

    use super::*;
    use shell_crypto::{
        CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
        UnsupportedSchemeError,
    };
    use shell_execution::{BlockExecutionOutcome, ExecutionReceipt};
    use shell_mempool::{MultiAuthorizationPolicy, ValidationError};
    use shell_primitives::{
        Authorization, BasicTransactionPayload, InvalidCredentialEncodingError, PrimitiveError,
        ProposerCredential, ProposerCredentialQuery, ProposerCredentialResolutionError,
        ProtocolObject, Root, TransactionEnvelope, TransactionPayload, TransactionPayloadSsz,
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
        failure: Option<ProposerCredentialResolutionError>,
    }

    impl CountingResolver {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
                failure: None,
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl shell_primitives::ProposerCredentialResolver for CountingResolver {
        fn resolve_proposer_credential(
            &self,
            query: ProposerCredentialQuery,
        ) -> Result<ProposerCredential, ProposerCredentialResolutionError> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(query.block_root, [0x01; 32]);
            assert_eq!(query.proposer_index_hint, Some(7));
            if let Some(error) = self.failure {
                return Err(error);
            }

            Ok(ProposerCredential {
                scheme_id: 9,
                public_key_material: vec![0x55; 32],
            })
        }
    }

    struct CountingDispatcher {
        validator_calls: Cell<usize>,
    }

    impl CountingDispatcher {
        fn new() -> Self {
            Self {
                validator_calls: Cell::new(0),
            }
        }

        fn validator_calls(&self) -> usize {
            self.validator_calls.get()
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
            _scheme_id: u8,
            _request: &SignatureVerificationRequest<'_>,
        ) -> Result<(), CryptoError> {
            self.validator_calls.set(self.validator_calls.get() + 1);
            Ok(())
        }
    }

    struct CountingRevalidator {
        calls: Cell<usize>,
        last_policy: Cell<MultiAuthorizationPolicy>,
    }

    impl CountingRevalidator {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
                last_policy: Cell::new(MultiAuthorizationPolicy::RequireAll),
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }

        fn last_policy(&self) -> MultiAuthorizationPolicy {
            self.last_policy.get()
        }
    }

    impl TransactionRevalidator for CountingRevalidator {
        fn revalidate(
            &self,
            _transaction: &TransactionEnvelope,
            policy: MultiAuthorizationPolicy,
        ) -> Result<(), ValidationError> {
            self.calls.set(self.calls.get() + 1);
            self.last_policy.set(policy);
            Ok(())
        }
    }

    struct CountingWitnessPreparer {
        calls: Cell<usize>,
    }

    impl CountingWitnessPreparer {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }

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
        outcome: BlockExecutionOutcome,
        calls: Cell<usize>,
    }

    impl FixedExecutionEngine {
        fn new(outcome: BlockExecutionOutcome) -> Self {
            Self {
                outcome,
                calls: Cell::new(0),
            }
        }

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
        ) -> Result<BlockExecutionOutcome, shell_execution::ExecutionError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.outcome.clone())
        }
    }

    fn sample_transaction(nonce: u64) -> TransactionEnvelope {
        let payload =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                nonce,
                gas_limit: 21_000 + nonce,
                ..Default::default()
            }));
        let payload_root = payload
            .canonical_root()
            .expect("payload root should exist for the sample");

        TransactionEnvelope {
            payload,
            authorizations: vec![Authorization {
                scheme_id: 1,
                payload_root,
                signature: vec![0xAB; 64],
            }],
        }
    }

    fn sample_import_fixture() -> (StubHeader, StubBody, StubSidecar, BlockExecutionOutcome) {
        let transactions = vec![sample_transaction(1), sample_transaction(2)];
        let header = StubHeader {
            block_root: [0x01; 32],
            witness_bytes: 128,
            transactions_root: [0x02; 32],
            execution_witnesses_root: [0x03; 32],
            state_root: [0x04; 32],
            receipts_root: [0x05; 32],
            proposer_signature: vec![0x06; 96],
            proposer_index_hint: Some(7),
        };
        let body = StubBody {
            root: header.transactions_root,
            transactions,
        };
        let sidecar = StubSidecar {
            block_root: header.block_root,
            committed_root: header.execution_witnesses_root,
        };
        let execution = BlockExecutionOutcome {
            post_state_root: header.state_root,
            receipts_root: header.receipts_root,
            transaction_outcomes: vec![shell_execution::TransactionExecutionOutcome {
                transaction_root: [0xAA; 32],
                post_state_root: header.state_root,
                receipt: ExecutionReceipt {
                    status_code: 1,
                    output: vec![0xBB],
                },
            }],
        };

        (header, body, sidecar, execution)
    }

    #[test]
    fn pipeline_runs_block_stages_in_order() {
        let (header, body, sidecar, execution) = sample_import_fixture();
        let pipeline = BlockImportPipeline::new(BlockImportConfig {
            header_prefilter: HeaderPrefilterConfig {
                max_witness_bytes: Some(256),
            },
            multi_authorization_policy: MultiAuthorizationPolicy::RequireAll,
        });
        let resolver = CountingResolver::new();
        let dispatcher = CountingDispatcher::new();
        let revalidator = CountingRevalidator::new();
        let preparer = CountingWitnessPreparer::new();
        let engine = FixedExecutionEngine::new(execution);

        let outcome = pipeline
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
            .expect("happy-path import should succeed");

        assert_eq!(outcome.block_root, header.block_root);
        assert_eq!(resolver.calls(), 1);
        assert_eq!(dispatcher.validator_calls(), 1);
        assert_eq!(revalidator.calls(), body.transactions.len());
        assert_eq!(
            revalidator.last_policy(),
            MultiAuthorizationPolicy::RequireAll
        );
        assert_eq!(preparer.calls(), 1);
        assert_eq!(engine.calls(), 1);
    }

    #[test]
    fn prefilter_rejects_oversized_witness_bytes_before_signature_work() {
        let (mut header, body, sidecar, execution) = sample_import_fixture();
        header.witness_bytes = 1024;
        let pipeline = BlockImportPipeline::new(BlockImportConfig {
            header_prefilter: HeaderPrefilterConfig {
                max_witness_bytes: Some(512),
            },
            multi_authorization_policy: MultiAuthorizationPolicy::RequireAll,
        });
        let resolver = CountingResolver::new();
        let dispatcher = CountingDispatcher::new();
        let revalidator = CountingRevalidator::new();
        let preparer = CountingWitnessPreparer::new();
        let engine = FixedExecutionEngine::new(execution);

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
            .expect_err("oversized header should fail at B0");

        assert_eq!(
            error,
            ConsensusError::WitnessByteLimitExceeded(WitnessByteLimitExceededError {
                max_bytes: 512,
                actual_bytes: 1024,
            })
        );
        assert_eq!(resolver.calls(), 0);
        assert_eq!(dispatcher.validator_calls(), 0);
        assert_eq!(preparer.calls(), 0);
        assert_eq!(engine.calls(), 0);
    }

    #[test]
    fn body_binding_failure_stops_before_signature_verification() {
        let (header, mut body, sidecar, execution) = sample_import_fixture();
        body.root[0] ^= 0xFF;
        let pipeline = BlockImportPipeline::new(BlockImportConfig::default());
        let resolver = CountingResolver::new();
        let dispatcher = CountingDispatcher::new();
        let revalidator = CountingRevalidator::new();
        let preparer = CountingWitnessPreparer::new();
        let engine = FixedExecutionEngine::new(execution);

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
            .expect_err("body-root mismatch should fail at B2");

        assert_eq!(
            error,
            ConsensusError::HeaderBodyRootMismatch(HeaderBodyRootMismatchError {
                expected: header.transactions_root,
                actual: body.root,
            })
        );
        assert_eq!(resolver.calls(), 0);
        assert_eq!(dispatcher.validator_calls(), 0);
    }

    #[test]
    fn sidecar_binding_failure_stops_before_execution() {
        let (header, body, mut sidecar, execution) = sample_import_fixture();
        sidecar.committed_root[0] ^= 0x01;
        let pipeline = BlockImportPipeline::new(BlockImportConfig::default());
        let resolver = CountingResolver::new();
        let dispatcher = CountingDispatcher::new();
        let revalidator = CountingRevalidator::new();
        let preparer = CountingWitnessPreparer::new();
        let engine = FixedExecutionEngine::new(execution);

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
            .expect_err("sidecar-root mismatch should fail at B4");

        assert_eq!(
            error,
            ConsensusError::SidecarCommitmentMismatch(SidecarCommitmentMismatchError {
                expected: header.execution_witnesses_root,
                actual: sidecar.committed_root,
            })
        );
        assert_eq!(preparer.calls(), 0);
        assert_eq!(engine.calls(), 0);
    }

    #[test]
    fn resolver_failures_propagate_before_dispatch() {
        let (header, body, sidecar, execution) = sample_import_fixture();
        let pipeline = BlockImportPipeline::new(BlockImportConfig::default());
        let resolver = CountingResolver {
            calls: Cell::new(0),
            failure: Some(
                ProposerCredentialResolutionError::InvalidCredentialEncoding(
                    InvalidCredentialEncodingError {
                        scheme_id: 9,
                        context: "validator public key bytes failed scheme decode",
                    },
                ),
            ),
        };
        let dispatcher = CountingDispatcher::new();
        let revalidator = CountingRevalidator::new();
        let preparer = CountingWitnessPreparer::new();
        let engine = FixedExecutionEngine::new(execution);

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
            .expect_err("invalid proposer credentials should fail before validator dispatch");

        assert_eq!(
            error,
            ConsensusError::ProposerCredentialResolution(
                ProposerCredentialResolutionError::InvalidCredentialEncoding(
                    InvalidCredentialEncodingError {
                        scheme_id: 9,
                        context: "validator public key bytes failed scheme decode",
                    },
                ),
            )
        );
        assert_eq!(resolver.calls(), 1);
        assert_eq!(dispatcher.validator_calls(), 0);
        assert_eq!(revalidator.calls(), 0);
        assert_eq!(preparer.calls(), 0);
        assert_eq!(engine.calls(), 0);
    }

    #[test]
    fn consensus_traits_are_object_safe() {
        struct DummyVerifier;

        impl SignatureVerifier for DummyVerifier {
            fn scheme_id(&self) -> u8 {
                0
            }

            fn verify(
                &self,
                _request: &SignatureVerificationRequest<'_>,
            ) -> Result<(), shell_crypto::VerificationFailure> {
                Ok(())
            }
        }

        struct DummyRevalidator;

        impl TransactionRevalidator for DummyRevalidator {
            fn revalidate(
                &self,
                _transaction: &TransactionEnvelope,
                _policy: MultiAuthorizationPolicy,
            ) -> Result<(), ValidationError> {
                Ok(())
            }
        }

        struct DummyPreparer;

        impl WitnessPreparer for DummyPreparer {
            fn prepare_witness(
                &self,
                _header: &dyn ConsensusHeader,
                _sidecar: &dyn ConsensusSidecar,
            ) -> Result<(), StateError> {
                Ok(())
            }
        }

        struct DummyExecutionEngine;

        impl BlockExecutionEngine for DummyExecutionEngine {
            fn execute_block(
                &self,
                _header: &dyn ConsensusHeader,
                _body: &dyn ConsensusBody,
                _sidecar: &dyn ConsensusSidecar,
            ) -> Result<BlockExecutionOutcome, shell_execution::ExecutionError> {
                Err(shell_execution::ExecutionError::Executor("unused"))
            }
        }

        let _: Box<dyn TransactionRevalidator> = Box::new(DummyRevalidator);
        let _: Box<dyn WitnessPreparer> = Box::new(DummyPreparer);
        let _: Box<dyn BlockExecutionEngine> = Box::new(DummyExecutionEngine);
        let _: Box<dyn SignatureVerifier> = Box::new(DummyVerifier);
    }
}
