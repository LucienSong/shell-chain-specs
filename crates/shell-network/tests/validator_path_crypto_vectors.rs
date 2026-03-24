use std::boxed::Box;

use shell_consensus::ConsensusError;
use shell_crypto::{
    CryptoError, SignatureLimitKind, SignatureSizeExceededError, UnsupportedSchemeError,
    VerificationFailure, VerificationPath,
};
use shell_fixtures::{
    crypto_fixture_paths, load_fixture, CryptoExpectedError, CryptoVector, VerificationPathInput,
};
use shell_network::{
    peer_action_for_consensus_error, NetworkOrigin, PeerAction, PeerActionHint, PeerId,
    ReputationDelta,
};

fn peer_origin() -> NetworkOrigin {
    NetworkOrigin::Gossip {
        peer_id: PeerId::from([7; 32]),
    }
}

#[test]
fn validator_path_negative_crypto_vectors_keep_network_classification_stable() {
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

        let error = ConsensusError::Crypto(expected_crypto_error(
            &fixture,
            fixture.expected_error.as_ref().unwrap(),
        ));
        let action = peer_action_for_consensus_error(&peer_origin(), &error);

        let expected_action = match fixture
            .expected_error
            .as_ref()
            .and_then(|error| error.limit_kind.as_deref())
        {
            Some("local_transport_guard") => PeerAction::AdjustReputation(ReputationDelta::new(
                -5,
                PeerActionHint::OversizedObject,
            )),
            _ => PeerAction::Disconnect {
                hint: PeerActionHint::InvalidSignature,
            },
        };

        assert_eq!(
            action, expected_action,
            "{} network mapping drifted",
            fixture.id
        );
    }

    assert!(
        seen > 0,
        "expected validator-path reject fixtures under vectors/crypto"
    );
}

fn expected_crypto_error(fixture: &CryptoVector, expected: &CryptoExpectedError) -> CryptoError {
    match expected.kind.as_str() {
        "UnsupportedScheme" => CryptoError::UnsupportedScheme(UnsupportedSchemeError {
            scheme_id: expected
                .scheme_id
                .unwrap_or_else(|| panic!("{} missing scheme_id", fixture.id)),
        }),
        "SignatureSizeExceeded" => CryptoError::SignatureSizeExceeded(SignatureSizeExceededError {
            max_size: expected
                .max_size
                .unwrap_or_else(|| panic!("{} missing max_size", fixture.id)),
            actual_size: expected
                .actual_size
                .unwrap_or_else(|| panic!("{} missing actual_size", fixture.id)),
            path: parse_verification_path(
                expected
                    .path
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} missing path", fixture.id)),
            ),
            kind: parse_signature_limit_kind(
                expected
                    .limit_kind
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} missing limit_kind", fixture.id)),
            ),
        }),
        "VerificationFailed" => CryptoError::VerificationFailed(VerificationFailure {
            scheme_id: expected
                .scheme_id
                .unwrap_or_else(|| panic!("{} missing scheme_id", fixture.id)),
            context: verification_context(
                fixture,
                expected
                    .context
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} missing context", fixture.id)),
            ),
        }),
        other => panic!("{} has unsupported error kind {other:?}", fixture.id),
    }
}

fn verification_context(_fixture: &CryptoVector, value: &str) -> &'static str {
    Box::leak(value.to_owned().into_boxed_str())
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
