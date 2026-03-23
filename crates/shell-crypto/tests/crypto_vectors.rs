use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use shell_crypto::{
    CryptoError, DispatcherConfig, Ed25519Verifier, SignatureDispatcher,
    SignatureSizeExceededError, SignatureVerificationRequest, UnsupportedSchemeError,
    VerificationFailure, VerificationPath, VerifierRegistry, SCHEME_ID_ED25519,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoVector {
    id: String,
    category: String,
    rule: String,
    description: String,
    input: CryptoInput,
    expected_outcome: String,
    #[serde(default)]
    expected_error: Option<CryptoExpectedError>,
    owned_by: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoInput {
    scheme_id: u8,
    public_key_hex: String,
    signing_root_hex: String,
    signature_hex: String,
    verification_path: VerificationPathInput,
    #[serde(default)]
    dispatcher_config: Option<DispatcherConfigInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerificationPathInput {
    TransactionAuthorization,
    ValidatorMessage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherConfigInput {
    #[serde(default)]
    user_path_max_signature_size: Option<usize>,
    #[serde(default)]
    validator_path_max_signature_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoExpectedError {
    kind: String,
    #[serde(default)]
    scheme_id: Option<u8>,
    #[serde(default)]
    max_size: Option<usize>,
    #[serde(default)]
    actual_size: Option<usize>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

#[test]
fn crypto_vectors_match_the_dispatch_contract() {
    let mut paths = fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one crypto fixture under vectors/crypto"
    );

    for path in paths {
        let fixture = load_fixture(&path);

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "crypto",
            "{} must declare category 'crypto'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-crypto",
            "{} must be owned by shell-crypto",
            fixture.id
        );
        assert!(
            !fixture.rule.trim().is_empty(),
            "{} must declare the crypto rule it covers",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "{} must document the invariant it covers",
            fixture.id
        );
        if let Some(notes) = &fixture.notes {
            assert!(
                !notes.trim().is_empty(),
                "{} notes field must not be blank when present",
                fixture.id
            );
        }

        match fixture.expected_outcome.as_str() {
            "accept" => assert_accept(&fixture),
            "reject" => assert_reject(&fixture),
            other => panic!("unsupported expected_outcome {:?} in {}", other, fixture.id),
        }
    }
}

fn assert_accept(fixture: &CryptoVector) {
    dispatch(fixture).unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
}

fn assert_reject(fixture: &CryptoVector) {
    let expected = fixture
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));
    let err = dispatch(fixture).expect_err(&format!("{} should reject but accepted", fixture.id));
    assert_crypto_error(fixture, expected, err);
}

fn dispatch(fixture: &CryptoVector) -> Result<(), CryptoError> {
    let mut registry = registry_from_fixture(fixture);
    registry.register_verifier(Box::new(Ed25519Verifier::new()));

    let public_key = parse_hex(&fixture.input.public_key_hex);
    let signing_root = parse_root(&fixture.input.signing_root_hex);
    let signature = parse_hex(&fixture.input.signature_hex);
    let request = SignatureVerificationRequest {
        public_key_material: &public_key,
        signing_root,
        signature: &signature,
    };

    match fixture.input.verification_path.verification_path() {
        VerificationPath::TransactionAuthorization => {
            registry.verify_transaction_authorization(fixture.input.scheme_id, &request)
        }
        VerificationPath::ValidatorMessage => {
            registry.verify_validator_message(fixture.input.scheme_id, &request)
        }
    }
}

fn registry_from_fixture(fixture: &CryptoVector) -> VerifierRegistry {
    let Some(config) = &fixture.input.dispatcher_config else {
        return VerifierRegistry::default();
    };

    VerifierRegistry::with_config(DispatcherConfig {
        user_path_max_signature_size: config
            .user_path_max_signature_size
            .unwrap_or(shell_crypto::DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE),
        validator_path_max_signature_size: config.validator_path_max_signature_size,
    })
}

fn assert_crypto_error(fixture: &CryptoVector, expected: &CryptoExpectedError, err: CryptoError) {
    match (&*expected.kind, err) {
        ("UnsupportedScheme", CryptoError::UnsupportedScheme(actual)) => {
            assert_unsupported_scheme(fixture, expected, actual);
        }
        ("SignatureSizeExceeded", CryptoError::SignatureSizeExceeded(actual)) => {
            assert_signature_size_exceeded(fixture, expected, actual);
        }
        ("VerificationFailed", CryptoError::VerificationFailed(actual)) => {
            assert_verification_failed(fixture, expected, actual);
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

fn assert_unsupported_scheme(
    fixture: &CryptoVector,
    expected: &CryptoExpectedError,
    actual: UnsupportedSchemeError,
) {
    if let Some(expected_scheme_id) = expected.scheme_id {
        assert_eq!(
            actual.scheme_id, expected_scheme_id,
            "{} scheme_id mismatch",
            fixture.id
        );
    }
}

fn assert_signature_size_exceeded(
    fixture: &CryptoVector,
    expected: &CryptoExpectedError,
    actual: SignatureSizeExceededError,
) {
    if let Some(expected_max_size) = expected.max_size {
        assert_eq!(
            actual.max_size, expected_max_size,
            "{} max_size mismatch",
            fixture.id
        );
    }
    if let Some(expected_actual_size) = expected.actual_size {
        assert_eq!(
            actual.actual_size, expected_actual_size,
            "{} actual_size mismatch",
            fixture.id
        );
    }
    if let Some(expected_path) = &expected.path {
        assert_eq!(
            actual.path,
            parse_verification_path(expected_path),
            "{} path mismatch",
            fixture.id
        );
    }
}

fn assert_verification_failed(
    fixture: &CryptoVector,
    expected: &CryptoExpectedError,
    actual: VerificationFailure,
) {
    if let Some(expected_scheme_id) = expected.scheme_id {
        assert_eq!(
            actual.scheme_id, expected_scheme_id,
            "{} scheme_id mismatch",
            fixture.id
        );
    }
    if let Some(expected_context) = &expected.context {
        assert_eq!(
            actual.context, expected_context,
            "{} context mismatch",
            fixture.id
        );
    }
}

fn fixture_paths() -> Vec<PathBuf> {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/crypto");
    fs::read_dir(&vectors_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", vectors_dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect()
}

fn load_fixture(path: &Path) -> CryptoVector {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn parse_root(value: &str) -> [u8; 32] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte root, got {len} bytes in {value}"))
}

fn parse_hex(value: &str) -> Vec<u8> {
    let hex = value
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("hex values must use a 0x prefix: {value}"));
    assert!(
        hex.len().is_multiple_of(2),
        "hex values must contain an even number of digits: {value}"
    );

    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex byte at offset {index} in {value}"))
        })
        .collect()
}

fn parse_verification_path(value: &str) -> VerificationPath {
    match value {
        "transaction_authorization" => VerificationPath::TransactionAuthorization,
        "validator_message" => VerificationPath::ValidatorMessage,
        other => panic!("unsupported verification path {other:?}"),
    }
}

impl VerificationPathInput {
    fn verification_path(&self) -> VerificationPath {
        match self {
            Self::TransactionAuthorization => VerificationPath::TransactionAuthorization,
            Self::ValidatorMessage => VerificationPath::ValidatorMessage,
        }
    }
}

#[test]
fn ed25519_scheme_id_stays_stable_for_crypto_vectors() {
    assert_eq!(SCHEME_ID_ED25519, 0);
}
