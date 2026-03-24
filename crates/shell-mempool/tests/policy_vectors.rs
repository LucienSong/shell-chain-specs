use core::cell::Cell;
use std::boxed::Box;

use shell_crypto::{
    CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
    UnsupportedSchemeError,
};
use shell_fixtures::{
    load_fixture, mempool_policy_fixture_paths, parse_address, parse_hex, ExpectedError,
    MempoolInput, MempoolPolicyVector, PayloadRootMode,
};
use shell_mempool::{
    AdmissionPipeline, AdmissionPolicy, AdmissionStateView, AuthorizationMaterial, FeeLane,
    FeeSchedule, MultiAuthorizationPolicy, NoncePolicy, TransactionAuthorizationDomain,
    ValidationError,
};
use shell_primitives::{
    Authorization, BasicFeesPerGas, BasicTransactionPayload, GasPrice, TransactionEnvelope,
    TransactionPayload, TransactionPayloadSsz, U256,
};

struct CountingDispatcher {
    verify_calls: Cell<usize>,
}

impl CountingDispatcher {
    fn new() -> Self {
        Self {
            verify_calls: Cell::new(0),
        }
    }

    fn verify_calls(&self) -> usize {
        self.verify_calls.get()
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
        self.verify_calls.set(self.verify_calls.get() + 1);
        Err(CryptoError::UnsupportedScheme(UnsupportedSchemeError {
            scheme_id,
        }))
    }

    fn verify_validator_message(
        &self,
        scheme_id: u8,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedScheme(UnsupportedSchemeError {
            scheme_id,
        }))
    }
}

struct FixedNonceView {
    nonce: u64,
}

impl AdmissionStateView for FixedNonceView {
    fn observed_nonce(&self, _envelope: &TransactionEnvelope) -> Option<u64> {
        Some(self.nonce)
    }
}

#[test]
fn fixture_driven_vectors_cover_mempool_fee_and_nonce_policy() {
    let mut paths = mempool_policy_fixture_paths();
    paths.sort();

    let mut seen = 0;
    for path in paths {
        let fixture: MempoolPolicyVector = load_fixture(&path);
        seen += 1;

        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "mempool-policy",
            "{} must declare category 'mempool-policy'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-mempool",
            "{} must be owned by shell-mempool",
            fixture.id
        );
        assert!(
            !fixture.rule.trim().is_empty(),
            "{} must declare the policy rule it covers",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "{} must describe the policy invariant it covers",
            fixture.id
        );

        assert_policy_rejects_before_dispatch(&fixture);
    }

    assert!(
        seen > 0,
        "expected at least one fixture-driven mempool policy vector"
    );
}

fn assert_policy_rejects_before_dispatch(fixture: &MempoolPolicyVector) {
    let dispatcher = CountingDispatcher::new();
    let pipeline = AdmissionPipeline::new(&dispatcher, build_policy(&fixture.input));
    let envelope = build_envelope(&fixture.input);
    let materials = build_authorization_materials(&fixture.input);
    let nonce_view = fixture
        .input
        .observed_nonce
        .map(|nonce| FixedNonceView { nonce });

    let error = pipeline
        .admit_and_verify(
            &envelope,
            nonce_view
                .as_ref()
                .map(|view| view as &dyn AdmissionStateView),
            &materials,
        )
        .expect_err(&format!(
            "{} should reject under local mempool policy before T3",
            fixture.id
        ));

    assert_eq!(
        fixture.expected_outcome, "policy_reject",
        "{} must remain a soft local-policy rejection",
        fixture.id
    );
    assert_expected_error(error, &fixture.expected_error, fixture);
    if let Some(expected_calls) = fixture.expected_effects.transaction_signature_verifications {
        assert_eq!(
            dispatcher.verify_calls(),
            expected_calls,
            "{} signature verification count mismatch",
            fixture.id
        );
    }
}

fn assert_expected_error(
    error: ValidationError,
    expected: &ExpectedError,
    fixture: &MempoolPolicyVector,
) {
    match expected.kind.as_str() {
        "FeeFloor" => {
            let ValidationError::FeeFloor(actual) = error else {
                panic!("{} expected FeeFloor, got {:?}", fixture.id, error);
            };
            if let Some(expected_lane) = expected.lane.as_deref() {
                let actual_lane = match actual.lane {
                    FeeLane::Payload => "payload",
                    FeeLane::Witness => "witness",
                };
                assert_eq!(
                    actual_lane, expected_lane,
                    "{} fee lane mismatch",
                    fixture.id
                );
            }
        }
        "NoncePolicy" => {
            let ValidationError::NoncePolicy(actual) = error else {
                panic!("{} expected NoncePolicy, got {:?}", fixture.id, error);
            };
            if let Some(expected_context) = expected.context.as_deref() {
                assert_eq!(
                    actual.context, expected_context,
                    "{} nonce policy context mismatch",
                    fixture.id
                );
            }
        }
        kind => panic!(
            "{} has unsupported expected_error kind {:?}",
            fixture.id, kind
        ),
    }
}

fn build_policy(input: &MempoolInput) -> AdmissionPolicy {
    AdmissionPolicy {
        fee_schedule: FeeSchedule {
            payload_lane_base_fee: GasPrice(U256(le_u256(input.policy.payload_lane_base_fee))),
            witness_lane_base_fee: GasPrice(U256(le_u256(input.policy.witness_lane_base_fee))),
        },
        nonce_policy: NoncePolicy {
            max_future_nonce_gap: input.policy.max_future_nonce_gap,
        },
        authorization_domain: TransactionAuthorizationDomain::Canonical,
        multi_authorization_policy: MultiAuthorizationPolicy::RequireAll,
    }
}

fn build_envelope(input: &MempoolInput) -> TransactionEnvelope {
    let payload = TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
        nonce: input.payload.nonce,
        gas_limit: input.payload.gas_limit,
        fees: BasicFeesPerGas {
            regular: GasPrice(U256(le_u256(input.payload.regular_fee))),
            max_priority_fee_per_gas: GasPrice(U256(le_u256(
                input.payload.max_priority_fee_per_gas,
            ))),
            max_witness_priority_fee: GasPrice(U256(le_u256(
                input.payload.max_witness_priority_fee,
            ))),
        },
        to: parse_address(&input.payload.to),
        ..Default::default()
    }));
    let canonical_payload_root = payload
        .hash_tree_root()
        .expect("mempool policy fixture payload root must exist");
    let authorizations = input
        .authorizations
        .iter()
        .map(|authorization| Authorization {
            scheme_id: authorization.scheme_id,
            payload_root: match authorization.payload_root_mode {
                PayloadRootMode::Canonical => canonical_payload_root,
                PayloadRootMode::FlipFirstByte => authorization
                    .payload_root_mode
                    .apply(canonical_payload_root),
            },
            signature: parse_hex(&authorization.signature_hex),
        })
        .collect();

    TransactionEnvelope {
        payload,
        authorizations,
    }
}

fn build_authorization_materials(input: &MempoolInput) -> Vec<AuthorizationMaterial<'static>> {
    input
        .authorization_materials
        .iter()
        .map(|material| AuthorizationMaterial {
            public_key_material: Box::leak(parse_hex(&material.public_key_hex).into_boxed_slice()),
        })
        .collect()
}

fn le_u256(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}
