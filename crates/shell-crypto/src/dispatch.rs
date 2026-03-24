use alloc::{boxed::Box, vec::Vec};

use crate::errors::{
    CryptoError, SignatureLimitKind, SignatureSizeExceededError, UnsupportedSchemeError,
};
use crate::schemes::DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE;
use crate::traits::{
    SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier, VerificationPath,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatcherConfig {
    pub user_path_max_signature_size: usize,
    // This remains a configurable local transport guard until the validator path
    // gets a frozen consensus-invalidating size rule.
    pub validator_path_max_signature_size: Option<usize>,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            user_path_max_signature_size: DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE,
            validator_path_max_signature_size: None,
        }
    }
}

#[derive(Default)]
pub struct VerifierRegistry {
    config: DispatcherConfig,
    verifiers: Vec<Box<dyn SignatureVerifier>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: DispatcherConfig) -> Self {
        Self {
            config,
            verifiers: Vec::new(),
        }
    }

    pub fn config(&self) -> DispatcherConfig {
        self.config
    }

    fn verify_for_path(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
        path: VerificationPath,
    ) -> Result<(), CryptoError> {
        let verifier = self
            .verifier(scheme_id)
            .ok_or(CryptoError::UnsupportedScheme(UnsupportedSchemeError {
                scheme_id,
            }))?;

        if let Some(limit) = self.max_signature_size(verifier, path) {
            if request.signature.len() > limit.max_size {
                return Err(CryptoError::SignatureSizeExceeded(
                    SignatureSizeExceededError {
                        max_size: limit.max_size,
                        actual_size: request.signature.len(),
                        path,
                        kind: limit.kind,
                    },
                ));
            }
        }

        verifier
            .verify(request)
            .map_err(CryptoError::VerificationFailed)
    }

    fn max_signature_size(
        &self,
        verifier: &dyn SignatureVerifier,
        path: VerificationPath,
    ) -> Option<ResolvedSignatureLimit> {
        let mut chosen = match path {
            VerificationPath::TransactionAuthorization => Some(ResolvedSignatureLimit {
                max_size: self.config.user_path_max_signature_size,
                kind: SignatureLimitKind::RepositoryRule,
            }),
            VerificationPath::ValidatorMessage => self
                .config
                .validator_path_max_signature_size
                .map(|max_size| ResolvedSignatureLimit {
                    max_size,
                    kind: SignatureLimitKind::LocalTransportGuard,
                }),
        };

        if let Some(max_size) = verifier.max_signature_size(path) {
            let verifier_limit = ResolvedSignatureLimit {
                max_size,
                kind: SignatureLimitKind::Scheme,
            };
            if chosen
                .map(|current| verifier_limit.max_size < current.max_size)
                .unwrap_or(true)
            {
                chosen = Some(verifier_limit);
            }
        }

        chosen
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedSignatureLimit {
    max_size: usize,
    kind: SignatureLimitKind,
}

impl SignatureDispatcher for VerifierRegistry {
    fn register_verifier(
        &mut self,
        verifier: Box<dyn SignatureVerifier>,
    ) -> Option<Box<dyn SignatureVerifier>> {
        if let Some(existing) = self
            .verifiers
            .iter_mut()
            .find(|entry| entry.scheme_id() == verifier.scheme_id())
        {
            return Some(core::mem::replace(existing, verifier));
        }

        self.verifiers.push(verifier);
        None
    }

    fn verifier(&self, scheme_id: u8) -> Option<&dyn SignatureVerifier> {
        self.verifiers
            .iter()
            .find(|verifier| verifier.scheme_id() == scheme_id)
            .map(Box::as_ref)
    }

    fn verify_transaction_authorization(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.verify_for_path(
            scheme_id,
            request,
            VerificationPath::TransactionAuthorization,
        )
    }

    fn verify_validator_message(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), CryptoError> {
        self.verify_for_path(scheme_id, request, VerificationPath::ValidatorMessage)
    }
}
