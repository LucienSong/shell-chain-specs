use crate::traits::VerificationPath;
use shell_primitives::ValidationOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureLimitKind {
    RepositoryRule,
    LocalTransportGuard,
    Scheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedSchemeError {
    pub scheme_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureSizeExceededError {
    pub max_size: usize,
    pub actual_size: usize,
    pub path: VerificationPath,
    pub kind: SignatureLimitKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationFailure {
    pub scheme_id: u8,
    pub context: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    UnsupportedScheme(UnsupportedSchemeError),
    SignatureSizeExceeded(SignatureSizeExceededError),
    VerificationFailed(VerificationFailure),
}

impl CryptoError {
    pub const fn network_validation_outcome(&self) -> Option<ValidationOutcome> {
        match self {
            Self::UnsupportedScheme(_) | Self::VerificationFailed(_) => {
                Some(ValidationOutcome::Reject)
            }
            Self::SignatureSizeExceeded(error) => {
                if matches!(error.path, VerificationPath::ValidatorMessage)
                    && matches!(error.kind, SignatureLimitKind::LocalTransportGuard)
                {
                    Some(ValidationOutcome::PolicyReject)
                } else {
                    Some(ValidationOutcome::Reject)
                }
            }
        }
    }
}
