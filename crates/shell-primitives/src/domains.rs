use crate::errors::DomainError;
use crate::types::{Bytes4, Root, SigningData};

pub const DOMAIN_TYPE_WIDTH: usize = 4;
pub const DOMAIN_TX_SHELL: Bytes4 = [0x01, 0x00, 0x00, 0x00];
pub const DOMAIN_VALIDATOR_MESSAGE: Bytes4 = [0x02, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSelector {
    TransactionAuthorization,
    ValidatorMessage,
}

impl DomainSelector {
    pub const fn label(self) -> &'static str {
        match self {
            Self::TransactionAuthorization => "transaction-authorization",
            Self::ValidatorMessage => "validator-message",
        }
    }

    pub fn domain_type(self) -> Result<Bytes4, DomainError> {
        Ok(match self {
            Self::TransactionAuthorization => DOMAIN_TX_SHELL,
            Self::ValidatorMessage => DOMAIN_VALIDATOR_MESSAGE,
        })
    }
}

pub fn build_signing_data(
    object_root: Root,
    domain: DomainSelector,
) -> Result<SigningData, DomainError> {
    Ok(SigningData {
        object_root,
        domain_type: domain.domain_type()?,
    })
}
