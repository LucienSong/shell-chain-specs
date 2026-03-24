//! Local `shell-network` adapter implementations for the reference harness.
//!
//! These wrappers stay local/test oriented: they reuse [`LocalReferenceRuntime`]
//! plus fixture-backed reference data, and they do not introduce any transport,
//! RPC, daemon, or operator surface.

use std::collections::BTreeMap;

use shell_consensus::{ConsensusBody, ConsensusError, ConsensusHeader, ConsensusSidecar};
use shell_mempool::{AuthorizationMaterialCountError, ValidationError};
use shell_network::{NetworkConsensusAdapter, NetworkMempoolAdapter, NetworkOrigin};
use shell_primitives::{Root, TransactionEnvelope, ValidationOutcome};

use crate::{
    fixtures::{LocalReferenceScenario, OwnedAuthorizationMaterial},
    runtime::{
        build_admission_transactions_by_payload_root, validate_scenario_shape, LocalReferenceError,
        LocalReferenceRuntime,
    },
};

/// `shell-network` mempool adapter backed by local reference-harness fixtures.
pub struct LocalReferenceNetworkMempoolAdapter<'runtime> {
    runtime: &'runtime LocalReferenceRuntime<'runtime>,
    authorization_materials: BTreeMap<Root, Vec<OwnedAuthorizationMaterial>>,
}

impl<'runtime> LocalReferenceNetworkMempoolAdapter<'runtime> {
    pub fn try_new(
        runtime: &'runtime LocalReferenceRuntime<'runtime>,
        scenario: &LocalReferenceScenario,
    ) -> Result<Self, LocalReferenceError> {
        validate_scenario_shape(scenario)?;
        let mut authorization_materials = BTreeMap::new();
        for (transaction, materials) in scenario
            .admission_transactions
            .iter()
            .zip(scenario.transaction_authorization_materials.iter())
        {
            let payload_root = transaction.payload_root()?;
            if authorization_materials
                .insert(payload_root, materials.clone())
                .is_some()
            {
                return Err(LocalReferenceError::DuplicateAdmissionPayloadRoot(
                    payload_root,
                ));
            }
        }

        Ok(Self {
            runtime,
            authorization_materials,
        })
    }
}

impl NetworkMempoolAdapter for LocalReferenceNetworkMempoolAdapter<'_> {
    fn validate_gossip_transaction(
        &self,
        _origin: &NetworkOrigin,
        envelope: &TransactionEnvelope,
    ) -> Result<ValidationOutcome, ValidationError> {
        let payload_root = envelope.payload_root()?;
        let materials = self.authorization_materials.get(&payload_root).ok_or(
            ValidationError::AuthorizationMaterialCount(AuthorizationMaterialCountError {
                expected: envelope.authorizations.len(),
                actual: 0,
            }),
        )?;

        match self.runtime.validate_transaction(envelope, materials) {
            Ok(_) => Ok(ValidationOutcome::Accept),
            Err(error) => match error.network_validation_outcome() {
                Some(outcome) => Ok(outcome),
                None => Err(error),
            },
        }
    }
}

/// `shell-network` consensus adapter backed by local reference-harness fixtures.
pub struct LocalReferenceNetworkConsensusAdapter<'runtime, 'scenario> {
    runtime: &'runtime LocalReferenceRuntime<'runtime>,
    scenario: &'scenario LocalReferenceScenario,
    admission_transactions: BTreeMap<Root, (TransactionEnvelope, Vec<OwnedAuthorizationMaterial>)>,
}

impl<'runtime, 'scenario> LocalReferenceNetworkConsensusAdapter<'runtime, 'scenario> {
    pub fn try_new(
        runtime: &'runtime LocalReferenceRuntime<'runtime>,
        scenario: &'scenario LocalReferenceScenario,
    ) -> Result<Self, LocalReferenceError> {
        validate_scenario_shape(scenario)?;
        let admission_transactions = build_admission_transactions_by_payload_root(
            &scenario.admission_transactions,
            &scenario.transaction_authorization_materials,
        )?;

        Ok(Self {
            runtime,
            scenario,
            admission_transactions,
        })
    }
}

impl NetworkConsensusAdapter for LocalReferenceNetworkConsensusAdapter<'_, '_> {
    fn validate_gossip_block(
        &self,
        _origin: &NetworkOrigin,
        header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        sidecar: &dyn ConsensusSidecar,
    ) -> Result<ValidationOutcome, ConsensusError> {
        match self.runtime.validate_block_against_reference(
            self.scenario,
            header,
            body,
            sidecar,
            &self.admission_transactions,
        ) {
            Ok(_) => Ok(ValidationOutcome::Accept),
            Err(error) => match error.network_validation_outcome() {
                Some(outcome) => Ok(outcome),
                None => Err(error),
            },
        }
    }
}
