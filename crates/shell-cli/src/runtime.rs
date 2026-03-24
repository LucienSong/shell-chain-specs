use std::collections::BTreeMap;

use shell_consensus::{
    BlockExecutionEngine, BlockImportConfig, BlockImportOutcome, BlockImportPipeline,
    BlockImportServices, ConsensusBody, ConsensusError, ConsensusHeader, ConsensusSidecar,
    TransactionRevalidator, WitnessPreparer,
};
use shell_crypto::SignatureDispatcher;
use shell_execution::{
    BlockExecutionOutcome, ExecutionError, PlannedTransaction, PlannedTransactionExecutor,
    StatelessBlockExecutor,
};
use shell_mempool::{
    AdmissionPipeline, AdmissionPolicy, AdmissionStateView, AuthorizationMaterial,
    AuthorizationMaterialCountError, AuthorizationValidated, ValidationError,
};
use shell_primitives::{
    PrimitiveError, ProposerCredentialResolver, Root, StateKey, TransactionEnvelope,
};
use shell_state::{
    InMemoryAccumulator, ReferenceStateApplier, RootContinuityError, StateAccumulator, StateError,
    StatePatch, WitnessVerifier,
};

use crate::fixtures::{LocalReferenceScenario, OwnedAuthorizationMaterial};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioShapeError {
    pub expected: usize,
    pub actual: usize,
    pub context: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalReferenceError {
    ScenarioShape(ScenarioShapeError),
    DuplicateAdmissionPayloadRoot(Root),
    Primitive(PrimitiveError),
    Admission(ValidationError),
    Consensus(ConsensusError),
}

impl From<PrimitiveError> for LocalReferenceError {
    fn from(value: PrimitiveError) -> Self {
        Self::Primitive(value)
    }
}

impl From<ValidationError> for LocalReferenceError {
    fn from(value: ValidationError) -> Self {
        Self::Admission(value)
    }
}

impl From<ConsensusError> for LocalReferenceError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalReferenceFlowOutcome {
    pub admissions: Vec<AuthorizationValidated>,
    pub import_outcome: BlockImportOutcome,
}

pub struct LocalReferenceRuntime<'a> {
    dispatcher: &'a dyn SignatureDispatcher,
    resolver: &'a dyn ProposerCredentialResolver,
    admission_policy: AdmissionPolicy,
    import_config: BlockImportConfig,
    admission_state_view: Option<&'a dyn AdmissionStateView>,
}

impl<'a> LocalReferenceRuntime<'a> {
    pub fn new(
        dispatcher: &'a dyn SignatureDispatcher,
        resolver: &'a dyn ProposerCredentialResolver,
        admission_policy: AdmissionPolicy,
        import_config: BlockImportConfig,
    ) -> Self {
        Self {
            dispatcher,
            resolver,
            admission_policy,
            import_config,
            admission_state_view: None,
        }
    }

    pub fn with_admission_state_view(mut self, state_view: &'a dyn AdmissionStateView) -> Self {
        self.admission_state_view = Some(state_view);
        self
    }

    pub fn run(
        &self,
        scenario: &LocalReferenceScenario,
    ) -> Result<LocalReferenceFlowOutcome, LocalReferenceError> {
        validate_scenario_shape(scenario)?;
        let admissions = self.admit_transactions(scenario)?;
        let admission_transactions = build_admission_transactions_by_payload_root(
            &scenario.admission_transactions,
            &scenario.transaction_authorization_materials,
        )?;
        let import_outcome = self.validate_block_against_reference(
            scenario,
            &scenario.block.header,
            &scenario.block.body,
            &scenario.block.sidecar,
            &admission_transactions,
        )?;

        Ok(LocalReferenceFlowOutcome {
            admissions,
            import_outcome,
        })
    }

    fn admit_transactions(
        &self,
        scenario: &LocalReferenceScenario,
    ) -> Result<Vec<AuthorizationValidated>, LocalReferenceError> {
        scenario
            .admission_transactions
            .iter()
            .zip(scenario.transaction_authorization_materials.iter())
            .map(|(transaction, materials)| {
                self.validate_transaction(transaction, materials)
                    .map_err(LocalReferenceError::from)
            })
            .collect()
    }

    pub(crate) fn validate_transaction(
        &self,
        envelope: &TransactionEnvelope,
        authorization_materials: &[OwnedAuthorizationMaterial],
    ) -> Result<AuthorizationValidated, ValidationError> {
        let borrowed = borrow_authorization_materials(authorization_materials);
        AdmissionPipeline::new(self.dispatcher, self.admission_policy).admit_and_verify(
            envelope,
            self.admission_state_view,
            &borrowed,
        )
    }

    pub(crate) fn validate_block_against_reference(
        &self,
        scenario: &LocalReferenceScenario,
        header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        sidecar: &dyn ConsensusSidecar,
        admission_transactions: &BTreeMap<
            Root,
            (TransactionEnvelope, Vec<OwnedAuthorizationMaterial>),
        >,
    ) -> Result<BlockImportOutcome, ConsensusError> {
        let revalidator = ReferenceTransactionRevalidator {
            dispatcher: self.dispatcher,
            policy: self.admission_policy,
            state_view: self.admission_state_view,
            admission_transactions,
        };
        let preparer = ReferenceWitnessScenarioPreparer {
            pre_state_root: scenario.pre_state_root,
            materialized_state: &scenario.materialized_state,
            witnesses: &scenario.block.sidecar.witnesses,
        };
        let execution_engine = ReferenceExecutionEngine {
            pre_state_root: scenario.pre_state_root,
            materialized_state: &scenario.materialized_state,
            planned_transactions: &scenario.planned_transactions,
        };

        BlockImportPipeline::new(self.import_config).import_block(
            header,
            body,
            sidecar,
            BlockImportServices {
                resolver: self.resolver,
                dispatcher: self.dispatcher,
                revalidator: &revalidator,
                preparer: &preparer,
                execution_engine: &execution_engine,
            },
        )
    }
}

pub(crate) fn validate_scenario_shape(
    scenario: &LocalReferenceScenario,
) -> Result<(), LocalReferenceError> {
    let transaction_count = scenario.block.body.transactions.len();
    let admission_count = scenario.admission_transactions.len();
    if admission_count != transaction_count {
        return Err(LocalReferenceError::ScenarioShape(ScenarioShapeError {
            expected: transaction_count,
            actual: admission_count,
            context: "admission transactions must align one-to-one with block body transactions",
        }));
    }

    let planned_count = scenario.planned_transactions.len();
    if planned_count != transaction_count {
        return Err(LocalReferenceError::ScenarioShape(ScenarioShapeError {
            expected: transaction_count,
            actual: planned_count,
            context: "planned transactions must align one-to-one with block body transactions",
        }));
    }

    let materials_count = scenario.transaction_authorization_materials.len();
    if materials_count != transaction_count {
        return Err(LocalReferenceError::ScenarioShape(ScenarioShapeError {
            expected: transaction_count,
            actual: materials_count,
            context:
                "authorization material entries must align one-to-one with block body transactions",
        }));
    }

    Ok(())
}

pub(crate) fn build_admission_transactions_by_payload_root(
    transactions: &[TransactionEnvelope],
    authorization_materials: &[Vec<OwnedAuthorizationMaterial>],
) -> Result<
    BTreeMap<Root, (TransactionEnvelope, Vec<OwnedAuthorizationMaterial>)>,
    LocalReferenceError,
> {
    let mut by_root = BTreeMap::new();
    for (transaction, materials) in transactions.iter().zip(authorization_materials.iter()) {
        let payload_root = transaction.payload_root()?;
        if by_root
            .insert(payload_root, (transaction.clone(), materials.clone()))
            .is_some()
        {
            return Err(LocalReferenceError::DuplicateAdmissionPayloadRoot(
                payload_root,
            ));
        }
    }

    Ok(by_root)
}

fn borrow_authorization_materials(
    materials: &[OwnedAuthorizationMaterial],
) -> Vec<AuthorizationMaterial<'_>> {
    materials
        .iter()
        .map(OwnedAuthorizationMaterial::as_borrowed)
        .collect()
}

struct ReferenceTransactionRevalidator<'a> {
    dispatcher: &'a dyn SignatureDispatcher,
    policy: AdmissionPolicy,
    state_view: Option<&'a dyn AdmissionStateView>,
    admission_transactions:
        &'a BTreeMap<Root, (TransactionEnvelope, Vec<OwnedAuthorizationMaterial>)>,
}

impl TransactionRevalidator for ReferenceTransactionRevalidator<'_> {
    fn revalidate(
        &self,
        transaction: &shell_primitives::TransactionEnvelope,
        _multi_authorization_policy: shell_mempool::MultiAuthorizationPolicy,
    ) -> Result<(), ValidationError> {
        let payload_root = transaction.payload_root()?;
        let (admission_transaction, materials) =
            self.admission_transactions.get(&payload_root).ok_or(
                ValidationError::AuthorizationMaterialCount(AuthorizationMaterialCountError {
                    expected: 1,
                    actual: 0,
                }),
            )?;
        let borrowed = borrow_authorization_materials(materials);
        AdmissionPipeline::new(self.dispatcher, self.policy)
            .admit_and_verify(admission_transaction, self.state_view, &borrowed)
            .map(|_| ())
    }
}

struct ReferenceWitnessScenarioPreparer<'a> {
    pre_state_root: Root,
    materialized_state: &'a [(StateKey, Vec<u8>)],
    witnesses: &'a [shell_primitives::StateWitness],
}

impl WitnessPreparer for ReferenceWitnessScenarioPreparer<'_> {
    fn prepare_witness(
        &self,
        header: &dyn ConsensusHeader,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<(), StateError> {
        if shell_fixtures::compute_execution_witnesses_root(self.witnesses)
            != header.execution_witnesses_root()
        {
            return Err(StateError::WitnessVerificationFailed(
                "reference witness set does not match the committed execution_witnesses_root",
            ));
        }

        let accumulator = materialize_accumulator(self.materialized_state)?;
        if accumulator.state_root() != self.pre_state_root {
            return Err(StateError::RootContinuityMismatch(RootContinuityError {
                expected: self.pre_state_root,
                actual: accumulator.state_root(),
            }));
        }

        accumulator.verify_witnesses(self.witnesses, &self.pre_state_root)
    }
}

struct ReferenceExecutionEngine<'a> {
    pre_state_root: Root,
    materialized_state: &'a [(StateKey, Vec<u8>)],
    planned_transactions: &'a [PlannedTransaction],
}

impl BlockExecutionEngine for ReferenceExecutionEngine<'_> {
    fn execute_block(
        &self,
        _header: &dyn ConsensusHeader,
        body: &dyn ConsensusBody,
        _sidecar: &dyn ConsensusSidecar,
    ) -> Result<BlockExecutionOutcome, ExecutionError> {
        let accumulator = materialize_accumulator(self.materialized_state)
            .map_err(ExecutionError::StateTransition)?;
        if accumulator.state_root() != self.pre_state_root {
            return Err(ExecutionError::StateTransition(
                StateError::RootContinuityMismatch(RootContinuityError {
                    expected: self.pre_state_root,
                    actual: accumulator.state_root(),
                }),
            ));
        }

        let planner = PlannedTransactionExecutor::new(self.planned_transactions.to_vec());
        let applier = ReferenceStateApplier::new(accumulator);
        let outcome = StatelessBlockExecutor::new().execute_block(
            &self.pre_state_root,
            body.transactions(),
            &planner,
            &applier,
        )?;
        planner.ensure_exhausted()?;
        Ok(outcome)
    }
}

fn materialize_accumulator(
    materialized_state: &[(StateKey, Vec<u8>)],
) -> Result<InMemoryAccumulator, StateError> {
    let mut accumulator = InMemoryAccumulator::new();
    if materialized_state.is_empty() {
        return Ok(accumulator);
    }

    accumulator.apply_transition(&StatePatch {
        accesses: materialized_state
            .iter()
            .map(|(key, _)| key.clone())
            .collect(),
        new_values: materialized_state
            .iter()
            .map(|(_, value)| value.clone())
            .collect(),
    })?;
    Ok(accumulator)
}
