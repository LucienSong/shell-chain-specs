#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shell_primitives::{
    BasicFeesPerGas, BasicTransactionPayload, ChainId, CreateTransactionPayload, GasPrice,
    PrimitiveError, ProtocolObject, Root, StateKey, StateWitness, TransactionEnvelope,
    TransactionPayload, TransactionPayloadSsz, TxValue, U256,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoVector {
    pub id: String,
    pub category: String,
    pub rule: String,
    pub description: String,
    pub input: CryptoInput,
    pub expected_outcome: String,
    #[serde(default)]
    pub expected_error: Option<CryptoExpectedError>,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoInput {
    pub scheme_id: u8,
    pub public_key_hex: String,
    pub signing_root_hex: String,
    pub signature_hex: String,
    pub verification_path: VerificationPathInput,
    #[serde(default)]
    pub dispatcher_config: Option<DispatcherConfigInput>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPathInput {
    TransactionAuthorization,
    ValidatorMessage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatcherConfigInput {
    #[serde(default)]
    pub user_path_max_signature_size: Option<usize>,
    #[serde(default)]
    pub validator_path_max_signature_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoExpectedError {
    pub kind: String,
    #[serde(default)]
    pub scheme_id: Option<u8>,
    #[serde(default)]
    pub max_size: Option<usize>,
    #[serde(default)]
    pub actual_size: Option<usize>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub limit_kind: Option<String>,
    #[serde(default)]
    pub context: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheapFirstVector {
    pub id: String,
    pub category: String,
    pub rule: String,
    pub description: String,
    pub input: CheapFirstInput,
    pub expected_outcome: String,
    pub expected_error: ExpectedError,
    #[serde(default)]
    pub expected_effects: ExpectedEffects,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MempoolPolicyVector {
    pub id: String,
    pub category: String,
    pub rule: String,
    pub description: String,
    pub input: MempoolInput,
    pub expected_outcome: String,
    pub expected_error: ExpectedError,
    #[serde(default)]
    pub expected_effects: ExpectedEffects,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerActionVector {
    pub id: String,
    pub category: String,
    pub rule: String,
    pub description: String,
    pub input: PeerActionInput,
    pub expected_outcome: OutcomeClass,
    pub expected_action: ExpectedPeerAction,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerActionInput {
    ValidationOutcome {
        origin: NetworkOriginInput,
        outcome: OutcomeClass,
    },
    MempoolError {
        origin: NetworkOriginInput,
        stage: ValidationStageInput,
        error: MempoolPeerErrorInput,
    },
    ConsensusError {
        origin: NetworkOriginInput,
        error: ConsensusPeerErrorInput,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeClass {
    Accept,
    Reject,
    PolicyReject,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkOriginInput {
    Gossip,
    Fetch,
    Sync,
    LocalRpc,
    LocalBuilder,
    TestHarness,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStageInput {
    T0,
    T1,
    T2,
    T3,
    T4,
    B0,
    B1,
    B2,
    B3,
    B4,
    B5,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneInput {
    Payload,
    Witness,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MempoolPeerErrorInput {
    MalformedSsz {
        context: String,
    },
    FeeFloor {
        lane: FeeLaneInput,
        required: u64,
        actual: u64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsensusPeerErrorInput {
    CryptoVerificationFailed { scheme_id: u8, context: String },
    WitnessByteLimitExceeded { max_bytes: u64, actual_bytes: u64 },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerActionHintInput {
    RejectedObject,
    MalformedAnnouncement,
    InvalidTransaction,
    InvalidBlock,
    InvalidSignature,
    OversizedObject,
    PolicyRejected,
    InternalError,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpectedPeerAction {
    Accept,
    Ignore {
        hint: PeerActionHintInput,
    },
    AdjustReputation {
        delta: i32,
        hint: PeerActionHintInput,
    },
    Disconnect {
        hint: PeerActionHintInput,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "layer", deny_unknown_fields)]
pub enum CheapFirstInput {
    #[serde(rename = "shell-mempool")]
    Mempool(MempoolInput),
    #[serde(rename = "shell-consensus")]
    Consensus(ConsensusInput),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedError {
    pub kind: String,
    #[serde(default)]
    pub lane: Option<String>,
    #[serde(default)]
    pub context: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedEffects {
    #[serde(default)]
    pub transaction_signature_verifications: Option<usize>,
    #[serde(default)]
    pub proposer_credential_resolutions: Option<usize>,
    #[serde(default)]
    pub validator_signature_verifications: Option<usize>,
    #[serde(default)]
    pub transaction_revalidations: Option<usize>,
    #[serde(default)]
    pub witness_preparations: Option<usize>,
    #[serde(default)]
    pub execution_calls: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MempoolInput {
    pub payload: MempoolPayloadInput,
    pub authorizations: Vec<MempoolAuthorizationInput>,
    pub authorization_materials: Vec<AuthorizationMaterialInput>,
    pub policy: MempoolPolicyInput,
    #[serde(default)]
    pub observed_nonce: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MempoolPayloadInput {
    pub nonce: u64,
    pub gas_limit: u64,
    pub regular_fee: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_witness_priority_fee: u64,
    pub to: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MempoolAuthorizationInput {
    pub scheme_id: u8,
    pub signature_hex: String,
    pub payload_root_mode: PayloadRootMode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadRootMode {
    Canonical,
    FlipFirstByte,
}

impl PayloadRootMode {
    pub fn apply(&self, root: Root) -> Root {
        match self {
            Self::Canonical => root,
            Self::FlipFirstByte => {
                let mut mutated = root;
                mutated[0] ^= 0xFF;
                mutated
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationMaterialInput {
    pub public_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MempoolPolicyInput {
    pub payload_lane_base_fee: u64,
    pub witness_lane_base_fee: u64,
    pub max_future_nonce_gap: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusInput {
    pub header: ConsensusHeaderInput,
    pub body: ConsensusBodyInput,
    pub sidecar: ConsensusSidecarInput,
    pub execution: ConsensusExecutionInput,
    #[serde(default)]
    pub prefilter: Option<ConsensusPrefilterInput>,
    pub resolver: ConsensusResolverInput,
    pub dispatcher: ConsensusDispatcherInput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusHeaderInput {
    pub block_root: String,
    pub transactions_root: String,
    pub execution_witnesses_root: String,
    pub state_root: String,
    pub receipts_root: String,
    pub witness_bytes: u64,
    pub proposer_index: u64,
    pub proposer_signature_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusBodyInput {
    pub transactions_root_mode: RootMode,
    pub transaction_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusSidecarInput {
    pub block_root_mode: RootMode,
    pub committed_root_mode: RootMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusExecutionInput {
    pub post_state_root_mode: RootMode,
    pub receipts_root_mode: RootMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusPrefilterInput {
    #[serde(default)]
    pub max_witness_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusResolverInput {
    pub scheme_id: u8,
    pub public_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusDispatcherInput {
    pub validator_signature: SignatureOutcome,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureOutcome {
    Accept,
    Reject,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootMode {
    Canonical,
    FlipFirstByte,
}

impl RootMode {
    pub fn apply(&self, root: Root) -> Root {
        match self {
            Self::Canonical => root,
            Self::FlipFirstByte => {
                let mut mutated = root;
                mutated[0] ^= 0x01;
                mutated
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionVector {
    pub id: String,
    pub category: String,
    pub description: String,
    pub input: TransactionVectorInput,
    pub expected_outcome: String,
    #[serde(default)]
    pub expected_error: Option<TransactionExpectedError>,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub payload_tag: Option<u8>,
    #[serde(default)]
    pub payload_root: Option<String>,
    #[serde(default)]
    pub authorization_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionVectorInput {
    #[serde(default)]
    pub payload: Option<TransactionPayloadInput>,
    #[serde(default)]
    pub wire_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransactionPayloadInput {
    Basic {
        chain_id: String,
        nonce: u64,
        gas_limit: u64,
        fees: FeeInput,
        to: String,
        value: String,
        input_hex: String,
        access_commitment: String,
    },
    Create {
        chain_id: String,
        nonce: u64,
        gas_limit: u64,
        fees: FeeInput,
        value: String,
        initcode_hex: String,
        access_commitment: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeInput {
    regular: String,
    max_priority_fee_per_gas: String,
    max_witness_priority_fee: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionExpectedError {
    pub kind: String,
    #[serde(default)]
    pub tag: Option<u8>,
    #[serde(default)]
    pub context: Option<String>,
}

impl TransactionVector {
    pub fn payload(&self) -> TransactionPayloadSsz {
        let payload = self
            .input
            .payload
            .as_ref()
            .unwrap_or_else(|| panic!("{} is missing input.payload", self.id));
        build_payload(payload)
    }

    pub fn envelope(&self) -> TransactionEnvelope {
        TransactionEnvelope {
            payload: self.payload(),
            authorizations: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessVector {
    pub id: String,
    pub category: String,
    pub rule: String,
    pub description: String,
    pub input: WitnessInput,
    pub expected_outcome: String,
    #[serde(default)]
    pub expected_error: Option<WitnessExpectedError>,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub state_keys: Option<Vec<String>>,
    #[serde(default)]
    pub proof_shape_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessInput {
    #[serde(default)]
    pub ordering_is_canonical: Option<bool>,
    #[serde(default)]
    pub proof_shape_kind: Option<String>,
    #[serde(default)]
    pub expected_state_root: Option<String>,
    #[serde(default)]
    pub witnesses: Option<Vec<WitnessFixture>>,
    #[serde(default)]
    pub witness: Option<WitnessFixture>,
    #[serde(default)]
    pub materialized_state: Option<Vec<MaterializedLeafFixture>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessFixture {
    key: StateKeyInput,
    leaf_value_hex: String,
    proof_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedLeafFixture {
    key: StateKeyInput,
    leaf_value_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateKeyInput {
    AccountHeader {
        address: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    StorageSlot {
        address: String,
        slot: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    CodeChunk {
        address: String,
        chunk_index: u32,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    RawTreeKey {
        raw_key: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
    Stem {
        stem: String,
        #[serde(default)]
        canonical_key_hex: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessExpectedError {
    pub kind: String,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub context: Option<String>,
}

impl WitnessVector {
    pub fn witness(&self) -> Option<StateWitness> {
        self.input
            .witness
            .as_ref()
            .map(WitnessFixture::to_state_witness)
    }

    pub fn witnesses(&self) -> Vec<StateWitness> {
        self.input
            .witnesses
            .as_ref()
            .map(|witnesses| {
                witnesses
                    .iter()
                    .map(WitnessFixture::to_state_witness)
                    .collect()
            })
            .or_else(|| self.witness().map(|witness| vec![witness]))
            .unwrap_or_default()
    }

    pub fn materialized_state(&self) -> Vec<(StateKey, Vec<u8>)> {
        self.input
            .materialized_state
            .as_ref()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| (entry.key.to_state_key(), parse_hex(&entry.leaf_value_hex)))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn expected_state_root(&self) -> Option<Root> {
        self.input.expected_state_root.as_deref().map(parse_root)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckVector {
    pub id: String,
    pub category: String,
    pub rule: String,
    pub description: String,
    pub input: RootCheckInput,
    pub expected_outcome: String,
    #[serde(default)]
    pub expected_error: Option<RootCheckExpectedError>,
    pub owned_by: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub transactions_root: String,
    pub execution_witnesses_root: String,
    pub state_root: String,
    pub receipts_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckInput {
    pub header: RootCheckHeaderInput,
    pub body: RootCheckBodyInput,
    pub sidecar: RootCheckSidecarInput,
    pub execution: RootCheckExecutionInput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckHeaderInput {
    pub block_root: String,
    pub block_number: u64,
    pub timestamp: u64,
    pub proposer_index: u64,
    pub parent_root: String,
    pub transactions_root: String,
    pub execution_witnesses_root: String,
    pub state_root: String,
    pub receipts_root: String,
    pub witness_bytes: u64,
    pub proposer_signature_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckBodyInput {
    pub transaction_vector_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckSidecarInput {
    pub block_root: String,
    pub witness_vector_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckExecutionInput {
    pub steps: Vec<RootCheckExecutionStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckExecutionStep {
    pub transaction_vector_id: String,
    pub witness_vector_id: String,
    pub new_leaf_value_hex: String,
    pub receipt_status_code: u8,
    pub receipt_output_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckExpectedError {
    pub kind: String,
    pub expected_root: String,
    pub actual_root: String,
}

pub fn validation_order_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("validation-order")
}

pub fn mempool_policy_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("mempool-policy")
}

pub fn peer_action_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("peer-actions")
}

pub fn crypto_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("crypto")
}

pub fn transaction_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("transactions")
}

pub fn witness_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("witnesses")
}

pub fn root_check_fixture_paths() -> Vec<PathBuf> {
    fixture_paths("root-checks")
}

pub fn fixture_paths(category: &str) -> Vec<PathBuf> {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(category);
    fs::read_dir(&vectors_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", vectors_dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect()
}

pub fn load_fixture<T: DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

pub fn load_transaction_fixture_by_id(id: &str) -> TransactionVector {
    load_fixture(&fixture_path_for_id("transactions", id))
}

pub fn load_witness_fixture_by_id(id: &str) -> WitnessVector {
    load_fixture(&fixture_path_for_id("witnesses", id))
}

pub fn compute_transactions_root(
    transactions: &[TransactionEnvelope],
) -> Result<Root, PrimitiveError> {
    let mut hasher = Sha256::new();
    hasher.update(b"shell-fixtures/transactions-root/v1");
    hasher.update((transactions.len() as u64).to_be_bytes());

    for transaction in transactions {
        hasher.update(transaction.canonical_root()?);
    }

    Ok(hasher.finalize().into())
}

pub fn compute_execution_witnesses_root(witnesses: &[StateWitness]) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(b"shell-fixtures/execution-witnesses-root/v1");
    hasher.update((witnesses.len() as u64).to_be_bytes());

    for witness in witnesses {
        let encoded_key = shell_primitives::encode_state_key(&witness.key);
        hasher.update((encoded_key.as_slice().len() as u64).to_be_bytes());
        hasher.update(encoded_key.as_slice());
        hasher.update((witness.leaf_value.len() as u64).to_be_bytes());
        hasher.update(witness.leaf_value.as_slice());
        hasher.update((witness.proof.len() as u64).to_be_bytes());
        for node in &witness.proof {
            hasher.update(node);
        }
    }

    hasher.finalize().into()
}

pub fn parse_root(value: &str) -> Root {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte root, got {len} bytes in {value}"))
}

pub fn parse_address(value: &str) -> [u8; 20] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 20-byte address, got {len} bytes in {value}"))
}

pub fn parse_hex(value: &str) -> Vec<u8> {
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

fn fixture_path_for_id(category: &str, id: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(category)
        .join(format!("{id}.json"))
}

fn build_payload(input: &TransactionPayloadInput) -> TransactionPayloadSsz {
    match input {
        TransactionPayloadInput::Basic {
            chain_id,
            nonce,
            gas_limit,
            fees,
            to,
            value,
            input_hex,
            access_commitment,
        } => TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
            chain_id: ChainId(U256(parse_bytes_32(chain_id))),
            nonce: *nonce,
            gas_limit: *gas_limit,
            fees: parse_fees(fees),
            to: parse_address(to),
            value: TxValue(U256(parse_bytes_32(value))),
            input: parse_hex(input_hex),
            access_commitment: parse_root(access_commitment),
        })),
        TransactionPayloadInput::Create {
            chain_id,
            nonce,
            gas_limit,
            fees,
            value,
            initcode_hex,
            access_commitment,
        } => TransactionPayloadSsz::new(TransactionPayload::Create(CreateTransactionPayload {
            chain_id: ChainId(U256(parse_bytes_32(chain_id))),
            nonce: *nonce,
            gas_limit: *gas_limit,
            fees: parse_fees(fees),
            value: TxValue(U256(parse_bytes_32(value))),
            initcode: parse_hex(initcode_hex),
            access_commitment: parse_root(access_commitment),
        })),
    }
}

fn parse_fees(fees: &FeeInput) -> BasicFeesPerGas {
    BasicFeesPerGas {
        regular: GasPrice(U256(parse_bytes_32(&fees.regular))),
        max_priority_fee_per_gas: GasPrice(U256(parse_bytes_32(&fees.max_priority_fee_per_gas))),
        max_witness_priority_fee: GasPrice(U256(parse_bytes_32(&fees.max_witness_priority_fee))),
    }
}

fn parse_bytes_32(value: &str) -> [u8; 32] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte hex string, got {len} bytes in {value}"))
}

fn parse_bytes_31(value: &str) -> [u8; 31] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 31-byte hex string, got {len} bytes in {value}"))
}

impl StateKeyInput {
    fn to_state_key(&self) -> StateKey {
        let key = match self {
            Self::AccountHeader { address, .. } => StateKey::AccountHeader(parse_address(address)),
            Self::StorageSlot { address, slot, .. } => StateKey::StorageSlot {
                address: parse_address(address),
                slot: parse_bytes_32(slot),
            },
            Self::CodeChunk {
                address,
                chunk_index,
                ..
            } => StateKey::CodeChunk {
                address: parse_address(address),
                chunk_index: *chunk_index,
            },
            Self::RawTreeKey { raw_key, .. } => StateKey::RawTreeKey(parse_bytes_32(raw_key)),
            Self::Stem { stem, .. } => StateKey::Stem(parse_bytes_31(stem)),
        };

        if let Some(expected_hex) = self.canonical_key_hex() {
            assert_eq!(
                shell_primitives::encode_state_key(&key).as_slice(),
                parse_hex(expected_hex).as_slice(),
                "canonical StateKey bytes mismatch for {:?}",
                self
            );
        }

        key
    }

    fn canonical_key_hex(&self) -> Option<&str> {
        match self {
            Self::AccountHeader {
                canonical_key_hex, ..
            }
            | Self::StorageSlot {
                canonical_key_hex, ..
            }
            | Self::CodeChunk {
                canonical_key_hex, ..
            }
            | Self::RawTreeKey {
                canonical_key_hex, ..
            }
            | Self::Stem {
                canonical_key_hex, ..
            } => canonical_key_hex.as_deref(),
        }
    }
}

impl WitnessFixture {
    fn to_state_witness(&self) -> StateWitness {
        StateWitness {
            key: self.key.to_state_key(),
            leaf_value: parse_hex(&self.leaf_value_hex),
            proof: self
                .proof_hex
                .iter()
                .map(|value| parse_bytes_32(value))
                .collect(),
        }
    }
}
