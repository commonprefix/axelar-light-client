use consensus_types::{
    common::WorkerSetMessage,
    consensus::Update,
    lightclient::LightClientState,
    proofs::{BatchVerificationData, Message},
};
use eth::types::EthConfig;
use ethers::{
    contract::EthEvent,
    types::{Address, Bytes, Log, H256},
};
use prover::prover::types::ProverConfig;
use serde::{Deserialize, Serialize};
pub use std::str::FromStr;

// Step 1: Define the enum
#[derive(Debug, Clone, Default)]
pub enum VerificationMethod {
    Optimistic,
    #[default]
    Finality,
}

impl FromStr for VerificationMethod {
    type Err = ();

    fn from_str(input: &str) -> Result<VerificationMethod, Self::Err> {
        match input {
            "optimistic" => Ok(VerificationMethod::Optimistic),
            "finality" => Ok(VerificationMethod::Finality),
            _ => Err(()),
        }
    }
}

/// Main configuration structure of the relayer.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Network configuration. This will be used to generate the content id, as
    /// well as tweak the request in the state_prover accordingly.
    pub network: String,
    /// RPC endpoint for the consensus layer.
    pub consensus_rpc: String,
    /// RPC endpoint for the execution layer.
    pub execution_rpc: String,
    /// The RPC of the WASM chain. In our case it's Axelar devnet
    pub wasm_rpc: String,
    /// The API url of the state prover
    pub state_prover_rpc: String,
    /// The API url of the block roots archive
    pub block_roots_rpc: String,
    /// The Axelar Gateway address in the Ethereum chain
    pub gateway_addr: String,
    /// The verifier address in the wasm chain
    pub verifier_addr: String,

    /// Should the historical roots be rejected from the queue? Enabling it
    /// might drain the beacon API quota
    pub reject_historical_roots: bool,
    pub historical_roots_block_roots_batch_size: u64,

    /// Determines whether the verification will occur using sync_committee optimistic
    /// or finality updates. Use with caution, optimistic verification might lead to
    /// re-orgs.
    pub verification_method: VerificationMethod,

    /// Sentinel rabbitMQ details
    pub sentinel_queue_addr: String,
    pub sentinel_queue_name: String,

    /// RPC options for the eth package
    pub rpc_pool_max_idle_per_host: usize,
    pub rpc_timeout_secs: u64,
    pub rpc_max_retries: u64,

    /// What is the genesis timestamp of the ETH chain. Used to calculate slots out of timestmaps
    pub genesis_timestamp: u64,

    /// How many contents should the relayer process in one round/batch
    pub max_batch_size: usize,
    /// How many seconds should the relayer wait before processing the next batch
    pub process_interval: u64,
    /// How many seconds should the feeder wait before feeding the verifier with new
    /// update messages
    pub feed_interval: u64,
    /// Used to run execute messages in the wasm using wasmd. Will be deprecated
    pub wasm_wallet: String,
    /// Should the state prover implement
    pub state_prover_check: bool,
}

impl From<Config> for ProverConfig {
    fn from(config: Config) -> Self {
        ProverConfig {
            network: config.network,
            consensus_rpc: config.consensus_rpc,
            execution_rpc: config.execution_rpc,
            state_prover_rpc: config.state_prover_rpc,
            reject_historical_roots: config.reject_historical_roots,
            historical_roots_block_roots_batch_size: config.historical_roots_block_roots_batch_size,
        }
    }
}

impl From<Config> for EthConfig {
    fn from(config: Config) -> Self {
        EthConfig {
            pool_max_idle_per_host: config.rpc_pool_max_idle_per_host,
            timeout_secs: config.rpc_timeout_secs,
            rpc_max_retries: config.rpc_max_retries,
        }
    }
}

// Events
#[derive(Debug, Clone, EthEvent, PartialEq)]
pub struct ContractCall {
    #[ethevent(indexed)]
    pub sender: Address,
    pub destination_chain: String,
    pub destination_contract_address: String,
    #[ethevent(indexed)]
    pub payload_hash: H256,
    pub payload: Bytes,
}

#[derive(Debug, Clone, EthEvent, PartialEq)]
pub struct OperatorshipTransferred {
    pub new_operators_data: Bytes,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct EnrichedLog {
    pub event_name: String,
    pub contract_name: String,
    pub chain: String, // Assuming ChainName is a simple string, replace with actual type if not
    pub log: Log,
    pub source: String,
    pub tx_to: Address,
}

#[derive(Debug, serde::Deserialize)]
pub struct LightClientStateResult {
    pub data: LightClientState,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateExecuteMsg {
    #[serde(rename = "LightClientUpdate")]
    pub light_client_update: Update,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchVerificationDataRequest {
    #[serde(rename = "BatchVerificationData")]
    pub batch_verification_data: BatchVerificationData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IsWorkerSetVerifiedRequest {
    pub is_worker_set_verified: WorkerSetMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IsWorkerSetVerifiedResult {
    pub data: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IsVerifiedMessages {
    pub messages: Vec<Message>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IsVerifiedRequest {
    pub is_verified: IsVerifiedMessages,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IsVerifiedResponse {
    pub data: Vec<(Message, bool)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyDataResponse {
    pub data: String,
}
