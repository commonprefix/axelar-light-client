use consensus_types::{consensus::Update, lightclient::LightClientState};
use eth::types::EthConfig;
use ethers::{
    contract::EthEvent,
    types::{Address, Bytes, Log, H256, U256},
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
    pub network: String,
    pub consensus_rpc: String,
    pub execution_rpc: String,
    pub wasm_rpc: String,
    pub state_prover_rpc: String,
    pub gateway_addr: String,
    pub verifier_addr: String,
    pub historical_roots_enabled: bool,
    pub historical_roots_block_roots_batch_size: u64,
    pub verification_method: VerificationMethod,
    pub sentinel_queue_addr: String,
    pub sentinel_queue_name: String,
    pub rpc_pool_max_idle_per_host: usize,
    pub rpc_timeout_secs: u64,
    pub rpc_max_retries: u64,
    pub genesis_timestamp: u64,
    pub max_batch_size: usize,
    pub process_interval: u64,
    pub feed_interval: u64,
}

impl From<Config> for ProverConfig {
    fn from(config: Config) -> Self {
        ProverConfig {
            network: config.network,
            consensus_rpc: config.consensus_rpc,
            execution_rpc: config.execution_rpc,
            state_prover_rpc: config.state_prover_rpc,
            historical_roots_enabled: config.historical_roots_enabled,
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
pub struct ContractCallWithToken {
    #[ethevent(indexed)]
    pub sender: Address,
    pub destination_chain: String,
    pub destination_contract_address: String,
    #[ethevent(indexed)]
    pub payload_hash: H256,
    pub payload: Bytes,
    pub symbol: String,
    pub amount: U256,
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
