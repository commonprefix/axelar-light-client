use ethers::{contract::EthEvent, types::{U256, Bytes, Address, H256, Log}};
use prover::prover::types::ProverConfig;
use eth::types::EthConfig;
use serde::{Serialize, Deserialize};
pub use std::str::FromStr;

// Step 1: Define the enum
#[derive(Debug, Clone)]
pub enum VerificationMethod {
    Optimistic,
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

#[derive(Debug, Clone)]
pub struct Config {
    pub consensus_rpc: String,
    pub execution_rpc: String,
    pub state_prover_rpc: String,
    pub gateway_addr: String,
    pub historical_roots_enabled: bool,
    pub historical_roots_block_roots_batch_size: u64,
    pub verification_method: VerificationMethod,
    pub sentinel_queue_addr: String,
    pub sentinel_queue_name: String,
    pub rpc_pool_max_idle_per_host: usize,
    pub rpc_timeout_secs: u64,
}

impl From<Config> for ProverConfig {
    fn from(config: Config) -> Self {
        ProverConfig {
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
            timeout_secs: config.rpc_timeout_secs
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

#[derive(Serialize, Deserialize, Debug)]
pub struct EnrichedLog {
    pub event_name: String,
    contract_name: String,
    chain: String, // Assuming ChainName is a simple string, replace with actual type if not
    pub log: Log,
    source: String,
    tx_to: Address,
}

