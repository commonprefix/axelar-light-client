use std::{env, str::FromStr};
use dotenv::dotenv;

use crate::types::{Config, VerificationMethod};

pub fn load_config() -> Config {
    dotenv().ok();

    Config {
        consensus_rpc: env::var("CONSENSUS_RPC").expect("Missing CONSENSUS_RPC from .env"),
        execution_rpc: env::var("EXECUTION_RPC").expect("Missing EXECUTION_RPC from .env"),
        state_prover_rpc: env::var("STATE_PROVER_RPC").expect("Missing STATE_PROVER from .env"),
        gateway_addr: env::var("GATEWAY_ADDR").expect("Missing GATEWAY_ADDR from .env"),
        sentinel_queue_addr: env::var("SENTINEL_QUEUE_ADDR").expect("Missing SENTINEL_QUEUE_ADDR from .env"),
        sentinel_queue_name: env::var("SENTINEL_QUEUE_NAME").expect("Missing SENTINEL_QUEUE_NAME from .env"),
        historical_roots_enabled: true,
        historical_roots_block_roots_batch_size: 1000,
        verification_method: VerificationMethod::from_str(
            env::var("VERIFICATION_METHOD")
                .expect("VERIFICATION not found")
                .as_str(),
        ).unwrap(),
        rpc_pool_max_idle_per_host: usize::from_str(env::var("RPC_POOL_MAX_IDLE_PER_HOST").expect("Missing RPC_POOL_MAX_IDLE_PER_HOST from .env").as_str()).unwrap(),
        rpc_timeout_secs: u64::from_str(env::var("RPC_TIMEOUT_SECS").expect("Missing RPC_TIMEOUT_SECS from .env").as_str()).unwrap()
    }
}