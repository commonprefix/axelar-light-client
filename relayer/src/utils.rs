use dotenv::dotenv;
use std::{env, str::FromStr};

use crate::types::{Config, VerificationMethod};

pub fn is_in_slot_range(slot: u64, start_slot: u64, end_slot: u64) -> bool {
    slot >= start_slot && slot < end_slot
}

/// Loads the full relayer configuration from the environment variables.
pub fn load_config() -> Config {
    dotenv().ok();

    Config {
        network: env::var("NETWORK").expect("Missing NETWORK from .env"),
        consensus_rpc: env::var("CONSENSUS_RPC").expect("Missing CONSENSUS_RPC from .env"),
        execution_rpc: env::var("EXECUTION_RPC").expect("Missing EXECUTION_RPC from .env"),
        wasm_rpc: env::var("WASM_RPC").expect("Missing WASM_RPC from .env"),
        state_prover_rpc: env::var("STATE_PROVER_RPC").expect("Missing STATE_PROVER from .env"),
        gateway_addr: env::var("GATEWAY_ADDR").expect("Missing GATEWAY_ADDR from .env"),
        verifier_addr: env::var("VERIFIER_ADDR").expect("Missing VERIFIER_ADDR from .env"),
        sentinel_queue_addr: env::var("SENTINEL_QUEUE_ADDR")
            .expect("Missing SENTINEL_QUEUE_ADDR from .env"),
        sentinel_queue_name: env::var("SENTINEL_QUEUE_NAME")
            .expect("Missing SENTINEL_QUEUE_NAME from .env"),
        reject_historical_roots: true,
        historical_roots_block_roots_batch_size: 1000,
        verification_method: VerificationMethod::from_str(
            env::var("VERIFICATION_METHOD")
                .expect("VERIFICATION not found")
                .as_str(),
        )
        .unwrap(),
        rpc_pool_max_idle_per_host: usize::from_str(
            env::var("RPC_POOL_MAX_IDLE_PER_HOST")
                .expect("Missing RPC_POOL_MAX_IDLE_PER_HOST from .env")
                .as_str(),
        )
        .unwrap(),
        rpc_timeout_secs: u64::from_str(
            env::var("RPC_TIMEOUT_SECS")
                .expect("Missing RPC_TIMEOUT_SECS from .env")
                .as_str(),
        )
        .unwrap(),
        rpc_max_retries: u64::from_str(
            env::var("RPC_MAX_RETRIES")
                .expect("Missing RPC_MAX_RETRIES from .env")
                .as_str(),
        )
        .unwrap(),
        genesis_timestamp: u64::from_str(
            env::var("GENESIS_TIMESTAMP")
                .expect("Missing GENESIS_TIMESTAMP from .env")
                .as_str(),
        )
        .unwrap(),
        max_batch_size: usize::from_str(
            env::var("MAX_BATCH_SIZE")
                .expect("Missing MAX_BATCH_SIZE from .env")
                .as_str(),
        )
        .unwrap(),
        process_interval: u64::from_str(
            env::var("PROCESS_INTERVAL")
                .expect("Missing PROCESS_INTERVAL from .env")
                .as_str(),
        )
        .unwrap(),
        feed_interval: u64::from_str(
            env::var("FEED_INTERVAL")
                .expect("Missing FEED_INTERVAL from .env")
                .as_str(),
        )
        .unwrap(),
        wasm_wallet: env::var("WASM_WALLET").expect("Missing WASM_WALLET from .env"),
        state_prover_check: true,
    }
}

pub fn calc_sync_period(slot: u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}
