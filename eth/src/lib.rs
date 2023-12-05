pub mod consensus;
pub mod error;
pub mod execution;
pub mod gateway;
pub mod types;
pub mod utils;

pub mod constants {
    pub const CONSENSUS_RPC: &str =
        "https://ethereum-mainnet.core.chainstack.com/beacon/473f6bf8d0a884c77ef1ac103eaa5f1a";
    pub const EXECUTION_RPC: &str = "https://eth.meowrpc.com";
    pub const STATE_PROVER_RPC: &str = "http://65.21.123.218:3000";
    pub const GATEWAY_ADDR: &str = "0x4F4495243837681061C4743b74B3eEdf548D56A5";
}
