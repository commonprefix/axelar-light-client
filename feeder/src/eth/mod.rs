use self::consensus::ConsensusRPC;
use self::execution::ExecutionRPC;
use self::gateway::Gateway;

pub mod consensus;
pub mod execution;
pub mod gateway;
pub mod utils;

pub mod constants {
    pub const CONSENSUS_RPC: &str = "http://nimbus-mainnet.commonprefix.com";
    pub const EXECUTION_RPC: &str = "https://eth.llamarpc.com";
    pub const GATEWAY_ADDR: &str = "0x4F4495243837681061C4743b74B3eEdf548D56A5";
}