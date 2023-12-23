use prover::prover::types::ProverConfig;

#[derive(Debug, Clone)]
pub struct Config {
    pub consensus_rpc: String,
    pub execution_rpc: String,
    pub state_prover_rpc: String,
    pub gateway_addr: String,
    pub historical_roots_enabled: bool,
    pub historical_roots_block_roots_batch_size: u64,
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