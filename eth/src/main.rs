use eth::consensus::{ConsensusRPC, CustomConsensusApi};
use eth::constants::CONSENSUS_RPC;

#[tokio::main]
async fn main() {
	let consensus: ConsensusRPC = ConsensusRPC::new(CONSENSUS_RPC);
	let res = consensus.get_latest_beacon_block().await;
	println!("{:?}", res);
}
