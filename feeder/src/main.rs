mod error;
mod eth;
mod types;

use eth::{consensus::ConsensusRPC, execution::ExecutionRPC};
use ethers::types::H256;
use tokio;

#[tokio::main]
async fn main() {
    let url = "http://nimbus-mainnet.commonprefix.com";
    let consensus = ConsensusRPC::new(url);

    let res = consensus.get_updates(863, 1).await.unwrap();
    println!("Update: {:?}", res);

    let url: &str = "https://eth.llamarpc.com";
    let execution = ExecutionRPC::new(url).unwrap();

    let hash = "0x1f59181a06f73b58a02ffb2ec291e108af359f8c4702fb5c50d9e2d0a240ac43"
        .parse::<H256>()
        .unwrap();

    let res = execution
        .get_transaction_receipt(&hash)
        .await
        .unwrap()
        .unwrap();

    println!("Transaction Receipt: {:?}", res);
}
