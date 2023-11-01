mod error;
mod eth;
mod types;
mod wasm;

use tokio;
use wasm::WasmClient;

#[tokio::main]
async fn main() {
    const NODE_URL: &str = "http://devnet.rpc.axelar.dev:9090";
    const ADDR: &str = "axelar1mpk5vthrcgsugqtcn6ha8rt4uurpryrsnrezrxdmlxuqc6helu9qupm6nh";

    let mut wasm = WasmClient::new(NODE_URL.into(), ADDR.into());
    // let state = wasm.get_state().await.unwrap();
    // println!("State: {:?}", state);
    let period = wasm.get_period().await.unwrap();
    println!("Period: {:?}", period);
    // let url = "http://nimbus-mainnet.commonprefix.com";
    // let consensus = ConsensusRPC::new(url);

    // let res = consensus.get_updates(863, 1).await.unwrap();
    // println!("Update: {:?}", res);

    // let url: &str = "https://eth.llamarpc.com";
    // let execution = ExecutionRPC::new(url).unwrap();

    // let hash = "0x1f59181a06f73b58a02ffb2ec291e108af359f8c4702fb5c50d9e2d0a240ac43"
    //     .parse::<H256>()
    //     .unwrap();

    // let res = execution
    //     .get_transaction_receipt(&hash)
    //     .await
    //     .unwrap()
    //     .unwrap();

    // println!("Transaction Receipt: {:?}", res);
}
