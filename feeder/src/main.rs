mod error;
mod eth;
mod prover;
mod types;
mod wasm;

use consensus_types::lightclient::UpdateVariant;
use eth::{consensus::ConsensusRPC, constants::*, execution::ExecutionRPC, gateway::Gateway};
use eyre::anyhow;
use prover::Prover;
use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;
use tokio;
use wasm::WasmClient;

#[tokio::main]
async fn main() {
    const NODE_URL: &str = "http://devnet.rpc.axelar.dev:9090";
    const ADDR: &str = "axelar1mpk5vthrcgsugqtcn6ha8rt4uurpryrsnrezrxdmlxuqc6helu9qupm6nh";

    let consensus: ConsensusRPC = ConsensusRPC::new(CONSENSUS_RPC);
    let execution: ExecutionRPC = ExecutionRPC::new(EXECUTION_RPC);
    let gateway: Gateway = Gateway::new(EXECUTION_RPC, GATEWAY_ADDR);

    let mut wasm = WasmClient::new(NODE_URL.into(), ADDR.into());

    let finality_update = consensus.get_finality_update().await.unwrap();
    let finality_header_slot = finality_update.finalized_header.beacon.slot;
    let min_slot_in_block_roots = finality_header_slot - SLOTS_PER_HISTORICAL_ROOT as u64 + 1;
    let interested_messages = gateway
        .get_messages_in_slot_range(min_slot_in_block_roots, finality_header_slot)
        .await
        .unwrap();

    let first_message = interested_messages.first().unwrap();
    let prover = Prover::new(execution, consensus);

    let proof = prover
        .generate_proof(
            first_message.clone(),
            UpdateVariant::Finality(finality_update),
        )
        .await
        .unwrap();

    let json_string = serde_json::to_string(&proof).unwrap();

    // Print the JSON string
    println!("AncestryProof JSON: {}", json_string);

    // let state = wasm.get_state().await.unwrap();
    // println!("State: {:?}", state);
    let period = wasm.get_period().await.unwrap();
    println!("Period: {:?}", period);

    //let state = consensus.get_state(7734415).await.unwrap();
    //let res = consensus.get_updates(863, 1).await.unwrap();
    //println!("Update: {:#?}", res);

    //let messages = gateway.get_messages_after_slot(10).await;

    //println!("Messages: {:#?}", messages);

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
