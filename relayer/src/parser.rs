use consensus_types::proofs::{ContentVariant, Message, CrossChainId};
use eth::types::FullBlockDetails;
use eyre::{Result, eyre};
use ethers::{contract::EthEvent, abi::RawLog, types::{TransactionReceipt, Log}};
use prover::prover::types::EnrichedContent;
use crate::types::{EnrichedLog, ContractCallWithToken};

pub fn parse_enriched_log(enriched_log: &EnrichedLog, block_details: &FullBlockDetails) -> Result<EnrichedContent> {
    let log = &enriched_log.log;
    match enriched_log.event_name.as_str() {
        "ContractCallWithToken" => {
            let event: ContractCallWithToken = EthEvent::decode_log(&RawLog::from(log.clone())).unwrap();
            let message = Message {
                cc_id: generate_cc_id(&enriched_log.log, &block_details.receipts)?,
                source_address: format!("0x{:x}", event.sender).parse().unwrap(),
                destination_chain: event.destination_chain.parse().unwrap(),
                destination_address: event.destination_contract_address.parse().unwrap(),
                payload_hash: event.payload_hash.into(),
            };

            Ok(ContentVariant::Message(message))
        },
        _ => Err(eyre!("Enriched log variant is not supported {:?}", enriched_log))
    }
    .and_then(|content| enrich_content(&content, log, block_details))
}

fn enrich_content(content: &ContentVariant, log: &Log, block_details: &FullBlockDetails) -> Result<EnrichedContent> {
    let msg = EnrichedContent {
        content: content.clone(),
        exec_block: block_details.exec_block.clone(),
        beacon_block: block_details.beacon_block.clone(),
        receipts: block_details.receipts.clone(),
        tx_hash: log.transaction_hash.unwrap(),
    };

    Ok(msg)
}

fn generate_cc_id(log: &Log, receipts: &[TransactionReceipt]) -> Result<CrossChainId> {
    let tx_hash = log.transaction_hash.unwrap();
    let tx_log_index = calculate_tx_log_index(log, receipts);

    let cc_id = CrossChainId {
        chain: "ethereum".parse().unwrap(),
        id: format!("0x{:x}:{}", log.transaction_hash.unwrap(), tx_log_index)
            .parse()?
    };

    Ok(cc_id)
}

fn calculate_tx_log_index(
    log: &Log,
    receipts: &[TransactionReceipt],
) -> u64 {
    if let Some(tx_log_index) = log.transaction_log_index {
        return tx_log_index.as_u64()
    }

    let log_index = log.log_index.unwrap().as_u64();
    let tx_index = log.transaction_index.unwrap().as_u64();

    let mut logs_before_tx = 0;
    for idx in 0..tx_index {
        logs_before_tx += receipts.get(idx as usize).unwrap().logs.len();
    }

    log_index - logs_before_tx as u64
}