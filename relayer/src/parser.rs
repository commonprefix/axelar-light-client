use crate::types::{ContractCall, EnrichedLog, OperatorshipTransferred};
use consensus_types::{
    common::{ContentVariant, PrimaryKey, WorkerSetMessage},
    proofs::{CrossChainId, Message},
};
use eth::types::FullBlockDetails;
use ethers::{
    abi::RawLog,
    contract::EthEvent,
    types::{Log, TransactionReceipt},
    utils::hex,
};
use eyre::{eyre, Result};
use prover::prover::types::EnrichedContent;

/// The driver function for parsing an enriched log into an enriched content.
/// This is the only place where we need to know about the different enriched log variants.
/// Currenlty we support only ContractCall and OperatorshipTransferred events.
pub fn parse_enriched_log(
    enriched_log: &EnrichedLog,
    block_details: &FullBlockDetails,
    delivery_tag: u64,
) -> Result<EnrichedContent> {
    let log = &enriched_log.log;
    match enriched_log.event_name.as_str() {
        "ContractCall" => {
            let event: ContractCall = EthEvent::decode_log(&RawLog::from(log.clone()))
                .map_err(|e| eyre!("Error decoding log {:?}", e))?;
            let message = Message {
                cc_id: CrossChainId {
                    chain: "ethereum".parse().unwrap(),
                    id: generate_id(log, block_details.receipts.as_slice())
                        .try_into()
                        .unwrap(),
                },
                source_address: format!("0x{:x}", event.sender).parse().unwrap(),
                destination_chain: event.destination_chain.parse().unwrap(),
                destination_address: event.destination_contract_address.parse().unwrap(),
                payload_hash: event.payload_hash.into(),
            };

            Ok(ContentVariant::Message(message))
        }
        "OperatorshipTransferred" => {
            let event: OperatorshipTransferred =
                EthEvent::decode_log(&RawLog::from(log.clone()))
                    .map_err(|e| eyre!("Error decoding log {:?}", e))?;
            let message = WorkerSetMessage {
                message_id: generate_id(log, block_details.receipts.as_slice()).try_into()?,
                new_operators_data: hex::encode(event.new_operators_data),
            };

            Ok(ContentVariant::WorkerSet(message))
        }
        _ => Err(eyre!(
            "Enriched log variant is not supported block_hash: {:x} tx_hash: {:x} log_index: {}",
            enriched_log.log.block_hash.unwrap(),
            enriched_log.log.transaction_hash.unwrap(),
            enriched_log.log.log_index.unwrap(),
        )),
    }
    .and_then(|content| enrich_content(&content, log, block_details, delivery_tag))
}

/// Enriches the content with the block details and the transaction hash.
fn enrich_content(
    content: &ContentVariant,
    log: &Log,
    block_details: &FullBlockDetails,
    delivery_tag: u64,
) -> Result<EnrichedContent> {
    let msg = EnrichedContent {
        content: content.clone(),
        exec_block: block_details.exec_block.clone(),
        beacon_block: block_details.beacon_block.clone(),
        receipts: block_details.receipts.clone(),
        tx_hash: log.transaction_hash.unwrap(),
        id: match content {
            ContentVariant::Message(message) => message.key(),
            ContentVariant::WorkerSet(message) => message.key(),
        },
        delivery_tag,
    };

    Ok(msg)
}

/// Generates an id from a log and a list of receipts. This is used to both the
/// Message and the worker set and it's format is  "tx_hash:tx_log_index"
fn generate_id(log: &Log, receipts: &[TransactionReceipt]) -> String {
    let tx_log_index = calculate_tx_log_index(log, receipts);

    format!("0x{:x}:{}", log.transaction_hash.unwrap(), tx_log_index)
}

/// Helper function to calculate the log index specific to a transaction.  It is
/// used to translate the global log index (index in the block) to a transaction
/// specific index.
fn calculate_tx_log_index(log: &Log, receipts: &[TransactionReceipt]) -> u64 {
    if let Some(tx_log_index) = log.transaction_log_index {
        return tx_log_index.as_u64();
    }

    let log_index = log.log_index.unwrap().as_u64();
    let tx_index = log.transaction_index.unwrap().as_u64();

    let mut logs_before_tx = 0;
    for idx in 0..tx_index {
        logs_before_tx += receipts.get(idx as usize).unwrap().logs.len();
    }

    log_index - logs_before_tx as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::consensus::BeaconBlockAlias;
    use ethers::types::{Block, Transaction, H256, U256, U64};
    use std::{fs::File, str::FromStr};

    fn create_test_log(tx_index: u64, log_index: u64) -> Log {
        Log {
            transaction_index: Some(U64::from(tx_index)),
            transaction_hash: Some(H256::from_low_u64_be(tx_index)),
            log_index: Some(U256::from(log_index)),
            ..Default::default()
        }
    }

    fn create_test_receipts() -> Vec<TransactionReceipt> {
        fn generate_logs(n: u64) -> Vec<Log> {
            let mut logs = Vec::new();
            for _ in 0..n {
                logs.push(Default::default())
            }
            logs
        }

        vec![
            TransactionReceipt {
                transaction_hash: H256::from_low_u64_be(1),
                transaction_index: U64::from_str("1").unwrap(),
                logs: generate_logs(10),
                ..Default::default()
            },
            TransactionReceipt {
                transaction_hash: H256::from_low_u64_be(2),
                transaction_index: U64::from_str("2").unwrap(),
                logs: generate_logs(20),
                ..Default::default()
            },
            TransactionReceipt {
                transaction_hash: H256::from_low_u64_be(3),
                transaction_index: U64::from_str("3").unwrap(),
                logs: generate_logs(30),
                ..Default::default()
            },
        ]
    }

    fn create_test_block_details() -> FullBlockDetails {
        FullBlockDetails {
            exec_block: Block::<Transaction>::default(),
            beacon_block: BeaconBlockAlias::default(),
            receipts: create_test_receipts(),
        }
    }

    #[test]
    fn test_parse_enriched_log() {
        let file = File::open("testdata/contract_call.json").unwrap();
        let enriched_log = serde_json::from_reader(file).unwrap();
        let block_details = create_test_block_details();

        let result = parse_enriched_log(&enriched_log, &block_details, 1);
        assert!(result.is_ok());
        let enriched_content = result.unwrap();

        assert_eq!(enriched_content.exec_block, block_details.exec_block);
        assert_eq!(enriched_content.beacon_block, block_details.beacon_block);
        assert_eq!(enriched_content.receipts, block_details.receipts);
        assert_eq!(
            enriched_content.tx_hash,
            enriched_log.log.transaction_hash.unwrap()
        );
        match enriched_content.content {
            ContentVariant::Message(message) => {
                assert_eq!(message.cc_id.chain.to_string(), "ethereum");
                assert_eq!(
                    message.cc_id.id.to_string(),
                    format!("0x{:x}:{}", enriched_log.log.transaction_hash.unwrap(), 5)
                );
            }
            _ => panic!("Unexpected content variant"),
        }
    }

    #[test]
    fn test_enrich_content() {
        let content = ContentVariant::Message(Message {
            cc_id: CrossChainId {
                chain: "ethereum".parse().unwrap(),
                id: "0x1234".parse().unwrap(),
            },
            source_address: "0x00".parse().unwrap(),
            destination_address: "0x01".parse().unwrap(),
            payload_hash: Default::default(),
            destination_chain: "polygon".parse().unwrap(),
        });
        let block_details = create_test_block_details();
        let log = create_test_log(0, 5);
        let enriched_content = enrich_content(&content, &log, &block_details, 1).unwrap();

        assert_eq!(enriched_content.exec_block, block_details.exec_block);
        assert_eq!(enriched_content.beacon_block, block_details.beacon_block);
        assert_eq!(enriched_content.receipts, block_details.receipts);
        assert_eq!(enriched_content.tx_hash, log.transaction_hash.unwrap());
        assert_eq!(enriched_content.content, content);
    }

    #[test]
    fn test_calculate_tx_log_index() {
        let receipts = create_test_receipts();

        let log = create_test_log(0, 2);
        let tx_log_index = calculate_tx_log_index(&log, &receipts);
        assert_eq!(tx_log_index, 2);

        let log = create_test_log(1, 15);
        let tx_log_index = calculate_tx_log_index(&log, &receipts);
        assert_eq!(tx_log_index, 5);

        let log = create_test_log(2, 39);
        let tx_log_index = calculate_tx_log_index(&log, &receipts);
        assert_eq!(tx_log_index, 9);

        let log = create_test_log(3, 60);
        let tx_log_index = calculate_tx_log_index(&log, &receipts);
        assert_eq!(tx_log_index, 0);
    }

    #[test]
    fn test_generate_cc_id() {
        let receipts = create_test_receipts();

        let log = create_test_log(0, 2);
        let id = generate_id(&log, &receipts);
        assert_eq!(id, format!("0x{:x}:{}", log.transaction_hash.unwrap(), 2));

        let log = create_test_log(1, 12);
        let id = generate_id(&log, &receipts);
        assert_eq!(id, format!("0x{:x}:{}", log.transaction_hash.unwrap(), 2));

        let log = create_test_log(2, 35);
        let id = generate_id(&log, &receipts);
        assert_eq!(id, format!("0x{:x}:{}", log.transaction_hash.unwrap(), 5))
    }
}
