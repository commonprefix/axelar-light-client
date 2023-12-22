use crate::consensus::{ConsensusRPC, EthBeaconAPI};
use crate::execution::{EthExecutionAPI, ExecutionRPC};
use crate::types::InternalMessage;
use crate::utils::calc_slot_from_timestamp;
use ethers::abi::{Bytes, RawLog};
use ethers::prelude::EthEvent;
use ethers::providers::Middleware;
use ethers::types::{Filter, Transaction, TransactionReceipt, Block};
use ethers::types::{Address, Log, H256, U256};
use eyre::{eyre, Context};
use eyre::Result;
use types::consensus::BeaconBlockAlias;
use std::sync::Arc;
use types::lightclient::{CrossChainId, Message};

pub struct Gateway {
    consensus: Arc<ConsensusRPC>,
    execution: Arc<ExecutionRPC>,
    address: Address,
}

#[derive(Debug, Clone, EthEvent, PartialEq)]
pub struct ContractCallWithToken {
    #[ethevent(indexed)]
    pub sender: Address,
    pub destination_chain: String,
    pub destination_contract_address: String,
    #[ethevent(indexed)]
    pub payload_hash: H256,
    pub payload: Bytes,
    pub symbol: String,
    pub amount: U256,
}

impl Gateway {
    pub fn new(consensus: Arc<ConsensusRPC>, execution: Arc<ExecutionRPC>, address: String) -> Self {
        let address = address.parse::<Address>().unwrap();

        Self { consensus, execution, address }
    }

    pub async fn get_contract_call_with_token_messages(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<InternalMessage>> {
        let logs = self
            .get_contract_call_with_token_logs(from_block, to_block)
            .await?;

        let events = Self::decode_contract_call_with_token_logs(&logs)?;

        let mut messages = Vec::<InternalMessage>::new();

        for (log, event) in logs.iter().zip(events) {
                if log.transaction_hash.is_none()
                    || log.log_index.is_none()
                    || log.transaction_index.is_none()
                    || log.block_hash.is_none()
                    || log.block_number.is_none()
                {
                    println!("Missing fields in log: {:?}", log);
                    continue;
                }

                let tx_hash = log.transaction_hash.unwrap();
                let log_index = log.log_index.unwrap();
                let block_number = log.block_number.unwrap();
                let tx_index = log.transaction_index.unwrap();

                let block_data = self.get_full_block(block_number.as_u64()).await;
                if block_data.is_err() {
                    println!("Failed to get block data for {:?} {:?}", block_number, block_data.err());
                    continue;
                }

                let (exec_block, beacon_block, receipts) = block_data?;

                let transaction_log_index = if log.transaction_index.is_none() {
                    self.calculate_tx_log_index(log_index.as_u64(), tx_index.as_u64(), &receipts)
                } else {
                    log.transaction_index.unwrap().as_u64()
                };

                let cc_id = CrossChainId {
                    chain: "ethereum".parse().unwrap(),
                    id: format!("0x{:x}:{}", tx_hash, transaction_log_index).parse().unwrap(),
                };

                let msg = InternalMessage {
                    message: Message {
                        cc_id,
                        source_address: format!("0x{:x}", event.sender).parse().unwrap(),
                        destination_chain: event.destination_chain.parse().unwrap(),
                        destination_address: event.destination_contract_address.parse().unwrap(),
                        payload_hash: event.payload_hash.into(),
                    },
                    exec_block: exec_block.clone(),
                    beacon_block: beacon_block.clone(),
                    receipts: receipts.clone(),
                    tx_hash,
                };

                messages.push(msg);
        } 

        Ok(messages)
    }

    fn calculate_tx_log_index(&self, log_index: u64, tx_index: u64, receipts: &Vec<TransactionReceipt>) -> u64 {
        let mut logs_before_tx = 0;
        for idx in 0..tx_index {
            logs_before_tx += receipts.get(idx as usize).unwrap().logs.len();
        }

        log_index - logs_before_tx as u64
    }

    async fn get_full_block(&self, block_number: u64) -> Result<(Block<Transaction>, BeaconBlockAlias, Vec<TransactionReceipt>)> {
        let exec_block = self
            .execution
            .get_block_with_txs(block_number)
            .await
            .wrap_err(format!("failed to get exec block {}", block_number))?
            .ok_or_else(|| eyre!("could not find execution block {:?}", block_number))?;

        let block_slot = calc_slot_from_timestamp(exec_block.timestamp.as_u64());

        let beacon_block = self
            .consensus
            .get_beacon_block(block_slot)
            .await
            .wrap_err(eyre!("failed to get beacon block {}", block_number))?;

        let receipts = self.execution.get_block_receipts(block_number).await?;
        
        Ok((exec_block, beacon_block, receipts))
    }

    async fn get_contract_call_with_token_logs(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>> {
        let signature = "ContractCallWithToken(address,string,string,bytes32,bytes,string,uint256)";

        let filter = Filter::new()
            .address(self.address)
            .event(signature)
            .from_block(from_block)
            .to_block(to_block);

        Ok(self.execution.provider.get_logs(&filter).await?)
    }

    fn decode_contract_call_with_token_logs(logs: &Vec<Log>) -> Result<Vec<ContractCallWithToken>> {
        let events = logs
            .clone()
            .into_iter()
            .map(|log| EthEvent::decode_log(&RawLog::from(log)).unwrap())
            .collect::<Vec<ContractCallWithToken>>();

        if events.len() != logs.len() {
            // TODO: Error handling
            panic!("Failed to decode logs");
        }

        Ok(events)
    }

    pub async fn get_messages_in_slot_range(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<InternalMessage>> {
        // TODO: Move that out of the code
        const BLOCK_RANGE: u64 = 500;
        let latest_block_number = self.execution.get_latest_block_number().await?;

        let messages = self
            .get_contract_call_with_token_messages(
                latest_block_number.as_u64() - BLOCK_RANGE,
                latest_block_number.as_u64(),
            )
            .await?;

        println!("All messages: {:?}", messages.len());
        let block_heights = messages
            .iter()
            .map(|message| message.exec_block.number.unwrap().as_u64())
            .collect::<Vec<u64>>();

        let blocks = self.execution.get_blocks(&block_heights).await?;

        let filtered_messages = messages
            .into_iter()
            .zip(blocks.iter())
            .filter_map(|(message, block)| {
                block.as_ref().and_then(|block| {
                    let slot = calc_slot_from_timestamp(block.timestamp.as_u64());
                    (slot >= from_slot && slot < to_slot).then_some(message)
                })
            })
            .collect::<Vec<InternalMessage>>();

        println!("Messages in range: {:?}", filtered_messages.len());

        Ok(filtered_messages)
    }

}
