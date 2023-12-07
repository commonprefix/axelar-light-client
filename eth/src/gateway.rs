use crate::execution::ExecutionAPI;
use crate::types::InternalMessage;
use crate::utils::calc_slot_from_timestamp;
use ethers::abi::{Bytes, RawLog};
use ethers::prelude::{EthEvent, Http};
use ethers::providers::{Middleware, Provider};
use ethers::types::Filter;
use ethers::types::{Address, Log, H256, U256};
use eyre::eyre;
use eyre::Result;
use std::sync::Arc;
use types::lightclient::{CrossChainId, Message};

pub struct Gateway {
    client: Arc<Provider<Http>>,
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
    pub fn new(rpc: String, address: String) -> Self {
        let address = address.parse::<Address>().unwrap();

        let provider = Provider::<Http>::try_from(rpc).unwrap();
        let client = Arc::new(provider);

        Self { client, address }
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

        let messages = logs
            .iter()
            .zip(events)
            .map(|(log, event)| {
                if log.transaction_hash.is_none()
                    || log.log_index.is_none()
                    || log.block_hash.is_none()
                    || log.block_number.is_none()
                {
                    return Err(eyre!("Missing field on log/event: {:?}, {:?}", log, event));
                }

                let tx_hash = log.transaction_hash.unwrap();
                let log_index = log.log_index.unwrap();

                let cc_id = CrossChainId {
                    chain: "ethereum".parse().unwrap(),
                    id: format!("0x{:x}:{}", tx_hash, log_index).parse().unwrap(),
                };

                let msg = InternalMessage {
                    message: Message {
                        cc_id,
                        source_address: format!("0x{:x}", event.sender).parse().unwrap(),
                        destination_chain: event.destination_chain.parse().unwrap(),
                        destination_address: event.destination_contract_address.parse().unwrap(),
                        payload_hash: event.payload_hash.into(),
                    },
                    block_hash: log.block_hash.unwrap(),
                    block_number: log.block_number.unwrap().as_u64(),
                };

                Ok(msg)
            })
            .collect::<Vec<Result<InternalMessage>>>();

        for message in &messages {
            if message.is_err() {
                println!("Failed to decode message: {:?}", message);
            }
        }

        let messages = messages
            .into_iter()
            .filter_map(|message| message.ok())
            .collect::<Vec<InternalMessage>>();
        Ok(messages)
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

        Ok(self.client.get_logs(&filter).await?)
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
        execution: &dyn ExecutionAPI,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<InternalMessage>> {
        // TODO: Move that out of the code
        const BLOCK_RANGE: u64 = 500;
        let latest_block_number = execution.get_latest_block_number().await?;

        let messages = self
            .get_contract_call_with_token_messages(
                latest_block_number.as_u64() - BLOCK_RANGE,
                latest_block_number.as_u64(),
            )
            .await?;

        println!("All messages: {:?}", messages.len());
        let block_heights = messages
            .iter()
            .map(|message| message.block_number)
            .collect::<Vec<u64>>();

        let blocks = execution.get_blocks(&block_heights).await?;

        let filtered_messages = messages
            .into_iter()
            .zip(blocks.iter())
            .filter_map(|(message, block)| {
                block.as_ref().and_then(|block| {
                    let slot = calc_slot_from_timestamp(block.timestamp.as_u64());
                    (slot > from_slot && slot < to_slot).then_some(message)
                })
            })
            .collect::<Vec<InternalMessage>>();

        println!("Messages in range: {:?}", filtered_messages.len());

        Ok(filtered_messages)
    }
}
