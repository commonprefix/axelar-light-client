use crate::eth::constants::EXECUTION_RPC;
use crate::eth::execution::ExecutionRPC;
use crate::eth::utils::calc_slot_from_timestamp;
use crate::types::Message;
use ethers::abi::{Bytes, RawLog};
use ethers::prelude::{EthEvent, Http};
use ethers::providers::{Middleware, Provider};
use ethers::types::Filter;
use ethers::types::{Address, Log, H256, U256};
use eyre::Result;
use std::sync::Arc;

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
    pub fn new(rpc: &str, address: &str) -> Self {
        let address = address.parse::<Address>().unwrap();

        let provider = Provider::<Http>::try_from(rpc).unwrap();
        let client = Arc::new(provider);

        return Self { client, address };
    }

    pub async fn get_contract_call_with_token_messages(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Message>> {
        let logs = self
            .get_contract_call_with_token_logs(from_block, to_block)
            .await?;
        let events = Self::decode_contract_call_with_token_logs(&logs)?;

        let messages = logs
            .iter()
            .zip(events)
            .map(|(log, event)| Message {
                block_number: log.block_number.unwrap().as_u64(),
                block_hash: log.block_hash.unwrap(),
                tx_id: log.transaction_hash.unwrap(),
                event_index: log.log_index.unwrap(),
                destination_address: event.destination_contract_address,
                destination_chain: event.destination_chain,
                source_address: event.sender,
                payload_hash: event.payload_hash,
            })
            .collect::<Vec<Message>>();

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
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<Message>> {
        // TODO: Move that out of the code
        const BLOCK_RANGE: u64 = 10000;
        let execution = ExecutionRPC::new(EXECUTION_RPC);
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

        let blocks = execution.get_blocks(&block_heights).await.unwrap();

        let filtered_messages: Vec<Message> = messages
            .into_iter()
            .zip(blocks.iter())
            .filter_map(|(message, block)| {
                block.as_ref().and_then(|block| {
                    let slot = calc_slot_from_timestamp(block.timestamp.as_u64());
                    (slot > from_slot && slot < to_slot).then(|| message)
                })
            })
            .collect();

        println!("Messages in range: {:?}", filtered_messages.len());

        Ok(filtered_messages)
    }
}
