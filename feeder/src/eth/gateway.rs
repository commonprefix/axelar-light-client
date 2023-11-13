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
    pub fn new(endpoint: &str, address: &str) -> Self {
        let address = address.parse::<Address>().unwrap();

        let provider = Provider::<Http>::try_from(endpoint).unwrap();
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
}
