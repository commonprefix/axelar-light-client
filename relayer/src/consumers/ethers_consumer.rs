use crate::types::{EnrichedLog, ContractCallWithToken, OperatorshipTransferred};
use async_trait::async_trait;
use consensus_types::connection_router::events;
use eth::{
    consensus::ConsensusRPC,
    execution::{EthExecutionAPI, ExecutionRPC},
};
use ethers::{types::{Address, H160, Log, Filter}, contract::parse_log, abi::{RawLog, ParseLog}};
use eyre::Result;
use std::sync::Arc;

use super::Amqp;

pub struct EthersConsumer {
    execution: Arc<ExecutionRPC>,
    address: Address,
}

impl EthersConsumer {
    pub fn new(
        consensus: Arc<ConsensusRPC>,
        execution: Arc<ExecutionRPC>,
        address: String,
    ) -> Self {
        let address = address.parse::<Address>().unwrap();

        Self {
            execution,
            address,
        }
    }

    async fn get_logs(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<EnrichedLog>> {
        let signatures = vec![
            "ContractCallWithToken(address,string,string,bytes32,bytes,string,uint256)",
            "OperatorshipTransferred(bytes)"
        ];

        let filter = Filter::new()
            .address(self.address)
            .events(signatures)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.execution.get_logs(&filter).await?;

        let mut enriched_logs = vec![];
        for log in &logs {
            let event_name = if let Ok(_) = parse_log::<ContractCallWithToken>(log.clone()) {
                "ContractCallWithToken"
            } else if let Ok(_) = parse_log::<OperatorshipTransferred>(log.clone()) {
                "OperatorshipTransferred"
            } else {
                continue;
            };

            enriched_logs.push(EnrichedLog {
                log: log.clone(),
                event_name: event_name.to_string(),
                contract_name: "gateway".to_string(),
                chain: "ethereum".to_string(),
                source: "source".to_string(),
                tx_to: H160::default(),
            });
        }


        Ok(enriched_logs)
    }
}

#[async_trait]
impl Amqp for EthersConsumer {
    async fn consume(&mut self, limit: usize) -> Result<Vec<(u64, String)>> {
        let latest_block = self.execution.get_latest_block_number().await?;
        let start_block = latest_block - 9000;

        let mut contents: Vec<_> = self
            .get_logs(
                start_block.as_u64(),
                latest_block.as_u64(),
            )
            .await?;

        // Sort logs by block number in descending order
        contents.sort_by(|a, b| b.log.block_number.cmp(&a.log.block_number));

        let res = contents
            .iter()
            .enumerate()
            .map(|(i, c)| (i as u64, serde_json::to_string(c).unwrap()))
            .take(limit)
            .collect();

        Ok(res)
    }


    async fn ack_delivery(&self, _delivery_id: u64) -> Result<()> {
        Ok(())
    }

    async fn nack_delivery(&self, _delivery_id: u64) -> Result<()> {
        Ok(())
    }

}
