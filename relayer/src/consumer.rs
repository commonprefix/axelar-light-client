use eth::consensus::{ConsensusRPC, EthBeaconAPI};
use eth::execution::{EthExecutionAPI, ExecutionRPC};
use ethers::abi::{Bytes, RawLog};
use ethers::prelude::EthEvent;
use ethers::providers::Middleware;
use ethers::types::{Address, Log, H256, U256, H160};
use ethers::types::{Block, Filter, Transaction, TransactionReceipt};
use eyre::Result;
use eyre::{eyre, Context};
use futures::future::join_all;
use prover::prover::types::EnrichedContent;
use std::sync::Arc;

use crate::types::{ContractCallWithToken, EnrichedLog};

pub struct Gateway {
    consensus: Arc<ConsensusRPC>,
    execution: Arc<ExecutionRPC>,
    address: Address,
}
impl Gateway {
    pub fn new(
        consensus: Arc<ConsensusRPC>,
        execution: Arc<ExecutionRPC>,
        address: String,
    ) -> Self {
        let address = address.parse::<Address>().unwrap();

        Self {
            consensus,
            execution,
            address,
        }
    }

    pub async fn get_contract_call_with_token_messages(
        &self,
        from_block: u64,
        to_block: u64,
        limit: u64,
    ) -> Result<Vec<EnrichedLog>> {
        let logs = self
            .get_contract_call_with_token_logs(from_block, to_block, limit)
            .await?;
        println!("Got logs {:?}", logs.len());

        let enriched_logs = logs.iter().map(|log|
            EnrichedLog {
                log: log.clone(),
                event_name: "ContractCallWithToken".to_string(),
                contract_name: "gateway".to_string(),
                chain: "ethereum".to_string(),
                source: "source".to_string(),
                tx_to: H160::default(),

        }).collect();

        Ok(enriched_logs)
    }

    async fn get_contract_call_with_token_logs(
        &self,
        from_block: u64,
        to_block: u64,
        limit: u64,
    ) -> Result<Vec<Log>> {
        let signature = "ContractCallWithToken(address,string,string,bytes32,bytes,string,uint256)";

        let filter = Filter::new()
            .address(self.address)
            .event(signature)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.execution.provider.get_logs(&filter).await?;
        println!("Got logs {:?}", logs.len());

        let mut limited = vec![];
        for i in 0..limit {
            limited.push(logs[i as usize].clone());
        }

        Ok(limited)
    }

    pub async fn get_logs_in_slot_range(
        &self,
        from_slot: u64,
        to_slot: u64,
        limit: u64,
    ) -> Result<Vec<EnrichedLog>> {
        let beacon_block_from = self.consensus.get_beacon_block(from_slot).await?;
        let beacon_block_to = self.consensus.get_beacon_block(to_slot).await?;
        println!("Got beacon blocks {}, {}", beacon_block_from.slot, beacon_block_to.slot);

        let messages = self
            .get_contract_call_with_token_messages(
                beacon_block_from.body.execution_payload.block_number,
                beacon_block_to.body.execution_payload.block_number,
                limit,
            )
            .await?;

        Ok(messages)
    }
}
