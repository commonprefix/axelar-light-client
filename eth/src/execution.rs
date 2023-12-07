use std::str::FromStr;

use async_trait::async_trait;
use ethers::prelude::Http;
use ethers::providers::{HttpRateLimitRetryPolicy, Middleware, Provider, RetryClient};
use ethers::types::{Block, Filter, Log, Transaction, TransactionReceipt, H256, U64};
use eyre::Result;

use crate::error::RpcError;

#[async_trait]
pub trait ExecutionAPI {
    async fn get_block_receipts(&self, block_number: u64) -> Result<Vec<TransactionReceipt>>;
    async fn get_block(&self, block_number: u64) -> Result<Option<Block<H256>>>;
    async fn get_block_with_txs(&self, block_number: u64) -> Result<Option<Block<Transaction>>>;
    async fn get_blocks(&self, block_numbers: &[u64]) -> Result<Vec<Option<Block<H256>>>>;
    async fn get_latest_block_number(&self) -> Result<U64>;
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>>;
}

pub struct ExecutionRPC {
    pub provider: Provider<RetryClient<Http>>,
}

impl ExecutionRPC {
    pub fn new(rpc: String) -> Self {
        let http = Http::from_str(rpc.as_str()).expect("Could not initialize HTTP provider");
        let mut client = RetryClient::new(http, Box::new(HttpRateLimitRetryPolicy), 100, 50);
        client.set_compute_units(300);

        let provider = Provider::new(client);

        ExecutionRPC { provider }
    }
}

#[async_trait]
impl ExecutionAPI for ExecutionRPC {
    async fn get_block_receipts(&self, block_number: u64) -> Result<Vec<TransactionReceipt>> {
        let block_receipts = self.provider.get_block_receipts(block_number).await?;

        Ok(block_receipts)
    }

    async fn get_block(&self, block_number: u64) -> Result<Option<Block<H256>>> {
        let block = self
            .provider
            .get_block(block_number)
            .await
            .map_err(|e| RpcError::new("get_block", e))?;

        Ok(block)
    }

    async fn get_block_with_txs(&self, block_number: u64) -> Result<Option<Block<Transaction>>> {
        let block = self
            .provider
            .get_block_with_txs(block_number)
            .await
            .map_err(|e| RpcError::new("get_block", e))?;

        Ok(block)
    }

    async fn get_blocks(&self, block_numbers: &[u64]) -> Result<Vec<Option<Block<H256>>>> {
        let mut futures = vec![];
        for &block_number in block_numbers {
            futures.push(async move { self.get_block(block_number).await });
        }

        let results: Result<Vec<_>, _> = futures::future::try_join_all(futures).await;
        results
    }

    async fn get_latest_block_number(&self) -> Result<U64> {
        Ok(self
            .provider
            .get_block_number()
            .await
            .map_err(|e| RpcError::new("get_latest_block_number", e))?)
    }

    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        Ok(self
            .provider
            .get_logs(filter)
            .await
            .map_err(|e| RpcError::new("get_logs", e))?)
    }
}
