use std::str::FromStr;

use async_trait::async_trait;
use ethers::prelude::Http;
use ethers::providers::{HttpRateLimitRetryPolicy, Middleware, Provider, RetryClient};
use ethers::types::{Block, Filter, Log, Transaction, TransactionReceipt, H256, U64};
use eyre::Result;
use mockall::automock;

use crate::error::RpcError;

#[automock]
#[async_trait]
pub trait EthExecutionAPI {
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

#[automock]
#[async_trait]
impl EthExecutionAPI for ExecutionRPC {
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

#[cfg(test)]
mod tests {
    use ethers::types::{Block, Filter, Log, Transaction, TransactionReceipt, H256, U64};
    use mockall::predicate::eq;

    use crate::execution::{EthExecutionAPI, MockExecutionRPC};

    #[tokio::test]
    async fn test_get_block_receipts() {
        let mut mock = MockExecutionRPC::new();

        // Set up expected behavior
        let expected_receipts = vec![TransactionReceipt::default()];
        mock.expect_get_block_receipts()
            .with(eq(100))
            .times(1)
            .return_once(move |_| Ok(expected_receipts.clone()));

        let result = mock.get_block_receipts(100).await.unwrap();
        assert_eq!(result, vec![TransactionReceipt::default()]);
    }

    #[tokio::test]
    async fn test_get_block() {
        let mut mock = MockExecutionRPC::new();

        let expected_block = Some(Block::<H256>::default());
        let expected_block_clone = expected_block.clone();
        mock.expect_get_block()
            .with(eq(100))
            .times(1)
            .return_once(move |_| Ok(expected_block_clone));

        let result = mock.get_block(100).await.unwrap();
        assert_eq!(result, expected_block);
    }

    #[tokio::test]
    async fn test_get_block_with_txs() {
        let mut mock = MockExecutionRPC::new();

        let expected_block = Some(Block::<Transaction>::default());
        let expected_block_clone = expected_block.clone();

        mock.expect_get_block_with_txs()
            .with(eq(100))
            .times(1)
            .return_once(move |_| Ok(expected_block_clone));

        let result = mock.get_block_with_txs(100).await.unwrap();
        assert_eq!(result, expected_block);
    }

    #[tokio::test]
    async fn test_get_blocks() {
        let mut mock = MockExecutionRPC::new();

        let expected_blocks = vec![Some(Block::<H256>::default())];
        let expected_blocks_clone = expected_blocks.clone(); // Clone the data for the closure

        mock.expect_get_blocks()
            .with(eq(vec![100]))
            .times(1)
            .return_once(move |_| Ok(expected_blocks_clone)); // Use the clone here

        let result = mock.get_blocks(&[100]).await.unwrap();
        assert_eq!(result, expected_blocks);
    }

    #[tokio::test]
    async fn test_get_latest_block_number() {
        let mut mock = MockExecutionRPC::new();

        let expected_block_number = U64::from(100);
        mock.expect_get_latest_block_number()
            .times(1)
            .return_once(move || Ok(expected_block_number));

        let result = mock.get_latest_block_number().await.unwrap();
        assert_eq!(result, U64::from(100));
    }

    #[tokio::test]
    async fn test_get_logs() {
        let mut mock = MockExecutionRPC::new();

        let expected_logs = vec![Log::default()];
        let expected_logs_clone = expected_logs.clone();
        let filter = Filter::default();
        mock.expect_get_logs()
            .with(eq(filter.clone()))
            .times(1)
            .return_once(move |_| Ok(expected_logs_clone));

        let result = mock.get_logs(&filter).await.unwrap();
        assert_eq!(result, expected_logs);
    }
}
