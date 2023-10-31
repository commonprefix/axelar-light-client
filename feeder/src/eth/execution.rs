use std::str::FromStr;

use ethers::prelude::Http;
use ethers::providers::{FilterKind, HttpRateLimitRetryPolicy, Middleware, Provider, RetryClient};
use ethers::types::{Filter, Log, Transaction, TransactionReceipt, H256, U256};
use eyre::Result;

use crate::error::RpcError;
pub struct ExecutionRPC {
    provider: Provider<RetryClient<Http>>,
}

#[allow(dead_code)]
impl ExecutionRPC {
    pub fn new(rpc: &str) -> Result<Self> {
        let http = Http::from_str(rpc)?;
        let mut client = RetryClient::new(http, Box::new(HttpRateLimitRetryPolicy), 100, 50);
        client.set_compute_units(300);

        let provider = Provider::new(client);

        Ok(ExecutionRPC { provider })
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &H256,
    ) -> Result<Option<TransactionReceipt>> {
        let receipt = self
            .provider
            .get_transaction_receipt(*tx_hash)
            .await
            .map_err(|e| RpcError::new("get_transaction_receipt", e))?;

        Ok(receipt)
    }

    pub async fn get_transaction(&self, tx_hash: &H256) -> Result<Option<Transaction>> {
        Ok(self
            .provider
            .get_transaction(*tx_hash)
            .await
            .map_err(|e| RpcError::new("get_transaction", e))?)
    }

    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        Ok(self
            .provider
            .get_logs(filter)
            .await
            .map_err(|e| RpcError::new("get_logs", e))?)
    }

    pub async fn get_filter_changes(&self, filter_id: &U256) -> Result<Vec<Log>> {
        Ok(self
            .provider
            .get_filter_changes(filter_id)
            .await
            .map_err(|e| RpcError::new("get_filter_changes", e))?)
    }

    pub async fn uninstall_filter(&self, filter_id: &U256) -> Result<bool> {
        Ok(self
            .provider
            .uninstall_filter(filter_id)
            .await
            .map_err(|e| RpcError::new("uninstall_filter", e))?)
    }

    pub async fn get_new_filter(&self, filter: &Filter) -> Result<U256> {
        Ok(self
            .provider
            .new_filter(FilterKind::Logs(filter))
            .await
            .map_err(|e| RpcError::new("get_new_filter", e))?)
    }

    pub async fn chain_id(&self) -> Result<u64> {
        Ok(self
            .provider
            .get_chainid()
            .await
            .map_err(|e| RpcError::new("chain_id", e))?
            .as_u64())
    }
}
