use std::fs::File;

use crate::eth::execution::ExecutionAPI;
use async_trait::async_trait;
use ethers::types::{Block, Filter, Log, Transaction, TransactionReceipt, H256, U256, U64};
use eyre::Result;

pub struct MockExecutionRPC;

#[allow(dead_code)]
impl MockExecutionRPC {
    pub fn new() -> Self {
        MockExecutionRPC {}
    }
}

#[async_trait]
impl ExecutionAPI for MockExecutionRPC {
    async fn get_block_receipts(&self, block_number: u64) -> Result<Vec<TransactionReceipt>> {
        let filename = format!(
            "./src/prover/testdata/execution_blocks/receipts/{}.json",
            block_number
        );
        let file = File::open(filename).unwrap();
        let res: Vec<TransactionReceipt> = serde_json::from_reader(file).unwrap();
        Ok(res)
    }

    async fn get_block_with_txs(&self, block_number: u64) -> Result<Option<Block<Transaction>>> {
        let filename = format!(
            "./src/prover/testdata/execution_blocks/{}.json",
            block_number
        );
        println!("{}", filename);
        let file = File::open(filename).unwrap();
        let res: Option<Block<Transaction>> = Some(serde_json::from_reader(file).unwrap());
        Ok(res)
    }

    async fn get_block(&self, block_number: u64) -> Result<Option<Block<H256>>> {
        unimplemented!();
    }
    async fn get_transaction_receipt(&self, tx_hash: &H256) -> Result<Option<TransactionReceipt>> {
        unimplemented!();
    }
    async fn get_blocks(&self, block_numbers: &[u64]) -> Result<Vec<Option<Block<H256>>>> {
        unimplemented!();
    }
    async fn get_latest_block_number(&self) -> Result<U64> {
        unimplemented!();
    }
    async fn get_transaction(&self, tx_hash: &H256) -> Result<Option<Transaction>> {
        unimplemented!();
    }
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        unimplemented!();
    }
    async fn get_filter_changes(&self, filter_id: &U256) -> Result<Vec<Log>> {
        unimplemented!();
    }
    async fn uninstall_filter(&self, filter_id: &U256) -> Result<bool> {
        unimplemented!();
    }
    async fn get_new_filter(&self, filter: &Filter) -> Result<U256> {
        unimplemented!();
    }
    async fn chain_id(&self) -> Result<u64> {
        unimplemented!();
    }
}
