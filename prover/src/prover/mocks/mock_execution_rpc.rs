use std::fs::File;

use crate::eth::execution::ExecutionAPI;
use async_trait::async_trait;
use ethers::types::{Block, Filter, Log, Transaction, TransactionReceipt, H256, U64};
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

    async fn get_block(&self, _block_number: u64) -> Result<Option<Block<H256>>> {
        unimplemented!();
    }
    async fn get_blocks(&self, _block_numbers: &[u64]) -> Result<Vec<Option<Block<H256>>>> {
        unimplemented!();
    }
    async fn get_latest_block_number(&self) -> Result<U64> {
        unimplemented!();
    }
    async fn get_logs(&self, _filter: &Filter) -> Result<Vec<Log>> {
        unimplemented!();
    }
}
