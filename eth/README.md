# Types

This package exports connectors for both the beacon and the execution API of
Ethereum. It is being used by the prover for interacting with the Ethereum
chain. 

## Beacon API implementation

```
pub trait EthBeaconAPI {
    /// Get the block root for a given slot.
    async fn get_block_root(&self, slot: u64) -> Result<Root, RPCError>;

    /// Get the light client bootstrap for a given block root.
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap, RPCError>;

    /// Get the light client updates for a given period range.
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>, RPCError>;

    /// Get the latest light client finality update.
    async fn get_finality_update(&self) -> Result<FinalityUpdate, RPCError>;

    /// Get the latest light client optimistic update.
    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate, RPCError>;

    /// Get the beacon block header for a given slot.
    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader, RPCError>;

    /// Get the beacon block header for a given slot.
    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader, RPCError>;
 
    /// Get the beacon block for a given slot.
    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias, RPCError>;

    /// Get the block roots tree for a given start slot. This will return a vector of length
    /// `SLOTS_PER_HISTORICAL_ROOT` with the block roots for the given range. If any of the block

    /// roots fail to resolve, the previous root will be used instead.
    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>, RPCError>;
}
```

## Execution API implementation  

```
pub trait EthExecutionAPI {
    /// Get the receipts for a block
    async fn get_block_receipts(&self, block_number: u64) -> Result<Vec<TransactionReceipt>, ProviderError>;

    /// Get a block by its block number. This method returns the block without the full transactions.
    async fn get_block(&self, block_number: u64) -> Result<Option<Block<H256>>, ProviderError>;

    /// Get a block by its block number. This method returns the block with the full transactions.
    async fn get_block_with_txs(&self, block_number: u64) -> Result<Option<Block<Transaction>>, ProviderError>;

    /// Get multiple blocks by their block numbers.
    async fn get_blocks(&self, block_numbers: &[u64]) -> Result<Vec<Option<Block<H256>>>, ProviderError>;

    /// Get the latest block number.
    async fn get_latest_block_number(&self) -> Result<U64, ProviderError>;

    /// Get logs for a given filter.
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ProviderError>;
}
```
