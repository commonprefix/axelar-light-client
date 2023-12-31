use std::sync::Arc;
use crate::{consensus::{ConsensusRPC, EthBeaconAPI}, execution::{ExecutionRPC, EthExecutionAPI}, types::FullBlockDetails};
use eyre::{Result, eyre, Context};

const GENESIS_TIME: u64 = 1616508000;

pub fn calc_slot_from_timestamp(timestamp: u64) -> u64 {
    (timestamp - GENESIS_TIME) / 12
}

pub fn calc_timestamp_from_slot(slot: u64) -> u64 {
    (slot * 12) + GENESIS_TIME
}

pub async fn get_full_block_details(
    consensus: Arc<ConsensusRPC>,
    execution: Arc<ExecutionRPC>,
    block_number: u64,
) -> Result<FullBlockDetails> {
    let exec_block = execution
        .get_block_with_txs(block_number)
        .await
        .wrap_err(format!("failed to get exec block {}", block_number))?
        .ok_or_else(|| eyre!("could not find execution block {:?}", block_number))?;

    println!("Got execution block with timestamp {}", exec_block.timestamp);
    let block_slot = calc_slot_from_timestamp(exec_block.timestamp.as_u64());

    let beacon_block = consensus
        .get_beacon_block(block_slot)
        .await
        .wrap_err(eyre!("failed to get beacon block {}", block_number))?;

    let receipts = execution.get_block_receipts(block_number).await?;

    let full_block = FullBlockDetails {
        exec_block,
        beacon_block,
        receipts,
    };

    Ok(full_block)
}

#[cfg(test)]
mod tests {
    use crate::utils::{calc_slot_from_timestamp, calc_timestamp_from_slot};

    #[test]
    fn test_calc_slot_from_timestamp() {
        let timestamp = 1606824023 + 24;
        let expected_slot = 2;
        assert_eq!(calc_slot_from_timestamp(timestamp), expected_slot);
    }

    #[test]
    fn test_calc_timestamp_from_slot() {
        let slot = 2; // Example slot
        let expected_timestamp = 1606824023 + 24; // Expected timestamp for this slot
        assert_eq!(calc_timestamp_from_slot(slot), expected_timestamp);
    }
}
