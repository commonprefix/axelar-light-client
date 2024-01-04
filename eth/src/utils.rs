use std::sync::Arc;
use crate::{consensus::EthBeaconAPI, execution::EthExecutionAPI, types::FullBlockDetails};
use eyre::{Result, eyre, Context};

pub fn calc_slot_from_timestamp(genesis_time: u64, timestamp: u64) -> u64 {
    (timestamp - genesis_time) / 12
}

pub async fn get_full_block_details<CR: EthBeaconAPI, ER: EthExecutionAPI>(
    consensus: Arc<CR>,
    execution: Arc<ER>,
    block_number: u64,
    genesis_time: u64
) -> Result<FullBlockDetails> {
    let exec_block = execution
        .get_block_with_txs(block_number)
        .await
        .wrap_err(format!("failed to get exec block {}", block_number))?
        .ok_or_else(|| eyre!("could not find execution block {:?}", block_number))?;

    println!("Got execution block with timestamp {}", exec_block.timestamp);
    let block_slot = calc_slot_from_timestamp(genesis_time, exec_block.timestamp.as_u64());

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
    use crate::utils::calc_slot_from_timestamp;

    #[test]
    fn test_calc_slot_from_timestamp() {
        let timestamp = 1000 + 24;
        let expected_slot = 2;
        assert_eq!(calc_slot_from_timestamp(1000, timestamp), expected_slot);
    }
}
