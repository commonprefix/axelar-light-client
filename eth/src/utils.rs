const GENESIS_TIME: u64 = 1606824023;

pub fn calc_slot_from_timestamp(timestamp: u64) -> u64 {
    (timestamp - GENESIS_TIME) / 12
}

pub fn calc_timestamp_from_slot(slot: u64) -> u64 {
    (slot * 12) + GENESIS_TIME
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