const GENESIS_TIME: u64 = 1606824023;

pub fn calc_slot_from_timestamp(timestamp: u64) -> u64 {
    (timestamp - GENESIS_TIME) / 12
}

pub fn calc_timestamp_from_slot(slot: u64) -> u64 {
    (slot * 12) + GENESIS_TIME
}
