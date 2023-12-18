use ssz_rs::SszVariableOrIndex;

pub fn parse_path(path: &Vec<SszVariableOrIndex>) -> String {
    let mut path_str = String::new();
    for p in path {
        match p {
            SszVariableOrIndex::Name(name) => path_str.push_str(&format!(",{}", name)),
            SszVariableOrIndex::Index(index) => path_str.push_str(&format!(",{}", index)),
        }
    }
    path_str[1..].to_string() // remove first comma
}

fn get_tx_index(&self, receipts: &[TransactionReceipt], tx_hash: &str) -> Result<u64> {
    let tx_index = receipts
        .iter()
        .position(|r| format!("0x{:x}", r.transaction_hash) == tx_hash);

    match tx_index {
        Some(index) => Ok(index as u64),
        None => Err(anyhow!("Transaction not found in receipts. {:?}", tx_hash)),
    }
}

fn get_tx_hash_from_cc_id(&self, receipts: &[TransactionReceipt], tx_hash: &str) -> Result<u64> {
    let tx_index = receipts
        .iter()
        .position(|r| format!("0x{:x}", r.transaction_hash) == tx_hash);

    match tx_index {
        Some(index) => Ok(index as u64),
        None => Err(anyhow!("Transaction not found in receipts. {:?}", tx_hash)),
    }
}
