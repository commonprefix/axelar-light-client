use alloy_rlp::{Buf, Decodable};
use serde;
use ssz_rs::prelude::*;
use std::cmp::Ordering;

use crate::common::{Address, Bytes32};
use crate::primitives::{ByteList, ByteVector, U64};

pub type LogsBloom = ByteVector<256>;
pub type Transaction = ByteList<1073741824>;

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct ExecutionPayload {
    pub parent_hash: Bytes32,
    pub fee_recipient: Address,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: LogsBloom,
    pub prev_randao: Bytes32,
    pub block_number: U64,
    pub gas_limit: U64,
    pub gas_used: U64,
    pub timestamp: U64,
    pub extra_data: ByteList<32>,
    pub base_fee_per_gas: U64,
    pub block_hash: Bytes32,
    pub transactions: List<Transaction, 1048576>,
    pub withdrawals: List<Withdrawal, 16>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct Withdrawal {
    index: U64,
    validator_index: U64,
    address: Address,
    amount: U64,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReceiptLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
}

#[derive(Default)]
pub struct ReceiptLogs(Vec<ReceiptLog>);

impl ReceiptLogs {
    pub fn contains_topic(&self, topic: &[u8]) -> bool {
        if topic.len() != 32 {
            return false; // Or handle this case differently, if necessary
        }

        let topic_array: [u8; 32] = topic.try_into().unwrap();
        for log in &self.0 {
            if log.topics.contains(&topic_array) {
                return true;
            }
        }
        false
    }
}

impl Decodable for ReceiptLogs {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        let rlp_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
            "cannot decode a receipt from empty bytes",
        ))?;

        match rlp_type.cmp(&alloy_rlp::EMPTY_LIST_CODE) {
            Ordering::Less => {
                let _header = alloy_rlp::Header::decode(buf)?;
                let receipt_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
                    "typed receipt cannot be decoded from an empty slice",
                ))?;

                if receipt_type > 3 {
                    return Err(alloy_rlp::Error::Custom("Invalid Receipt Type"));
                }

                let mut logs_list: ReceiptLogs = ReceiptLogs::default();
                buf.advance(1);

                let b = &mut &**buf;
                let rlp_head = alloy_rlp::Header::decode(b)?;
                if !rlp_head.list {
                    return Err(alloy_rlp::Error::UnexpectedString);
                }

                for _i in 0..3 {
                    // skip the first 3 fields: success, cumulative_gas_used, bloom
                    let head = alloy_rlp::Header::decode(b)?;
                    b.advance(head.payload_length);
                }

                let logs_head = alloy_rlp::Header::decode(b)?;
                if !logs_head.list {
                    return Err(alloy_rlp::Error::UnexpectedString);
                }

                while !b.is_empty() {
                    let mut log: ReceiptLog = ReceiptLog::default();
                    let item_head = alloy_rlp::Header::decode(b)?;
                    if !item_head.list {
                        return Err(alloy_rlp::Error::UnexpectedString);
                    }

                    log.address = alloy_rlp::Decodable::decode(b)?;

                    let topic_list_head = alloy_rlp::Header::decode(b)?;
                    for _i in 0..(topic_list_head.payload_length / 32) {
                        log.topics.push(alloy_rlp::Decodable::decode(b)?);
                    }

                    // skip receipt data
                    let data_head = alloy_rlp::Header::decode(b)?;
                    b.advance(data_head.payload_length);

                    logs_list.0.push(log);
                }

                Ok(logs_list)
            }
            Ordering::Equal => Err(alloy_rlp::Error::Custom(
                "an empty list is not a valid receipt encoding",
            )),
            Ordering::Greater => Err(alloy_rlp::Error::Custom("Transaction Type Not Supported")),
        }
    }
}
