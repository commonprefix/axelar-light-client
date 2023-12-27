use alloy_primitives::Address;
use alloy_rlp::{Buf, Decodable};
use eyre::Result;
use serde::Deserialize;
use ssz_rs::prelude::*;
use std::cmp::Ordering;

pub const RECEIPTS_ROOT_GINDEX: usize = 3219;

#[derive(Default, Debug, Clone, Deserialize)]
pub struct ReceiptLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct ContractCallBase {
    pub source_address: Option<Address>,
    pub destination_chain: Option<String>,
    pub destination_address: Option<String>,
    pub payload_hash: Option<[u8; 32]>,
}

#[derive(Default, Debug)]
pub struct ReceiptLogs(pub Vec<ReceiptLog>);

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

                    log.data = Vec::from(alloy_rlp::Header::decode_bytes(b, false)?);

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
