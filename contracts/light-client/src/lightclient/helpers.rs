use std::{
    fmt::{self},
    sync::Arc,
};

use alloy_dyn_abi::EventExt;
use alloy_json_abi::{AbiItem, JsonAbi};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use cosmwasm_std::StdError;
use eyre::Result;
use types::alloy_primitives::{Bytes, FixedBytes, Log};
use types::alloy_rlp::encode;

use crate::ContractError;
use hasher::{Hasher, HasherKeccak};
use types::execution::{ReceiptLogs, RECEIPTS_ROOT_GINDEX};
use types::proofs::{AncestryProof, ReceiptProof, TransactionProof};
use types::ssz_rs::{
    get_generalized_index, is_valid_merkle_branch, verify_merkle_proof, GeneralizedIndex,
    Merkleized, Node, SszVariableOrIndex, Vector,
};
use types::sync_committee_rs::consensus_types::BeaconBlockHeader;
use types::sync_committee_rs::constants::{Bytes32, Root, SLOTS_PER_HISTORICAL_ROOT};
use types::{
    execution::{ContractCallBase, ReceiptLog},
    lightclient::Message,
};

pub fn is_proof_valid<L: Merkleized>(
    state_root: &Node,
    leaf_object: &mut L,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
) -> bool {
    let res: Result<bool> = (move || {
        let leaf_hash = leaf_object.hash_tree_root()?;
        let branch = branch_to_nodes(branch.to_vec())?;

        let is_valid = is_valid_merkle_branch(&leaf_hash, branch.iter(), depth, index, state_root);
        Ok(is_valid)
    })();

    if let Ok(is_valid) = res {
        is_valid
    } else {
        false
    }
}

pub fn verify_trie_proof(root: Root, key: u64, proof: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    if let Ok(res) = trie.verify_proof(root.as_bytes(), &encode(key), proof) {
        return res;
    }
    None
}

pub fn verify_ancestry_proof(
    proof: &AncestryProof,
    target_block: &BeaconBlockHeader,
    recent_block: &BeaconBlockHeader,
) -> Result<()> {
    let target_block_root = target_block.clone().hash_tree_root()?;

    match proof {
        AncestryProof::BlockRoots {
            block_roots_index,
            block_root_proof,
        } => verify_block_roots_proof(
            block_roots_index,
            block_root_proof,
            &target_block_root,
            &recent_block.state_root,
        ),
        AncestryProof::HistoricalRoots {
            block_root_proof,
            block_summary_root_proof,
            block_summary_root,
            block_summary_root_gindex,
        } => verify_historical_roots_proof(
            block_root_proof,
            block_summary_root_proof,
            block_summary_root,
            block_summary_root_gindex,
            target_block,
            &recent_block.state_root,
        ),
    }
}

pub fn verify_block_roots_proof(
    block_roots_index: &u64,
    block_root_proof: &Vec<Node>,
    leaf_root: &Node,
    root: &Node,
) -> Result<()> {
    // TODO: compute gindex
    if !verify_merkle_proof(
        leaf_root,
        block_root_proof.as_slice(),
        &GeneralizedIndex(*block_roots_index as usize),
        root,
    ) {
        return Err(ContractError::InvalidBlockRootsProof.into());
    }
    Ok(())
}

pub fn verify_historical_roots_proof(
    block_root_proof: &Vec<Node>,
    block_summary_root_proof: &Vec<Node>,
    block_summary_root: &Root,
    block_summary_root_gindex: &u64,
    target_block: &BeaconBlockHeader,
    recent_block_state_root: &Node,
) -> Result<()> {
    let target_block_root = target_block.clone().hash_tree_root()?;

    let block_root_index = target_block.slot as usize % SLOTS_PER_HISTORICAL_ROOT;
    let block_root_gindex = get_generalized_index(
        &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
        &[SszVariableOrIndex::Index(block_root_index)],
    );

    verify_block_roots_proof(
        &(block_root_gindex as u64),
        block_root_proof,
        &target_block_root,
        block_summary_root,
    )?;

    let valid_block_summary_root_proof = verify_merkle_proof(
        block_summary_root,
        block_summary_root_proof.as_slice(),
        &GeneralizedIndex(*block_summary_root_gindex as usize),
        recent_block_state_root,
    );

    if !valid_block_summary_root_proof {
        return Err(ContractError::InvalidBlockSummaryRootProof.into());
    }
    Ok(())
}

pub fn extract_logs_from_receipt_proof(
    proof: &ReceiptProof,
    transaction_index: u64,
    target_block_root: &Node,
) -> Result<ReceiptLogs> {
    if !verify_merkle_proof(
        &proof.receipts_root,
        &proof.receipts_root_proof,
        &GeneralizedIndex(RECEIPTS_ROOT_GINDEX),
        target_block_root,
    ) {
        return Err(ContractError::InvalidReceiptsBranchProof.into());
    }

    let receipt_option = verify_trie_proof(
        proof.receipts_root,
        transaction_index,
        proof.receipt_proof.clone(),
    );

    let receipt = match receipt_option {
        Some(s) => s,
        None => return Err(ContractError::InvalidReceiptProof.into()),
    };

    parse_logs_from_receipt(&receipt)
}

pub fn parse_logs_from_receipt(receipt: &[u8]) -> Result<ReceiptLogs> {
    let logs: ReceiptLogs = types::alloy_rlp::Decodable::decode(&mut &receipt[..])?;
    Ok(logs)
}

pub fn verify_transaction_proof(proof: &TransactionProof, target_block_root: &Node) -> Result<()> {
    if !verify_merkle_proof(
        &proof.transaction.clone().hash_tree_root()?,
        proof.transaction_proof.as_slice(),
        &GeneralizedIndex(proof.transaction_gindex as usize),
        target_block_root,
    ) {
        return Err(ContractError::InvalidTransactionProof.into());
    }
    Ok(())
}

pub fn parse_log(log: &ReceiptLog) -> Result<ContractCallBase, StdError> {
    let abi = JsonAbi::parse([
        "event ContractCall(address indexed sender,string destinationChain,string destinationContractAddress,bytes32 indexed payloadHash,bytes payload)",
        "event ContractCallWithToken(address indexed sender,string destinationChain,string destinationContractAddress,bytes32 indexed payloadHash,bytes payload,string symbol,uint256 amount)"])
        .unwrap();
    for item in abi.items() {
        if let AbiItem::Event(e) = item {
            let hasher = HasherKeccak::new();
            if log.topics.first().map_or(false, |t| {
                t.as_ref() == hasher.digest(e.signature().as_bytes())
            }) {
                let topics: Vec<FixedBytes<32>> = log.topics.iter().map(FixedBytes::from).collect();

                // TODO: unchecked -> checked
                // TODO: set validate = true
                let decoded = e
                    .decode_log(
                        &Log::new_unchecked(topics, Bytes::from(log.data.clone())),
                        false,
                    )
                    .map_err(|e| StdError::GenericErr { msg: e.to_string() })?;

                let mut indexed_consumed = 0;
                let mut base = ContractCallBase {
                    source_address: None,
                    destination_chain: None,
                    destination_address: None,
                    payload_hash: None,
                };
                for (idx, param) in e.inputs.iter().enumerate() {
                    let value = if param.indexed {
                        decoded.indexed.get(indexed_consumed).cloned()
                    } else {
                        decoded.body.get(idx - indexed_consumed).cloned()
                    };

                    if let Some(value) = value {
                        match param.name.as_str() {
                            "sender" => {
                                base.source_address = Some(value.as_address().unwrap_or_default())
                            }
                            "destinationChain" => {
                                base.destination_chain =
                                    Some(value.as_str().unwrap_or_default().to_string());
                            }
                            "destinationContractAddress" => {
                                base.destination_address =
                                    Some(value.as_str().unwrap_or_default().to_string());
                            }
                            "payloadHash" => {
                                let payload: [u8; 32] = value
                                    .as_fixed_bytes()
                                    .unwrap_or_default()
                                    .0
                                    .try_into()
                                    .map_err(|_| StdError::GenericErr {
                                        msg: "Invalid conversion of payload to [u8; 32]"
                                            .to_string(),
                                    })?;
                                base.payload_hash = Some(payload);
                            }
                            _ => {}
                        }
                    }

                    if param.indexed {
                        indexed_consumed += 1
                    }
                }
                return Ok(base);
            }
        }
    }
    Err(StdError::GenericErr {
        msg: "Couldn't match an event to decode the log".to_string(),
    })
}

pub fn verify_message(message: &Message, log: &ReceiptLog, transaction: &Vec<u8>) -> bool {
    let hasher = HasherKeccak::new();
    let transaction_hash = hex::encode(hasher.digest(transaction.as_slice()));

    // TODO: don't hardcode
    let gateway_address =
        hex::decode("4f4495243837681061c4743b74b3eedf548d56a5").unwrap_or_default();
    let message_id = message.cc_id.id.split(':').collect::<Vec<&str>>();
    let message_tx_hash = message_id[0].strip_prefix("0x").unwrap_or_default();

    let event = parse_log(log).unwrap_or_default();
    // println!("{:?}", log);

    // TODO: verify that values are not empty
    message_tx_hash == transaction_hash
        && gateway_address == log.address
        && *message.source_address.to_string().to_lowercase()
            == event
                .source_address
                .unwrap_or_default()
                .to_string()
                .to_lowercase()
        && String::from(message.destination_chain.clone()).to_lowercase()
            == event.destination_chain.unwrap_or_default().to_lowercase()
        && *message.destination_address.to_string().to_lowercase()
            == event.destination_address.unwrap_or_default().to_lowercase()
        && message.payload_hash == event.payload_hash.unwrap_or_default()
}

pub fn branch_to_nodes(branch: Vec<Bytes32>) -> Result<Vec<Node>> {
    branch
        .iter()
        .map(bytes32_to_node)
        .collect::<Result<Vec<Node>>>()
}

pub fn bytes32_to_node(bytes: &Bytes32) -> Result<Node> {
    Ok(Node::try_from(bytes.as_slice())?)
}

pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(stripped)?)
}

pub fn calc_sync_period(slot: u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}

pub fn from_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> serde::de::Visitor<'de> for HexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing hex bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            hex::decode(value.trim_start_matches("0x"))
                .map_err(|err| E::custom(format!("failed to decode hex: {}", err)))
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

pub fn from_hex_array<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexArrayVisitor;

    impl<'de> serde::de::Visitor<'de> for HexArrayVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of strings representing hex bytes")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(hex_str) = seq.next_element::<String>()? {
                // Adjusted to expect owned String values
                let bytes = hex::decode(hex_str.trim_start_matches("0x")).map_err(|err| {
                    serde::de::Error::custom(format!("failed to decode hex: {}", err))
                })?;
                vec.push(bytes);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_seq(HexArrayVisitor)
}

pub fn to_hex_array<S>(bytes_array: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(bytes_array.len()))?;

    for bytes in bytes_array {
        let hex_str = hex::encode(bytes);
        seq.serialize_element(&hex_str)?;
    }

    // End the sequence and return the result.
    seq.end()
}

pub fn to_hex_string<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_str = hex::encode(bytes);
    serializer.serialize_str(&hex_str)
}

#[cfg(test)]
pub mod test_helpers {
    use std::fs::File;

    use ssz_rs::Node;
    use types::lightclient::MessageVerification;
    use types::{
        common::{ChainConfig, Fork, Forks},
        consensus::{Bootstrap, Update},
    };

    use super::hex_str_to_bytes;

    pub fn get_bootstrap() -> Bootstrap {
        let file = File::open("testdata/bootstrap.json").unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();

        bootstrap
    }

    // Currently have in testdata: 767, 862, 863
    pub fn get_update(period: u64) -> Update {
        let path = format!("testdata/{}.json", period);
        let file = File::open(path).unwrap();
        let update: Update = serde_json::from_reader(file).unwrap();

        update
    }

    pub fn get_verification_data_with_block_roots() -> (Bootstrap, MessageVerification) {
        let verification_file =
            File::open(format!("testdata/verification/finality_block_roots.json")).unwrap();
        let verification_data: MessageVerification =
            serde_json::from_reader(verification_file).unwrap();

        let bootstrap_file =
            File::open(format!("testdata/verification/bootstrap_block_roots.json")).unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(bootstrap_file).unwrap();
        (bootstrap, verification_data)
    }

    pub fn get_verification_data_with_historical_roots() -> (Bootstrap, MessageVerification) {
        let verification_file = File::open(format!(
            "testdata/verification/finality_historical_roots.json"
        ))
        .unwrap();
        let verification_data: MessageVerification =
            serde_json::from_reader(verification_file).unwrap();

        let bootstrap_file =
            File::open(format!("testdata/verification/bootstrap_block_roots.json")).unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(bootstrap_file).unwrap();
        (bootstrap, verification_data)
    }

    pub fn get_config() -> ChainConfig {
        let genesis_root_bytes: [u8; 32] =
            hex_str_to_bytes("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .unwrap()
                .try_into()
                .unwrap();

        ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
            genesis_root: Node::from_bytes(genesis_root_bytes),
            forks: get_forks(),
        }
    }

    pub fn get_forks() -> Forks {
        Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: hex_str_to_bytes("0x00000000").unwrap().try_into().unwrap(),
            },
            altair: Fork {
                epoch: 74240,
                fork_version: hex_str_to_bytes("0x01000000").unwrap().try_into().unwrap(),
            },
            bellatrix: Fork {
                epoch: 144896,
                fork_version: hex_str_to_bytes("0x02000000").unwrap().try_into().unwrap(),
            },
            capella: Fork {
                epoch: 194048,
                fork_version: hex_str_to_bytes("0x03000000").unwrap().try_into().unwrap(),
            },
        }
    }
}