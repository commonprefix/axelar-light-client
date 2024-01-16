use std::sync::Arc;

use alloy_dyn_abi::EventExt;
use alloy_json_abi::{AbiItem, JsonAbi};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use eyre::{eyre, Result};
use types::alloy_primitives::{Bytes, FixedBytes, Log};

use crate::ContractError;
use hasher::{Hasher, HasherKeccak};
use types::alloy_rlp::encode;
use types::common::{ContentVariant, WorkerSetMessage};
use types::connection_router::state::{Message, ID_SEPARATOR};
use types::execution::{ContractCallBase, ReceiptLog};
use types::execution::{
    GatewayEvent, OperatorshipTransferredBase, ReceiptLogs, RECEIPTS_ROOT_GINDEX,
};
use types::proofs::{nonempty, AncestryProof, ReceiptProof, TransactionProof};
use types::ssz_rs::{
    get_generalized_index, is_valid_merkle_branch, verify_merkle_proof, GeneralizedIndex,
    Merkleized, Node, SszVariableOrIndex, Vector,
};
use types::sync_committee_rs::consensus_types::BeaconBlockHeader;
use types::sync_committee_rs::constants::{Bytes32, Root, SLOTS_PER_HISTORICAL_ROOT};

/// Trait implemented from messages to compare with the appropriate event
pub trait Comparison<E> {
    fn compare_with_event(&self, event: E) -> Result<()>;
}

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

/// Verifies an MPT proof. Used to verify that a receipt is included in the receipts MPT.
pub fn verify_trie_proof(root: Root, key: u64, proof: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    if let Ok(res) = trie.verify_proof(root.as_bytes(), &encode(key), proof) {
        return res;
    }
    None
}

/// Verifies that the target block is an ancestor of the recent block. It will use either a historical proof or a block roots proof, depending on how old the target block is.
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

/// Extracts the logs from a receipt after checking that this receipt is part of the target block.
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

/// Parse logs from a given encoded receipt.
pub fn parse_logs_from_receipt(receipt: &[u8]) -> Result<ReceiptLogs> {
    let logs: ReceiptLogs = types::alloy_rlp::Decodable::decode(&mut &receipt[..])?;
    Ok(logs)
}

/// Verify that the transaction is included in the block.
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

/// Given a receipt log and an event, it parses the log into a ContractCall event struct.
pub fn parse_contract_call_event(
    log: &ReceiptLog,
    e: &alloy_json_abi::Event,
) -> Result<GatewayEvent> {
    // let AbiItem::Event(e) = event_item;
    let topics: Vec<FixedBytes<32>> = log.topics.iter().map(FixedBytes::from).collect();
    let alloy_log = Log::new(topics, Bytes::from(log.data.clone()))
        .ok_or_else(|| eyre!("Failed to create log"))?;
    let decoded = e.decode_log(&alloy_log, true)?;

    let mut indexed_consumed = 0;
    let mut base = ContractCallBase::default();
    for (idx, param) in e.inputs.iter().enumerate() {
        let value = if param.indexed {
            decoded.indexed.get(indexed_consumed).cloned()
        } else {
            decoded.body.get(idx - indexed_consumed).cloned()
        };

        if let Some(value) = value {
            match param.name.as_str() {
                "sender" => {
                    let parsed_value = value
                        .as_address()
                        .ok_or_else(|| eyre!("Can't parse 'sender' from topics"))?;
                    base.source_address = Some(parsed_value);
                }
                "destinationChain" => {
                    let parsed_value = value
                        .as_str()
                        .ok_or_else(|| eyre!("Can't parse 'destinationChain' from topics"))?;
                    base.destination_chain = Some(parsed_value.to_string());
                }
                "destinationContractAddress" => {
                    let parsed_value = value.as_str().ok_or_else(|| {
                        eyre!("Can't parse 'destinationContractAddress' from topics")
                    })?;
                    base.destination_address = Some(parsed_value.to_string());
                }
                "payloadHash" => {
                    let (payload_bytes, _) = value
                        .as_fixed_bytes()
                        .ok_or_else(|| eyre!("Can't parse 'payloadHash' from topics"))?;
                    let payload: [u8; 32] = payload_bytes.try_into()?;
                    base.payload_hash = Some(payload);
                }
                _ => {}
            }
        }

        if param.indexed {
            indexed_consumed += 1
        }
    }
    Ok(GatewayEvent::ContactCall(base))
}

/// Given a receipt log and an event, it parses the log into an OperatorshipTransferred event struct.
pub fn parse_operatorship_transferred_event(
    log: &ReceiptLog,
    e: &alloy_json_abi::Event,
) -> Result<GatewayEvent> {
    let topics: Vec<FixedBytes<32>> = log.topics.iter().map(FixedBytes::from).collect();
    let alloy_log = Log::new(topics, Bytes::from(log.data.clone()))
        .ok_or_else(|| eyre!("Failed to create log"))?;
    let decoded = e.decode_log(&alloy_log, true)?;
    let new_operators_data = decoded
        .body
        .first()
        .and_then(|value| value.as_bytes())
        .ok_or_else(|| eyre!("Can't parse 'newOperatorsData' from topics"))?;

    Ok(GatewayEvent::OperatorshipTransferred(
        OperatorshipTransferredBase {
            new_operators_data: Some(Vec::from(new_operators_data)),
        },
    ))
}

/// Parses a log into either a ContractCall or OperatorshipTransferred event struct.
pub fn parse_log(log: &ReceiptLog) -> Result<GatewayEvent> {
    let abi = JsonAbi::parse([
        "event ContractCall(address indexed sender,string destinationChain,string destinationContractAddress,bytes32 indexed payloadHash,bytes payload)",
        "event ContractCallWithToken(address indexed sender,string destinationChain,string destinationContractAddress,bytes32 indexed payloadHash,bytes payload,string symbol,uint256 amount)",
        "event OperatorshipTransferred(bytes newOperatorsData)"]).map_err(|err| eyre!("Failed to parse ABI: {}", err))?;
    let hasher = HasherKeccak::new();
    let first_topic = log
        .topics
        .first()
        .ok_or_else(|| eyre!("No topics in log"))?;

    for item in abi.items() {
        if let AbiItem::Event(e) = item {
            let event_signature_hash = hasher.digest(e.signature().as_bytes());
            if first_topic == event_signature_hash.as_slice() {
                if e.signature().starts_with("ContractCall") {
                    return parse_contract_call_event(log, &e);
                } else if e.signature().starts_with("OperatorshipTransferred") {
                    return parse_operatorship_transferred_event(log, &e);
                }
            }
        }
    }
    Err(eyre!("Couldn't match an event to decode the log"))
}

/// Parses a message id of the format "<transaction hash>:<relative log index>".
pub fn parse_message_id(id: &nonempty::String) -> Result<(String, usize)> {
    let components = id.split(ID_SEPARATOR).collect::<Vec<_>>();

    if components.len() != 2 {
        return Err(eyre!("Invalid message id format"));
    }

    let tx_hash = components[0].strip_prefix("0x").unwrap_or(components[0]);
    if tx_hash.len() != 64 {
        return Err(eyre!("Invalid transaction hash in message id"));
    }

    Ok((tx_hash.to_string(), components[1].parse::<usize>()?))
}

impl Comparison<ContractCallBase> for Message {
    fn compare_with_event(&self, event: ContractCallBase) -> Result<()> {
        if event.source_address.is_none()
            || event.destination_address.is_none()
            || event.destination_chain.is_none()
            || event.payload_hash.is_none()
        {
            return Err(eyre!("Event could not be parsed"));
        }

        if !(self.source_address.to_string().to_lowercase()
            == event.source_address.unwrap().to_string().to_lowercase()
            && String::from(self.destination_chain.clone()).to_lowercase()
                == event.destination_chain.unwrap().to_lowercase()
            && self.destination_address.to_string().to_lowercase()
                == event.destination_address.unwrap().to_lowercase()
            && self.payload_hash == event.payload_hash.unwrap())
        {
            return Err(eyre!("Invalid message"));
        }
        Ok(())
    }
}

impl Comparison<OperatorshipTransferredBase> for WorkerSetMessage {
    fn compare_with_event(&self, event: OperatorshipTransferredBase) -> Result<()> {
        if event.new_operators_data.is_none() {
            return Err(eyre!("Event could not be parsed"));
        }

        if self.new_operators_data != event.new_operators_data.unwrap() {
            return Err(eyre!("Invalid workerset message"));
        }
        Ok(())
    }
}

pub fn compare_content_with_log(content: ContentVariant, log: &ReceiptLog) -> Result<()> {
    let gateway_event = parse_log(log)?;

    match gateway_event {
        GatewayEvent::ContactCall(event) => {
            let ContentVariant::Message(message) = content else {
                return Err(eyre!("Invalid content variant"));
            };
            message.compare_with_event(event)
        }
        GatewayEvent::OperatorshipTransferred(event) => {
            let ContentVariant::WorkerSet(message) = content else {
                return Err(eyre!("Invalid content variant"));
            };
            message.compare_with_event(event)
        }
    }
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

#[cfg(test)]
pub mod test_helpers {
    use ethabi::{decode, ParamType};
    use std::fs::File;

    use types::common::{Config, FinalizationVariant, WorkerSetMessage};
    use types::connection_router::state::Message;
    use types::execution::ReceiptLog;
    use types::proofs::{
        BatchVerificationData, CrossChainId, TransactionProofsBatch, UpdateVariant,
    };
    use types::ssz_rs::Node;
    use types::{
        common::{ChainConfig, ContentVariant},
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

    pub fn get_legacy_verification_data() -> Vec<u8> {
        let file_name = "testdata/legacy_receipt.json";
        let file = File::open(file_name).unwrap();

        serde_json::from_reader(file).unwrap()
    }

    pub fn get_batched_data(
        historical: bool,
        finalization: &str,
    ) -> (Bootstrap, BatchVerificationData) {
        let file_name = if historical {
            format!(
                "testdata/verification/{}_historical_roots.json",
                finalization
            )
        } else {
            format!("testdata/verification/{}_block_roots.json", finalization)
        };
        let verification_file = File::open(file_name).unwrap();
        let verification_data: BatchVerificationData =
            serde_json::from_reader(verification_file).unwrap();

        let bootstrap_file = File::open(format!("testdata/verification/bootstrap.json")).unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(bootstrap_file).unwrap();
        (bootstrap, verification_data)
    }

    pub fn get_finality_update() -> UpdateVariant {
        let verification_file = File::open(format!("testdata/verification/update.json")).unwrap();
        serde_json::from_reader(verification_file).unwrap()
    }

    pub fn get_transaction_proofs() -> TransactionProofsBatch {
        let verification_file = File::open(format!(
            "testdata/verification/transaction_proofs_batch.json"
        ))
        .unwrap();
        serde_json::from_reader(verification_file).unwrap()
    }

    pub fn get_config() -> Config {
        let genesis_root_bytes: [u8; 32] =
            hex_str_to_bytes("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .unwrap()
                .try_into()
                .unwrap();

        Config {
            chain_config: ChainConfig {
                chain_id: 1,
                genesis_time: 1606824023,
                genesis_root: Node::from_bytes(genesis_root_bytes),
            },
            gateway_address: String::from("0x4F4495243837681061C4743b74B3eEdf548D56A5"),
            finalization: FinalizationVariant::Finality(),
        }
    }

    pub fn filter_message_variants(proofs_batch: &TransactionProofsBatch) -> Vec<Message> {
        proofs_batch
            .content
            .iter()
            .filter_map(|c| match c {
                ContentVariant::Message(m) => Some((*m).clone()),
                ContentVariant::WorkerSet(..) => None,
            })
            .collect()
    }

    pub fn filter_workerset_variants(
        proofs_batch: &TransactionProofsBatch,
    ) -> Vec<WorkerSetMessage> {
        proofs_batch
            .content
            .iter()
            .filter_map(|c| match c {
                ContentVariant::WorkerSet(m) => Some((*m).clone()),
                ContentVariant::Message(..) => None,
            })
            .collect()
    }

    pub fn filter_workeset_message_variants(
        proofs_batch: &TransactionProofsBatch,
    ) -> Vec<WorkerSetMessage> {
        proofs_batch
            .content
            .iter()
            .filter_map(|c| match c {
                ContentVariant::Message(..) => None,
                ContentVariant::WorkerSet(m) => Some((*m).clone()),
            })
            .collect()
    }

    pub fn mock_contractcall_message_with_log() -> (Message, ReceiptLog) {
        let file = File::open("testdata/receipt_log_contractcall.json").unwrap();
        let log: ReceiptLog = serde_json::from_reader(file).unwrap();
        let message = Message {
            cc_id: CrossChainId {
                chain: String::from("ethereum").try_into().unwrap(),
                id: String::from("foo:bar").try_into().unwrap(),
            },
            source_address: String::from("0xce16f69375520ab01377ce7b88f5ba8c48f8d666")
                .try_into()
                .unwrap(),
            destination_chain: String::from("fantom").try_into().unwrap(),
            destination_address: String::from("0xce16f69375520ab01377ce7b88f5ba8c48f8d666")
                .try_into()
                .unwrap(),
            payload_hash: [
                68, 249, 93, 245, 6, 157, 169, 86, 138, 243, 82, 53, 145, 70, 138, 171, 153, 223,
                14, 249, 200, 50, 140, 182, 107, 223, 224, 230, 18, 217, 208, 55,
            ],
        };
        (message, log)
    }

    pub fn mock_workerset_message_with_log() -> (WorkerSetMessage, ReceiptLog) {
        let file = File::open("testdata/receipt_log_operatorship.json").unwrap();
        let log: ReceiptLog = serde_json::from_reader(file).unwrap();
        let message = WorkerSetMessage {
            new_operators_data: decode(&[ParamType::Bytes], log.data.as_slice()).unwrap()[0]
                .clone()
                .into_bytes()
                .unwrap(),
            message_id: String::from("foo:bar").try_into().unwrap(),
        };
        (message, log)
    }
}
