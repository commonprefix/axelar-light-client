use crate::{
    consumer::Amqp,
    parser::parse_enriched_log,
    types::{Config, EnrichedLog, VerificationMethod},
};
use consensus_types::{
    common::ContentVariant,
    proofs::{BatchVerificationData, UpdateVariant},
};
use eth::{consensus::EthBeaconAPI, execution::EthExecutionAPI, utils::get_full_block_details};
use eyre::{eyre, Result};
use prover::prover::{types::EnrichedContent, ProverAPI};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::time::interval;

pub struct Relayer<P, C, CR, ER> {
    config: Config,
    consensus: Arc<CR>,
    consumer: C,
    execution: Arc<ER>,
    prover: Arc<P>,
}

impl<C: Amqp, P: ProverAPI, CR: EthBeaconAPI, ER: EthExecutionAPI> Relayer<P, C, CR, ER> {
    pub async fn new(
        config: Config,
        consumer: C,
        consensus: Arc<CR>,
        execution: Arc<ER>,
        prover: Arc<P>,
    ) -> Self {
        Relayer {
            config,
            consumer,
            consensus,
            execution,
            prover,
        }
    }

    pub async fn start(&mut self) {
        let mut interval = interval(Duration::from_secs(self.config.process_interval));

        loop {
            interval.tick().await;

            let res = self.relay().await;
            match res {
                Ok(_) => println!("Relay succeeded"),
                Err(e) => println!("Relay failed {:?}", e),
            }
        }
    }

    pub async fn relay(&mut self) -> Result<()> {
        let update = self
            .get_update(&self.config.verification_method)
            .await
            .map_err(|e| eyre!("Error fetching update {}", e))?;
        let recent_block_slot = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon.slot,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon.slot,
        };

        let fetched_logs = self.collect_messages(self.config.max_batch_size).await;

        let contents = self.process_logs(fetched_logs).await;
        let mut successful_contents = vec![];
        let mut delivery_tags = vec![];
        for (delivery_tag, content) in contents {
            match content {
                Some(content) => {
                    println!("About content {:?}", content.content);
                    if content.beacon_block.slot >= recent_block_slot {
                        println!(
                            "Message {:?} is too recent. Update slot: {}, content slot: {}. Requeuing", 
                            content.content, recent_block_slot, content.beacon_block.slot
                        );
                        self.consumer.nack_delivery(delivery_tag).await?;
                        continue;
                    }
                    delivery_tags.push(delivery_tag);
                    successful_contents.push(content);
                }
                None => {
                    println!("Error processing log. Requeuing");
                    self.consumer.nack_delivery(delivery_tag).await?;
                    continue;
                }
            }
        }

        let batch_contents = self.prover.batch_messages(&successful_contents);
        let batch_verification_data: Result<BatchVerificationData, eyre::Error> = self
            .prover
            .batch_generate_proofs(batch_contents, update)
            .await;
        if batch_verification_data.is_err() {
            return Err(eyre!(
                "Error generating proofs {:?}",
                batch_verification_data
            ));
        }

        // let res = serde_json::to_string(batch_verification_data.as_ref().unwrap()).unwrap();
        // println!("res {}", res);

        let processed_messages = self.extract_all_contents(&batch_verification_data.unwrap());
        for (i, content) in successful_contents.iter().enumerate() {
            let delivery_tag = delivery_tags[i];
            if processed_messages.contains(&content.content) {
                println!("Message {:?} succeeded", delivery_tag);
                self.consumer.ack_delivery(delivery_tag).await?;
            } else {
                println!("Message {:?} failed", delivery_tag);
                self.consumer.nack_delivery(delivery_tag).await?;
            }
        }

        println!("Processed {} messages", processed_messages.len());
        Ok(())
    }

    async fn process_logs(
        &mut self,
        fetched_logs: HashMap<u64, EnrichedLog>,
    ) -> Vec<(u64, Option<EnrichedContent>)> {
        let mut contents: Vec<(u64, Option<EnrichedContent>)> = vec![];

        for (delivery_tag, enriched_log) in fetched_logs {
            println!("Working on log {}", enriched_log.event_name);
            let block_details = get_full_block_details(
                self.consensus.clone(),
                self.execution.clone(),
                enriched_log.log.block_number.unwrap().as_u64(),
                self.config.genesis_timestamp,
            )
            .await;

            if block_details.is_err() {
                println!(
                    "Error fetching block details {:?}. Requeuing",
                    block_details
                );
                contents.push((delivery_tag, None));
                continue;
            }

            let content = parse_enriched_log(&enriched_log, &block_details.unwrap());
            if content.is_err() {
                println!(
                    "Error parsing enriched log {:?} {:?}. Requeuing",
                    enriched_log,
                    content.err()
                );
                contents.push((delivery_tag, None));
                continue;
            }

            let content = content.unwrap();
            contents.push((delivery_tag, Some(content)))
        }

        contents
    }

    async fn collect_messages(&mut self, max_messages: usize) -> HashMap<u64, EnrichedLog> {
        let deliveries = self.consumer.consume(max_messages).await;
        if deliveries.is_err() {
            println!("Error consuming messages {:?}", deliveries);
            return HashMap::new();
        }

        let mut enriched_logs: HashMap<u64, EnrichedLog> = HashMap::new();
        for (delivery_tag, data_str) in deliveries.unwrap() {
            let enriched_log = serde_json::from_str(&data_str);
            if enriched_log.is_err() {
                println!("Error parsing log {:?}", enriched_log);
                continue;
            }
            enriched_logs.insert(delivery_tag, enriched_log.unwrap());
        }

        enriched_logs
    }

    async fn get_update(&self, verification_method: &VerificationMethod) -> Result<UpdateVariant> {
        match verification_method {
            VerificationMethod::Finality => match self.consensus.get_finality_update().await {
                Ok(update) => Ok(UpdateVariant::Finality(update)),
                Err(e) => Err(eyre!("Error fetching finality update {}", e)),
            },
            VerificationMethod::Optimistic => match self.consensus.get_optimistic_update().await {
                Ok(update) => Ok(UpdateVariant::Optimistic(update)),
                Err(e) => Err(eyre!("Error fetching finality update {}", e)),
            },
        }
    }

    pub fn extract_all_contents(&self, data: &BatchVerificationData) -> Vec<ContentVariant> {
        data.target_blocks
            .iter()
            .flat_map(|block| &block.transactions_proofs)
            .flat_map(|transaction| &transaction.content)
            .cloned() // Clone each ContentVariant, required if ContentVariant does not implement Copy
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumer::MockLapinConsumer;
    use crate::types::{Config, VerificationMethod};
    use consensus_types::consensus::{BeaconBlockAlias, FinalityUpdate};
    use consensus_types::proofs::{
        AncestryProof, BlockProofsBatch, CrossChainId, Message, TransactionProofsBatch,
    };
    use eth::consensus::MockConsensusRPC;
    use eth::execution::MockExecutionRPC;
    use eth::types::FullBlockDetails;
    use ethers::types::{Block, Transaction, H256};
    use indexmap::IndexMap;
    use mockall::predicate;
    use prover::prover::proof_generator::MockProofGenerator;
    use prover::prover::state_prover::MockStateProver;
    use prover::prover::types::BatchContentGroups;
    use prover::prover::MockProver;
    use prover::Prover;
    use std::fs::{self, File};
    use std::sync::Arc;
    use sync_committee_rs::consensus_types::BeaconBlockHeader;

    type MockProverAlias = MockProver<MockProofGenerator<MockConsensusRPC, MockStateProver>>;

    fn setup_test() -> (
        Config,
        MockLapinConsumer,
        MockConsensusRPC,
        MockExecutionRPC,
        MockProverAlias,
    ) {
        let config = Config {
            max_batch_size: 1,
            process_interval: 1,
            verification_method: VerificationMethod::Finality,
            genesis_timestamp: 0,
            ..Default::default()
        };
        let consumer = MockLapinConsumer::new();
        let consensus = MockConsensusRPC::new();
        let execution = MockExecutionRPC::new();
        let prover = MockProver::new();

        return (config, consumer, consensus, execution, prover);
    }

    fn get_content(tx_hash_n: u64, log_index: u64) -> ContentVariant {
        ContentVariant::Message(Message {
            cc_id: CrossChainId {
                chain: "ethereum".parse().unwrap(),
                id: format!("{:x}:{}", H256::from_low_u64_be(tx_hash_n), log_index)
                    .parse()
                    .unwrap(),
            },
            source_address: "0x1234".parse().unwrap(),
            destination_chain: "ethereum".parse().unwrap(),
            destination_address: "0x1234".parse().unwrap(),
            payload_hash: Default::default(),
        })
    }

    fn get_mock_ver_data() -> BatchVerificationData {
        BatchVerificationData {
            update: UpdateVariant::default(),
            target_blocks: vec![
                BlockProofsBatch {
                    ancestry_proof: AncestryProof::default(),
                    target_block: BeaconBlockHeader {
                        slot: 1,
                        ..Default::default()
                    },
                    transactions_proofs: vec![
                        TransactionProofsBatch {
                            transaction_proof: Default::default(),
                            receipt_proof: Default::default(),
                            content: vec![get_content(1, 0), get_content(1, 1)],
                        },
                        TransactionProofsBatch {
                            transaction_proof: Default::default(),
                            receipt_proof: Default::default(),
                            content: vec![get_content(2, 0), get_content(2, 1)],
                        },
                    ],
                },
                BlockProofsBatch {
                    ancestry_proof: AncestryProof::default(),
                    target_block: BeaconBlockHeader {
                        slot: 2,
                        ..Default::default()
                    },
                    transactions_proofs: vec![
                        TransactionProofsBatch {
                            transaction_proof: Default::default(),
                            receipt_proof: Default::default(),
                            content: vec![get_content(3, 0), get_content(3, 1)],
                        },
                        TransactionProofsBatch {
                            transaction_proof: Default::default(),
                            receipt_proof: Default::default(),
                            content: vec![get_content(4, 0), get_content(4, 1)],
                        },
                    ],
                },
            ],
        }
    }

    fn get_mock_finality_update(recent_block_slot: u64) -> FinalityUpdate {
        let mut finality_update = FinalityUpdate::default();
        finality_update.finalized_header.beacon.slot = recent_block_slot;
        finality_update
    }

    fn get_mock_exec_block(block_number: u64) -> Block<Transaction> {
        Block {
            timestamp: ethers::types::U256::from(1),
            number: Some(block_number.into()),
            ..Default::default()
        }
    }

    fn get_mock_enriched_log(block_number: u64, tx_hash_n: u64, log_index: u64) -> EnrichedLog {
        let file = File::open("testdata/contract_call_with_token.json").unwrap();
        let mut enriched_log: EnrichedLog = serde_json::from_reader(file).unwrap();
        enriched_log.log.transaction_hash = Some(H256::from_low_u64_be(tx_hash_n));
        enriched_log.log.block_number = Some(block_number.into());
        enriched_log.log.transaction_log_index = Some(log_index.into());
        enriched_log
    }

    #[tokio::test]
    async fn test_relay_valid() {
        let (config, mut consumer, mut consensus, mut execution, mut prover) = setup_test();

        let enriched_log = get_mock_enriched_log(5, 1, 0);
        let block_details = FullBlockDetails {
            exec_block: get_mock_exec_block(5),
            beacon_block: BeaconBlockAlias {
                slot: 5,
                ..Default::default()
            },
            receipts: vec![],
        };
        let enriched_content = parse_enriched_log(&enriched_log, &block_details).unwrap();
        let finality_update = get_mock_finality_update(10);

        let mut batched_content = BatchContentGroups::new();
        let mut batched_1 = IndexMap::new();
        batched_1.insert(H256::from_low_u64_be(1), vec![enriched_content.clone()]);
        batched_content.insert(5, batched_1);

        let ver_data = BatchVerificationData {
            update: UpdateVariant::Finality(finality_update.clone()),
            target_blocks: vec![BlockProofsBatch {
                ancestry_proof: AncestryProof::default(),
                target_block: BeaconBlockHeader {
                    slot: 5,
                    ..Default::default()
                },
                transactions_proofs: vec![TransactionProofsBatch {
                    transaction_proof: Default::default(),
                    receipt_proof: Default::default(),
                    content: vec![enriched_content.clone().content],
                }],
            }],
        };

        consensus
            .expect_get_finality_update()
            .returning(move || Ok(finality_update.clone()));
        execution
            .expect_get_block_with_txs()
            .returning(move |_| Ok(Some(block_details.exec_block.clone())));
        consensus
            .expect_get_beacon_block()
            .returning(move |_| Ok(block_details.beacon_block.clone()));
        execution
            .expect_get_block_receipts()
            .returning(move |_| Ok(block_details.receipts.clone()));

        consumer
            .expect_consume()
            .with(predicate::eq(1))
            .returning(move |_| Ok(vec![(1, serde_json::to_string(&enriched_log).unwrap())]));
        prover
            .expect_batch_messages()
            .returning(move |_| batched_content.clone());
        prover
            .expect_batch_generate_proofs()
            .returning(move |_, _| Ok(ver_data.clone()));

        consumer
            .expect_ack_delivery()
            .with(predicate::eq(1))
            .returning(|_| Ok(()));
        consumer.expect_nack_delivery().never();

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let relayed = relayer.relay().await;
        assert!(relayed.is_ok());
    }

    #[tokio::test]
    async fn test_process_logs_valid() {
        let (config, consumer, mut consensus, mut execution, _) = setup_test();
        let file = File::open("testdata/contract_call_with_token.json").unwrap();
        let enriched_log: EnrichedLog = serde_json::from_reader(file).unwrap();
        let prover = Prover::new(MockProofGenerator::<MockConsensusRPC, MockStateProver>::new());

        execution.expect_get_block_with_txs().returning(|_| {
            Ok(Some(Block {
                timestamp: ethers::types::U256::from(1),
                ..Default::default()
            }))
        });
        consensus
            .expect_get_beacon_block()
            .returning(|_| Ok(Default::default()));
        execution
            .expect_get_block_receipts()
            .returning(|_| Ok(Default::default()));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let mut fetched_logs = HashMap::new();
        fetched_logs.insert(0, enriched_log.clone());

        let res = relayer.process_logs(fetched_logs).await;
        assert_eq!(1, res.len());
        assert_eq!(res[0].0, 0);

        let content = res[0].1.as_ref().unwrap();
        assert_eq!(
            content.exec_block,
            Block {
                timestamp: ethers::types::U256::from(1),
                ..Default::default()
            }
        );
        assert_eq!(content.beacon_block, Default::default());

        match &content.content {
            ContentVariant::Message(message) => {
                assert_eq!(
                    message.cc_id.id,
                    format!(
                        "0x{:x}:{}",
                        enriched_log.log.transaction_hash.unwrap(),
                        enriched_log.log.log_index.unwrap()
                    )
                    .parse()
                    .unwrap()
                );
            }
            _ => panic!("Wrong content type"),
        }
    }

    #[tokio::test]
    async fn test_collect_messages_valid() {
        let (config, mut consumer, consensus, execution, prover) = setup_test();
        let path = "testdata/contract_call_with_token.json";
        let contents = fs::read_to_string(path).unwrap();
        let expected_log = serde_json::from_str::<EnrichedLog>(&contents).unwrap();

        consumer
            .expect_consume()
            .returning(move |_| Ok(vec![(0, contents.clone())]));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let fetched_logs = relayer.collect_messages(1).await;
        assert_eq!(fetched_logs.len(), 1);
        assert_eq!(fetched_logs.get(&0).unwrap(), &expected_log);
    }

    #[tokio::test]
    async fn test_collect_messages_invalid_delivery() {
        let (config, mut consumer, consensus, execution, prover) = setup_test();

        consumer
            .expect_consume()
            .returning(move |_| Ok(vec![(0, "invalid message".to_string())]));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let fetched_logs = relayer.collect_messages(1).await;
        assert_eq!(fetched_logs.len(), 0);
    }

    #[tokio::test]
    async fn test_collect_messages_consumer_failure() {
        let (config, mut consumer, consensus, execution, prover) = setup_test();

        consumer
            .expect_consume()
            .returning(move |_| Err(eyre!("Consumer failed")));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let fetched_logs = relayer.collect_messages(1).await;
        assert_eq!(fetched_logs.len(), 0);
    }

    #[tokio::test]
    async fn test_get_update() {
        let (config, consumer, mut consensus, execution, prover) = setup_test();
        consensus
            .expect_get_finality_update()
            .returning(|| Ok(Default::default()));
        consensus
            .expect_get_optimistic_update()
            .returning(|| Ok(Default::default()));
        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let update = relayer.get_update(&VerificationMethod::Finality).await;
        assert!(update.is_ok());
        assert_eq!(update.unwrap(), UpdateVariant::Finality(Default::default()));

        let update = relayer.get_update(&VerificationMethod::Optimistic).await;
        assert!(update.is_ok());
        assert_eq!(
            update.unwrap(),
            UpdateVariant::Optimistic(Default::default())
        );
    }

    #[tokio::test]
    async fn test_extract_all_contents() {
        let (config, consumer, consensus, execution, prover) = setup_test();
        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
        )
        .await;

        let ver_data = get_mock_ver_data();
        let content = relayer.extract_all_contents(&ver_data);
        let expected_content = vec![
            get_content(1, 0),
            get_content(1, 1),
            get_content(2, 0),
            get_content(2, 1),
            get_content(3, 0),
            get_content(3, 1),
            get_content(4, 0),
            get_content(4, 1),
        ];
        assert_eq!(content, expected_content);
    }
}
