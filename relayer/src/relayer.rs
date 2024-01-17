use crate::{
    consumers::Amqp,
    parser::parse_enriched_log,
    types::{Config, EnrichedLog, VerificationMethod},
    verifier::VerifierAPI,
};
use consensus_types::{
    common::ContentVariant,
    proofs::{BatchVerificationData, UpdateVariant},
};
use eth::{consensus::EthBeaconAPI, execution::EthExecutionAPI, utils::get_full_block_details};
use eyre::{eyre, Result};
use log::{debug, error, info, warn};
use prover::prover::{errors::StateProverError, types::EnrichedContent, ProverAPI};
use reqwest::Client;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::time::sleep;

// This is the main module of the relayer. It fetches logs from the rabbitMQ
// consumer, generates the proofs and forwards them to the verifier.
pub struct Relayer<P, C, CR, ER, V> {
    config: Config,
    consensus: Arc<CR>,
    consumer: C,
    execution: Arc<ER>,
    prover: Arc<P>,
    verifier: V,
}

impl<C: Amqp, P: ProverAPI, CR: EthBeaconAPI, ER: EthExecutionAPI, V: VerifierAPI>
    Relayer<P, C, CR, ER, V>
{
    pub async fn new(
        config: Config,
        consumer: C,
        consensus: Arc<CR>,
        execution: Arc<ER>,
        prover: Arc<P>,
        verifier: V,
    ) -> Self {
        Relayer {
            config,
            consumer,
            consensus,
            execution,
            prover,
            verifier,
        }
    }

    /// This is the main function of the relayer. It runs in a loop and relays
    /// new events that come from the consumer to the verifier after generating
    /// the neccessary proofs.
    pub async fn start(&mut self) {
        let interval = Duration::from_secs(self.config.process_interval);

        loop {
            let res = self.relay().await;
            if let Err(e) = res {
                error!("Relay failed {:?}", e);
            }

            sleep(interval).await;
        }
    }

    /// This function does a single round of relaying. It fetches a set of logs
    /// from the consumer, parses them accordingly, generates the needed proofs
    /// and relays them to the verifier. If the relay failed for any reason, the
    /// message is being requeued to the RabbitMQ otherwise it's being acked.
    pub async fn relay(&mut self) -> Result<()> {
        let update = self
            .get_update(&self.config.verification_method)
            .await
            .map_err(|e| eyre!("Error fetching update {}", e))?;

        if !self
            .has_state(&update.recent_block().state_root.to_string())
            .await?
        {
            error!(
                "State {} not found in state_prover (lodestar) cache. Requeuing",
                update.recent_block().state_root
            );
        }

        let fetched_logs = self.collect_messages(self.config.max_batch_size).await;
        if fetched_logs.is_empty() {
            info!("No new logs to process");
            return Ok(());
        }

        let contents = self.process_logs(fetched_logs).await;
        let contents = self
            .filter_applicable_content(contents, update.clone())
            .await?;

        let (proof_contents, batched_proofs) = self
            .get_proofs(contents, &update)
            .await
            .map_err(|e| eyre!("Error generating proofs {}", e))?;
        if proof_contents.is_empty() {
            info!("No new contents to process");
            return Ok(());
        }

        let _ = self.submit_proofs(&proof_contents, &batched_proofs).await?;

        Ok(())
    }

    async fn submit_proofs(
        &self,
        contents: &Vec<EnrichedContent>,
        proofs: &BatchVerificationData,
    ) -> Result<Vec<String>> {
        let result = self.verifier.verify_data(proofs.clone()).await?;

        let mut successful_ids = vec![];

        for content in contents {
            let delivery_tag = content.delivery_tag;
            let (id, res) = result.iter().find(|(key, _)| *key == content.id).unwrap(); // Will definitely succeed
            if res == "OK" {
                info!("Content with id={:?} succeeded", id);
                successful_ids.push(id.clone());
                self.consumer.ack_delivery(delivery_tag).await?;
            } else {
                error!("Content {} failed by the verifer with err: {}", id, res);
                self.consumer.nack_delivery(delivery_tag).await?;
            }
        }

        info!("Verified the following events {:#?}", successful_ids);
        Ok(successful_ids)
    }

    /// This function generates the batched proofs for a set of contents.
    /// - Will nack (requeue) if the batch_verification_data generation failed for a message
    async fn get_proofs(
        &self,
        contents: Vec<EnrichedContent>,
        update: &UpdateVariant,
    ) -> Result<(Vec<EnrichedContent>, BatchVerificationData)> {
        let batched = self.prover.batch_messages(&contents);

        let batch_verification_data = self
            .prover
            .batch_generate_proofs(batched, update.clone())
            .await?;
        let successful = self.extract_all_contents(&batch_verification_data);
        let mut successful_enriched = vec![];

        // Reject the contents that were not included in the batch_verification_data
        for content in contents {
            if !successful.contains(&content.content) {
                warn!(
                    "Content {:?} was not included in the batch_verification_data. Requeuing",
                    content.content
                );
                self.consumer.nack_delivery(content.delivery_tag).await?;
                continue;
            }
            successful_enriched.push(content);
        }

        info!("Generated {} proofs", successful_enriched.len());
        Ok((successful_enriched, batch_verification_data))
    }

    // Filters out the contents that are not applicable to the current update.
    // - Will nack (requeue) if the content is more recent than the recent block of the latest update
    async fn filter_applicable_content(
        &self,
        contents: Vec<EnrichedContent>,
        update: UpdateVariant,
    ) -> Result<Vec<EnrichedContent>> {
        let recent_block_slot = update.recent_block().slot;
        let mut applicable = vec![];
        let contents_len = contents.len();

        for content in contents {
            if content.beacon_block.slot >= recent_block_slot {
                warn!(
                    "Message {:?} is too recent. Update slot: {}, content slot: {}. Requeuing",
                    content.content, recent_block_slot, content.beacon_block.slot
                );
                self.consumer.nack_delivery(content.delivery_tag).await?;
                continue;
            }
            if content.beacon_block.slot < recent_block_slot - 7000 {
                warn!(
                    "Message {:?} would be in historical. Update slot: {}, content slot: {}. Removing",
                    content.content, recent_block_slot, content.beacon_block.slot
                );
                self.consumer.ack_delivery(content.delivery_tag).await?;
                continue;
            }
            applicable.push(content);
        }

        info!(
            "Filtered {} out of {} contents",
            applicable.len(),
            contents_len
        );
        Ok(applicable)
    }

    /// The function that generates contents compatible with the prover out of a
    /// set of logs provided by the consumer.
    /// - Will nack (requeue) if full blockchain data could not be received
    /// - Will ack (remove from queue) if the log could not be parsed
    async fn process_logs(
        &mut self,
        fetched_logs: HashMap<u64, EnrichedLog>,
    ) -> Vec<EnrichedContent> {
        let mut contents: Vec<EnrichedContent> = vec![];

        for (delivery_tag, enriched_log) in fetched_logs {
            debug!("Working on log {}", enriched_log.event_name);
            let block_details = get_full_block_details(
                self.consensus.clone(),
                self.execution.clone(),
                enriched_log.log.block_number.unwrap().as_u64(),
                self.config.genesis_timestamp,
            )
            .await;

            if block_details.is_err() {
                error!(
                    "Error fetching block details {:?}. Requeuing",
                    block_details
                );
                self.consumer.nack_delivery(delivery_tag).await.unwrap();
                continue;
            }

            let content = parse_enriched_log(&enriched_log, &block_details.unwrap(), delivery_tag);
            if content.is_err() {
                error!(
                    "Error parsing enriched log {:?}. {:?}. Will not requeue",
                    enriched_log,
                    content.err().unwrap()
                );

                self.consumer.ack_delivery(delivery_tag).await.unwrap();
                continue;
            }

            let content = content.unwrap();
            contents.push(content)
        }

        info!("Generated {} contents", contents.len());
        contents
    }

    /// Fetches a set of messages from the consumer up to a limit.
    async fn collect_messages(&mut self, max_messages: usize) -> HashMap<u64, EnrichedLog> {
        let deliveries = self.consumer.consume(max_messages).await;
        if deliveries.is_err() {
            error!("Error consuming messages {:?}", deliveries);
            return HashMap::new();
        }
        let deliveries = deliveries.unwrap();

        let mut enriched_logs: HashMap<u64, EnrichedLog> = HashMap::new();
        for (delivery_tag, data_str) in &deliveries {
            debug!("Working on delivery_tag={:?}", delivery_tag);
            let enriched_log = serde_json::from_str(data_str);
            if enriched_log.is_err() {
                error!("Error parsing log {:?}", enriched_log);
                continue;
            }
            enriched_logs.insert(*delivery_tag, enriched_log.unwrap());
        }

        info!(
            "Generated {} enriched_logs from {} deliveries",
            enriched_logs.len(),
            &deliveries.len()
        );
        enriched_logs
    }

    /// Fetches either a finality or an optimistic light client update, provided a verification method.
    async fn get_update(&self, verification_method: &VerificationMethod) -> Result<UpdateVariant> {
        match verification_method {
            VerificationMethod::Finality => match self.consensus.get_finality_update().await {
                Ok(update) => {
                    info!(
                        "Got finality update with slot {}",
                        update.finalized_header.beacon.slot
                    );
                    return Ok(UpdateVariant::Finality(update));
                }
                Err(e) => Err(eyre!("Error fetching finality update {}", e)),
            },
            VerificationMethod::Optimistic => match self.consensus.get_optimistic_update().await {
                Ok(update) => {
                    info!(
                        "Got optimistic update with slot {}",
                        update.attested_header.beacon.slot
                    );
                    return Ok(UpdateVariant::Optimistic(update));
                }
                Err(e) => Err(eyre!("Error fetching finality update {}", e)),
            },
        }
    }

    /// A helper function that extracts all messages out of the main structure of batched proofs.
    /// Used to see which messages succeeded and which not, in order to ack or nack accordingly.
    pub fn extract_all_contents(&self, data: &BatchVerificationData) -> Vec<ContentVariant> {
        data.target_blocks
            .iter()
            .flat_map(|block| &block.transactions_proofs)
            .flat_map(|transaction| &transaction.content)
            .cloned() // Clone each ContentVariant, required if ContentVariant does not implement Copy
            .collect()
    }

    pub async fn has_state(&self, state_id: &str) -> Result<bool, StateProverError> {
        println!("Checking state for {}", state_id);
        let req = format!(
            "{}/has_state?state_id={}&network={}",
            self.config.state_prover_rpc, state_id, self.config.network
        );

        let response = reqwest::get(&req).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        println!("STATE WOULD PASS");
        return Ok(true);
    }
}

#[cfg(test)]
mod tests {
    use self::verifier::MockVerifierAPI;

    use super::*;
    use crate::consumers::MockLapinConsumer;
    use crate::types::{Config, VerificationMethod};
    use consensus_types::consensus::{BeaconBlockAlias, FinalityUpdate};
    use consensus_types::proofs::{
        AncestryProof, BlockProofsBatch, CrossChainId, Message, TransactionProofsBatch,
    };
    use consensus_types::sync_committee_rs::consensus_types::BeaconBlockHeader;
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

    type MockProverAlias = MockProver<MockProofGenerator<MockConsensusRPC, MockStateProver>>;

    fn setup_test() -> (
        Config,
        MockLapinConsumer,
        MockConsensusRPC,
        MockExecutionRPC,
        MockProverAlias,
        MockVerifierAPI,
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
        let verifier = MockVerifierAPI::new();

        return (config, consumer, consensus, execution, prover, verifier);
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

    fn get_mock_enriched_content(
        slot: u64,
        block_num: u64,
        delivery_tag: u64,
        id: &str,
    ) -> EnrichedContent {
        EnrichedContent {
            id: id.to_string(),
            content: get_content(1, 1),
            tx_hash: H256::default(),
            exec_block: Block {
                number: Some(block_num.into()),
                ..Default::default()
            },
            beacon_block: BeaconBlockAlias {
                slot,
                ..Default::default()
            },
            receipts: Default::default(),
            delivery_tag,
        }
    }

    pub fn get_mock_batched_data(
        update: UpdateVariant,
        contents: Vec<EnrichedContent>,
    ) -> (BatchContentGroups, BatchVerificationData) {
        let mut groups: BatchContentGroups = IndexMap::new();
        for content in contents {
            groups
                .entry(content.exec_block.number.unwrap().as_u64())
                .or_default()
                .entry(content.tx_hash)
                .or_default()
                .push(content.clone());
        }

        let mut block_proofs_batch: Vec<BlockProofsBatch> = vec![];
        for (_, block_groups) in &groups {
            let mut block_proof = BlockProofsBatch {
                ancestry_proof: Default::default(),
                target_block: Default::default(),
                transactions_proofs: vec![],
            };

            for (_, contents) in block_groups {
                let tx_level_verification = TransactionProofsBatch {
                    transaction_proof: Default::default(),
                    receipt_proof: Default::default(),
                    content: contents.iter().map(|m| m.content.clone()).collect(),
                };

                block_proof.transactions_proofs.push(tx_level_verification);
            }

            block_proofs_batch.push(block_proof);
        }

        (
            groups,
            BatchVerificationData {
                update,
                target_blocks: block_proofs_batch,
            },
        )
    }

    #[tokio::test]
    async fn test_filter_applicable_content() {
        let (config, mut consumer, consensus, execution, prover, verifier) = setup_test();

        consumer
            .expect_nack_delivery()
            .times(3)
            .returning(|_| Ok(()));

        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
        )
        .await;

        let update = UpdateVariant::Finality(get_mock_finality_update(10));
        let contents = vec![
            get_mock_enriched_content(8, 8, 0, "id1"),
            get_mock_enriched_content(10, 10, 1, "id2"),
            get_mock_enriched_content(15, 15, 2, "id3"),
            get_mock_enriched_content(12, 12, 3, "id4"),
        ];

        let filtered = relayer
            .filter_applicable_content(contents, update)
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[tokio::test]
    async fn test_submit_proofs() {
        let (config, mut consumer, consensus, execution, prover, mut verifier) = setup_test();

        let contents = vec![get_mock_enriched_content(1, 1, 1, "id1")];
        let finality_update = get_mock_finality_update(10);
        let (_, ver_data) = get_mock_batched_data(
            UpdateVariant::Finality(finality_update.clone()),
            contents.clone(),
        );

        consumer
            .expect_ack_delivery()
            .with(predicate::eq(1))
            .returning(|_| Ok(()));

        consumer.expect_nack_delivery().never();

        verifier
            .expect_verify_data()
            .returning(move |_| Ok(vec![("id1".to_string(), "OK".to_string())]));

        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
        )
        .await;

        let proofs = relayer.submit_proofs(&contents, &ver_data).await;
        assert!(proofs.is_ok());
        assert_eq!(proofs.unwrap(), vec!["id1".to_string()]);
    }

    #[tokio::test]
    async fn test_submit_proofs_with_nack() {
        let (config, mut consumer, consensus, execution, prover, mut verifier) = setup_test();

        let c1 = get_mock_enriched_content(1, 1, 1, "id1");
        let c2 = get_mock_enriched_content(2, 2, 2, "id2");
        let contents = vec![c1, c2];

        let finality_update = get_mock_finality_update(10);
        let (_, mut ver_data) = get_mock_batched_data(
            UpdateVariant::Finality(finality_update.clone()),
            contents.clone(),
        );
        ver_data.target_blocks.remove(1);

        consumer
            .expect_ack_delivery()
            .with(predicate::eq(1))
            .once()
            .returning(|_| Ok(()));
        consumer
            .expect_nack_delivery()
            .with(predicate::eq(2))
            .once()
            .returning(|_| Ok(()));
        verifier.expect_verify_data().returning(move |_| {
            Ok(vec![
                ("id1".to_string(), "OK".to_string()),
                ("id2".to_string(), "ERR".to_string()),
            ])
        });

        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
        )
        .await;

        let proofs = relayer.submit_proofs(&contents, &ver_data).await;
        assert!(proofs.is_ok());
        assert_eq!(proofs.unwrap(), vec!["id1".to_string()]);
    }

    #[tokio::test]
    async fn test_get_proofs() {
        let (config, mut consumer, consensus, execution, mut prover, verifier) = setup_test();

        let enriched_log = get_mock_enriched_log(5, 1, 0);
        let block_details = FullBlockDetails {
            exec_block: get_mock_exec_block(5),
            beacon_block: BeaconBlockAlias {
                slot: 5,
                ..Default::default()
            },
            receipts: vec![],
        };

        let mut contents = vec![parse_enriched_log(&enriched_log, &block_details, 1).unwrap()];
        let finality_update = get_mock_finality_update(10);
        let (batched_contents, ver_data) = get_mock_batched_data(
            UpdateVariant::Finality(finality_update.clone()),
            contents.clone(),
        );

        prover
            .expect_batch_messages()
            .returning(move |_| batched_contents.clone());
        prover
            .expect_batch_generate_proofs()
            .returning(move |_, _| Ok(ver_data.clone()));

        consumer
            .expect_nack_delivery()
            .with(predicate::eq(1))
            .times(1)
            .returning(|_| Ok(()));

        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            Verifier::new("".to_string(), "".to_string()),
        )
        .await;

        contents.push(get_mock_enriched_content(2, 2, 1, "id2"));
        let update = UpdateVariant::Finality(finality_update);
        let proofs = relayer.get_proofs(contents, &update).await;
        assert!(proofs.is_ok());
        let (enriched_content, batched_proofs) = proofs.unwrap();
        assert_eq!(enriched_content.len(), 1);

        let contents_of_verdata = relayer.extract_all_contents(&batched_proofs);
        assert_eq!(contents_of_verdata.len(), 1)
    }

    #[tokio::test]
    async fn test_relay_valid() {
        let (config, mut consumer, mut consensus, mut execution, mut prover, mut verifier) =
            setup_test();

        let content = get_mock_enriched_content(5, 5, 1, "id1");
        let enriched_log = get_mock_enriched_log(5, 1, 0);
        let block_details = FullBlockDetails {
            exec_block: get_mock_exec_block(5),
            beacon_block: BeaconBlockAlias {
                slot: 5,
                ..Default::default()
            },
            receipts: vec![],
        };

        let finality_update = get_mock_finality_update(10);

        let (batched, ver_data) = get_mock_batched_data(
            UpdateVariant::Finality(finality_update.clone()),
            vec![content],
        );

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
            .returning(move |_| batched.clone());
        prover
            .expect_batch_generate_proofs()
            .returning(move |_, _| Ok(ver_data.clone()));

        consumer
            .expect_ack_delivery()
            .with(predicate::eq(1))
            .returning(|_| Ok(()));

        consumer.expect_nack_delivery().returning(|_| Ok(()));

        verifier
            .expect_verify_data()
            .returning(move |_| Ok(vec![("id1".to_string(), "OK".to_string())]));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
        )
        .await;

        let relayed = relayer.relay().await;
        assert!(relayed.is_ok());
    }

    #[tokio::test]
    async fn test_process_logs_valid() {
        let (config, consumer, mut consensus, mut execution, _, verifier) = setup_test();
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
            verifier,
        )
        .await;

        let mut fetched_logs = HashMap::new();
        fetched_logs.insert(0, enriched_log.clone());

        let res = relayer.process_logs(fetched_logs).await;

        let content = res.first().unwrap();
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
        let (config, mut consumer, consensus, execution, prover, verifier) = setup_test();
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
            verifier,
        )
        .await;

        let fetched_logs = relayer.collect_messages(1).await;
        assert_eq!(fetched_logs.len(), 1);
        assert_eq!(fetched_logs.get(&0).unwrap(), &expected_log);
    }

    #[tokio::test]
    async fn test_collect_messages_invalid_delivery() {
        let (config, mut consumer, consensus, execution, prover, verifier) = setup_test();

        consumer
            .expect_consume()
            .returning(move |_| Ok(vec![(0, "invalid message".to_string())]));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
        )
        .await;

        let fetched_logs = relayer.collect_messages(1).await;
        assert_eq!(fetched_logs.len(), 0);
    }

    #[tokio::test]
    async fn test_collect_messages_consumer_failure() {
        let (config, mut consumer, consensus, execution, prover, verifier) = setup_test();

        consumer
            .expect_consume()
            .returning(move |_| Err(eyre!("Consumer failed")));

        let mut relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
        )
        .await;

        let fetched_logs = relayer.collect_messages(1).await;
        assert_eq!(fetched_logs.len(), 0);
    }

    #[tokio::test]
    async fn test_get_update() {
        let (config, consumer, mut consensus, execution, prover, verifier) = setup_test();
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
            verifier,
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
        let (config, consumer, consensus, execution, prover, verifier) = setup_test();
        let relayer = Relayer::new(
            config,
            consumer,
            Arc::new(consensus),
            Arc::new(execution),
            Arc::new(prover),
            verifier,
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
