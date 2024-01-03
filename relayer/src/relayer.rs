use std::{sync::Arc, time::Duration, collections::HashMap};
use async_trait::async_trait;
use consensus_types::proofs::{UpdateVariant, BatchVerificationData, ContentVariant};
use eth::{execution::ExecutionRPC, consensus::{ConsensusRPC, EthBeaconAPI}, utils::get_full_block_details};
use futures::StreamExt;
use lapin::{message::Delivery, Consumer, options::{BasicNackOptions, BasicConsumeOptions}, Channel, types::FieldTable};
use prover::{Prover, prover::{proof_generator::ProofGeneratorAPI, types::EnrichedContent}};
use eyre::{Result, eyre};
use tokio::time::interval;
use crate::{types::{Config, VerificationMethod, EnrichedLog}, parser::parse_enriched_log};

#[async_trait]
pub trait RelayerAPI {
    async fn start(&self);
    async fn digest_messages(&self, messages: &Vec<EnrichedLog>) -> Result<()>;
}

pub struct Relayer<PG> {
    config: Config,
    consensus: Arc<ConsensusRPC>,
    channel: Channel,
    consumer: Consumer,
    execution: Arc<ExecutionRPC>,
    prover: Prover<PG>,
}

impl<PG: ProofGeneratorAPI> Relayer<PG> {
    pub async fn new(config: Config, channel: Channel, consensus: Arc<ConsensusRPC>, execution: Arc<ExecutionRPC>, prover: Prover<PG>) -> Self {
        let consumer = channel
            .basic_consume(config.sentinel_queue_name.as_str(), "relayer", BasicConsumeOptions::default(), FieldTable::default())
            .await.unwrap();

        Relayer { config, channel, consumer, consensus, execution, prover} 
    }

    pub async fn start(&mut self) -> Result<()> {
        let mut interval = interval(Duration::from_secs(self.config.process_interval));

        loop {
            interval.tick().await;

            let update = self.get_update(&self.config.verification_method).await.map_err(|e| eyre!("Error fetching update {}", e));
            if update.is_err() {
                println!("Error fetching update {:?}", update);
                continue;
            }

            let fetched_logs = self.collect_messages(self.config.max_batch_size).await;

            let contents = self.process_logs(fetched_logs).await;
            let mut successful_contents = vec![];
            let mut delivery_tags = vec![];
            for (delivery_tag, content) in contents {
                if content.is_none() {
                    self.nack_delivery(delivery_tag).await?;
                }
                else {
                    delivery_tags.push(delivery_tag);
                    successful_contents.push(content.unwrap()); 
                }
            }

            let batch_contents = self.prover.batch_messages(&successful_contents);
            let batch_verification_data: std::prelude::v1::Result<BatchVerificationData, eyre::Error> = self.prover.batch_generate_proofs(batch_contents, update.unwrap()).await;
            if batch_verification_data.is_err() {
                println!("Error generating proofs {:?}", batch_verification_data);
                continue;
            }

            let processed_messages = Self::extract_all_contents(&batch_verification_data.unwrap());
            for (i, content) in successful_contents.iter().enumerate() {
                let delivery_tag = delivery_tags[i];
                if processed_messages.contains(&content.content) {
                    println!("Message {:?} succeeded", content);
                    // TODO: Change to ack
                    self.nack_delivery(delivery_tag).await?;
                }
                else {
                    println!("Message {:?} failed", content);
                    self.nack_delivery(delivery_tag).await?;
                }
            }

            println!("Processed {} messages", processed_messages.len());
        };
    }

    async fn process_logs(&mut self, fetched_logs: HashMap<u64, EnrichedLog>) -> Vec<(u64, Option<EnrichedContent>)> {
        let mut contents: Vec<(u64, Option<EnrichedContent>)> = vec![];

        for (delivery_tag, enriched_log) in fetched_logs {
            println!("Working on log {}", enriched_log.event_name);
            let block_details = get_full_block_details(
                self.consensus.clone(),
                self.execution.clone(),
                enriched_log.log.block_number.unwrap().as_u64(),
                self.config.genesis_timestamp
            ).await;

            if block_details.is_err() {
                println!("Error fetching block details {:?}. Requeuing", block_details);
                contents.push((delivery_tag, None));
            }

            let content = parse_enriched_log(&enriched_log, &block_details.unwrap());
            if content.is_err() {
                println!("Error parsing enriched log {:?} {:?}. Requeuing", enriched_log, content.err());
                contents.push((delivery_tag, None));
                continue
            }

            let content = content.unwrap();
            contents.push((delivery_tag, Some(content)))
        }

        contents
    }

    async fn collect_messages(&mut self, max_messages: usize) -> HashMap<u64, EnrichedLog> {
        let mut deliveries = Vec::with_capacity(max_messages);
        let mut count = 0;
      
        while let Some(delivery) = self.consumer.next().await {
            let (_, delivery) = delivery.expect("Error in consumer");
            deliveries.push(delivery);
            count += 1;
    
            if count >= max_messages {
                break;
            }
        }
        println!("Got {} logs from sentinel", deliveries.len());
    
        let mut enriched_logs: HashMap<u64, EnrichedLog> = HashMap::new();
        for delivery in deliveries {
            let enriched_log = serde_json::from_slice(&delivery.data);
            if enriched_log.is_err() {
                println!("Error parsing log {:?}", enriched_log);
                continue;
            }
            enriched_logs.insert(delivery.delivery_tag, enriched_log.unwrap());
        };
    
        return enriched_logs;
    }

    async fn get_update(&self, verification_method: &VerificationMethod) -> Result<UpdateVariant> {
        match verification_method {
            VerificationMethod::Finality => match self.consensus.get_finality_update().await {
                Ok(update) => Ok(UpdateVariant::Finality(update)),
                Err(e) => Err(eyre!("Error fetching finality update {}", e))
            }
            VerificationMethod::Optimistic => match self.consensus.get_optimistic_update().await {
                Ok(update) => Ok(UpdateVariant::Optimistic(update)),
                Err(e) => Err(eyre!("Error fetching finality update {}", e))
            }
        }
    }

    pub fn extract_all_contents(data: &BatchVerificationData) -> Vec<ContentVariant> {
        data.target_blocks.iter()
            .flat_map(|block| &block.transactions_proofs)
            .flat_map(|transaction| &transaction.content)
            .cloned() // Clone each ContentVariant, required if ContentVariant does not implement Copy
            .collect()
    }

    async fn nack_delivery(&self, delivery_tag: u64) -> Result<()> {
        let requeue_nack = BasicNackOptions {
            requeue: true,
            ..Default::default()
        };

        self.channel.basic_nack(delivery_tag, requeue_nack).await
            .map_err(|e| eyre!("Error nacking delivery {} {}", delivery_tag, e))?;

        Ok(())
    }
}
