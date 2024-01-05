use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::StreamExt;
use lapin::{
    options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions},
    types::FieldTable,
    Channel, Connection, ConnectionProperties, Consumer,
};
use log::info;
use mockall::automock;

// The basic RabbitMQ consumer.
#[async_trait]
pub trait Amqp {
    // It consumes a set of messages from the queue up to a given limit.
    // Returns a vector of tuples containing the delivery tag and the message.
    async fn consume(&mut self, max_deliveries: usize) -> Result<Vec<(u64, String)>>;
    // It acks a delivery.
    async fn ack_delivery(&self, delivery_tag: u64) -> Result<()>;
    // It nacks a delivery with a nacking strategy forcing a requeue.
    async fn nack_delivery(&self, delivery_tag: u64) -> Result<()>;
}

pub struct LapinConsumer {
    channel: Channel,
    consumer: Consumer,
}

impl LapinConsumer {
    pub async fn new(queue_addr: &str, queue_name: &str) -> Self {
        let connection = Connection::connect(queue_addr, ConnectionProperties::default())
            .await
            .unwrap();
        let channel = connection.create_channel().await.unwrap();
        let consumer = channel
            .basic_consume(
                queue_name,
                "relayer",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .unwrap();

        Self { channel, consumer }
    }
}

#[automock]
#[async_trait]
impl Amqp for LapinConsumer {
    async fn consume(&mut self, max_deliveries: usize) -> Result<Vec<(u64, String)>> {
        let mut deliveries = Vec::with_capacity(max_deliveries);
        let mut count = 0;

        while let Some(delivery) = self.consumer.next().await {
            let (_, delivery) = delivery.expect("Error in consumer");
            deliveries.push(delivery);
            count += 1;

            if count >= max_deliveries {
                break;
            }
        }
        info!("Got {} logs from sentinel", deliveries.len());

        let result = deliveries
            .iter()
            .map(|delivery| {
                (
                    delivery.delivery_tag,
                    std::str::from_utf8(&delivery.data).unwrap().to_string(),
                )
            })
            .collect();

        Ok(result)
    }

    async fn nack_delivery(&self, delivery_tag: u64) -> Result<()> {
        let requeue_nack = BasicNackOptions {
            requeue: true,
            ..Default::default()
        };

        self.channel
            .basic_nack(delivery_tag, requeue_nack)
            .await
            .map_err(|e| eyre!("Error nacking delivery {} {}", delivery_tag, e))?;

        Ok(())
    }

    async fn ack_delivery(&self, delivery_tag: u64) -> Result<()> {
        self.channel
            .basic_ack(delivery_tag, BasicAckOptions::default())
            .await
            .map_err(|e| eyre!("Error nacking delivery {} {}", delivery_tag, e))?;

        Ok(())
    }
}

// pub struct Gateway {
//     consensus: Arc<ConsensusRPC>,
//     execution: Arc<ExecutionRPC>,
//     address: Address,
// }
// impl Gateway {
//     pub fn new(
//         consensus: Arc<ConsensusRPC>,
//         execution: Arc<ExecutionRPC>,
//         address: String,
//     ) -> Self {
//         let address = address.parse::<Address>().unwrap();

//         Self {
//             consensus,
//             execution,
//             address,
//         }
//     }

//     pub async fn get_contract_call_with_token_messages(
//         &self,
//         from_block: u64,
//         to_block: u64,
//         limit: u64,
//     ) -> Result<Vec<EnrichedLog>> {
//         let logs = self
//             .get_contract_call_with_token_logs(from_block, to_block, limit)
//             .await?;
//         println!("Got logs {:?}", logs.len());

//         let enriched_logs = logs.iter().map(|log|
//             EnrichedLog {
//                 log: log.clone(),
//                 event_name: "ContractCallWithToken".to_string(),
//                 contract_name: "gateway".to_string(),
//                 chain: "ethereum".to_string(),
//                 source: "source".to_string(),
//                 tx_to: H160::default(),

//         }).collect();

//         Ok(enriched_logs)
//     }

//     async fn get_contract_call_with_token_logs(
//         &self,
//         from_block: u64,
//         to_block: u64,
//         limit: u64,
//     ) -> Result<Vec<Log>> {
//         let signature = "ContractCallWithToken(address,string,string,bytes32,bytes,string,uint256)";

//         let filter = Filter::new()
//             .address(self.address)
//             .event(signature)
//             .from_block(from_block)
//             .to_block(to_block);

//         let logs = self.execution.provider.get_logs(&filter).await?;
//         println!("Got logs {:?}", logs.len());

//         let mut limited = vec![];
//         for i in 0..limit {
//             limited.push(logs[i as usize].clone());
//         }

//         Ok(limited)
//     }

//     pub async fn get_logs_in_slot_range(
//         &self,
//         from_slot: u64,
//         to_slot: u64,
//         limit: u64,
//     ) -> Result<Vec<EnrichedLog>> {
//         let beacon_block_from = self.consensus.get_beacon_block(from_slot).await?;
//         let beacon_block_to = self.consensus.get_beacon_block(to_slot).await?;
//         println!("Got beacon blocks {}, {}", beacon_block_from.slot, beacon_block_to.slot);

//         let messages = self
//             .get_contract_call_with_token_messages(
//                 beacon_block_from.body.execution_payload.block_number,
//                 beacon_block_to.body.execution_payload.block_number,
//                 limit,
//             )
//             .await?;

//         Ok(messages)
//     }
// }
