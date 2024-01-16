use super::Amqp;
use async_trait::async_trait;
use eyre::{eyre, Ok, Result};
use futures::StreamExt;
use lapin::{
    options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions},
    types::FieldTable,
    Channel, Connection, ConnectionProperties, Consumer,
};
use log::{info, debug};
use mockall::automock;

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
            println!("Got delivery");
            let (_, delivery) = delivery.expect("Error in consumer");
            deliveries.push(delivery);
            count += 1;
            debug!("Got delivery {}", count);

            if count >= max_deliveries {
                debug!("breaking");
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
        debug!("Nacking delivery {}", delivery_tag);

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
        debug!("Acking delivery {}", delivery_tag);
        self.channel
            .basic_ack(delivery_tag, BasicAckOptions::default())
            .await
            .map_err(|e| eyre!("Error nacking delivery {} {}", delivery_tag, e))?;

        Ok(())
    }
}
