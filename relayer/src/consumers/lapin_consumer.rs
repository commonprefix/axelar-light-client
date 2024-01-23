use super::Amqp;
use async_trait::async_trait;
use eyre::{eyre, Result};
use lapin::{
    options::{BasicAckOptions, BasicGetOptions, BasicNackOptions},
    Channel, Connection, ConnectionProperties,
};
use log::{debug, info};
use mockall::automock;

pub struct LapinConsumer {
    queue_name: String,
    channel: Channel,
}

impl LapinConsumer {
    pub async fn new(queue_addr: &str, queue_name: String) -> Self {
        let connection = Connection::connect(queue_addr, ConnectionProperties::default())
            .await
            .unwrap();
        let channel = connection.create_channel().await.unwrap();

        Self {
            queue_name,
            channel,
        }
    }
}

#[automock]
#[async_trait]
impl Amqp for LapinConsumer {
    async fn consume(&mut self, max_deliveries: usize) -> Result<Vec<(u64, String)>> {
        let mut deliveries = Vec::with_capacity(max_deliveries);

        while deliveries.len() < max_deliveries {
            let message = self
                .channel
                .basic_get(self.queue_name.as_str(), BasicGetOptions::default())
                .await?;

            match message {
                Some(message) => {
                    println!("Got message: {:?}", message.delivery);
                    deliveries.push(message.delivery);
                }
                None => {
                    println!("Queue is empty");
                    break; // Queue is empty, break the loop
                }
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
