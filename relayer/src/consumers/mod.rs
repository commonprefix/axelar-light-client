mod ethers_consumer;
mod lapin_consumer;

use async_trait::async_trait;
use eyre::Result;

pub use ethers_consumer::EthersConsumer;
pub use lapin_consumer::{LapinConsumer, MockLapinConsumer};

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
