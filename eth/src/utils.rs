use eyre::Result;
use retri::{retry, BackoffSettings};
use serde::de::DeserializeOwned;

const GENESIS_TIME: u64 = 1606824023;

pub fn calc_slot_from_timestamp(timestamp: u64) -> u64 {
    (timestamp - GENESIS_TIME) / 12
}

pub async fn get<R: DeserializeOwned>(req: &str) -> Result<R> {
    let bytes = retry(
        || async { Ok::<_, eyre::Report>(reqwest::get(req).await?.bytes().await?) },
        BackoffSettings::default(),
    )
    .await?;

    Ok(serde_json::from_slice::<R>(&bytes)?)
}
