use reqwest::StatusCode;
use serde::de::DeserializeOwned;

use crate::error::RPCError;

const GENESIS_TIME: u64 = 1606824023;

pub fn calc_slot_from_timestamp(timestamp: u64) -> u64 {
    (timestamp - GENESIS_TIME) / 12
}

pub async fn get<R: DeserializeOwned>(req: &str) -> Result<R, RPCError> {
    let response = match reqwest::get(req).await {
        Ok(resp) => resp,
        Err(e) => return Err(RPCError::RequestError(req.to_string(), e)),
    };

    match response.status() {
        StatusCode::OK => {
            let bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => return Err(RPCError::RequestError(req.to_string(), e)),
            };
            serde_json::from_slice::<R>(&bytes)
                .map_err(|e| RPCError::DeserializationError(e.to_string()))
        }
        StatusCode::NOT_FOUND => Err(RPCError::NotFoundError(req.to_string())),
        StatusCode::TOO_MANY_REQUESTS => Err(RPCError::RateLimitError(req.to_string())),
        _ => Err(RPCError::UnknownError(req.to_string())),
    }
}
