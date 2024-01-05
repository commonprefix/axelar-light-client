use consensus_types::{consensus::Update, lightclient::LightClientState};
use cosmos_sdk_proto::cosmwasm::wasm::v1::{
    query_client::QueryClient, QuerySmartContractStateRequest,
};
use eyre::Result;
use futures::executor::block_on;
use log::error;
use serde::de::DeserializeOwned;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Verifier {
    _rpc: String,
    address: String,
    query_client: QueryClient<tonic::transport::Channel>,
}

#[allow(dead_code)]
impl Verifier {
    pub fn new(rpc: String, address: String) -> Self {
        Self {
            query_client: block_on(QueryClient::connect(rpc.clone())).unwrap(),
            _rpc: rpc,
            address,
        }
    }

    pub async fn get_period(&mut self) -> Result<u64> {
        let state = self.get_state().await?;
        let period = state.update_slot / 32 / 256;
        Ok(period)
    }

    pub async fn get_state(&mut self) -> Result<LightClientState> {
        let query_data = b"{\"light_client_state\": {}}".to_vec();
        let state = self.query(query_data).await?;
        Ok(state)
    }

    pub async fn update(&self, _update: Update) -> Result<()> {
        Ok(())
    }

    async fn query<T: DeserializeOwned>(&mut self, query_data: Vec<u8>) -> Result<T> {
        let query_msg = QuerySmartContractStateRequest {
            address: self.address.clone(),
            query_data,
        };

        let response = self
            .query_client
            .smart_contract_state(query_msg)
            .await
            .map_err(|e| {
                error!("Error querying smart contract state: {:?}", e);
                e
            })?;

        let response_data = response.into_inner().data;
        let state: T = serde_json::from_slice(&response_data)?;
        Ok(state)
    }
}
