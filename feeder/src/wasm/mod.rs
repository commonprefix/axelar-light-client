use consensus_types::lightclient::LightClientState;
use cosmos_sdk_proto::cosmwasm::wasm::v1::{
    query_client::QueryClient, QuerySmartContractStateRequest,
};
use eyre::Result;
use futures::executor::block_on;
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub struct WasmClient {
    _rpc: String,
    address: String,
    query_client: QueryClient<tonic::transport::Channel>,
}

impl WasmClient {
    pub fn new(rpc: String, address: String) -> Self {
        Self {
            query_client: block_on(QueryClient::connect(rpc.clone())).unwrap(),
            _rpc: rpc,
            address,
        }
    }

    pub async fn get_period(&mut self) -> Result<u64> {
        let state = self.get_state().await?;
        let period = state.finalized_header.slot / 32 / 256;
        Ok(period)
    }

    pub async fn get_state(&mut self) -> Result<LightClientState> {
        let query_data = b"{\"light_client_state\": {}}".to_vec();
        let state = self.query(query_data).await?;
        return Ok(state);
    }

    pub async fn update() -> Result<()> {
        todo!()
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
                eprintln!("Error querying smart contract state: {:?}", e);
                e
            })?;

        let response_data = response.into_inner().data;
        let state: T = serde_json::from_slice(&response_data)?;
        Ok(state)
    }
}
