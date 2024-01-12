use std::process::Command;

use crate::{
    types::{LightClientStateResult, UpdateExecuteMsg},
    utils::calc_sync_period,
};
use consensus_types::{consensus::Update, lightclient::LightClientState};
use eyre::Result;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Verifier {
    rpc: String,
    address: String,
}

#[allow(dead_code)]
impl Verifier {
    pub fn new(rpc: String, address: String) -> Self {
        Self { rpc, address }
    }

    pub async fn get_period(&mut self) -> Result<u64> {
        let state = self.get_state().await?;
        let period = calc_sync_period(state.update_slot);
        Ok(period)
    }

    pub async fn get_state(&mut self) -> Result<LightClientState> {
        let cmd = "axelard";
        let args = [
            "query",
            "wasm",
            "contract-state",
            "smart",
            self.address.as_str(),
            "{\"light_client_state\": {}}",
            "--node",
            self.rpc.as_str(),
            "--output",
            "json",
        ];

        let output = Command::new(cmd).args(args).output()?;

        let state = serde_json::from_slice::<LightClientStateResult>(&output.stdout)?;

        Ok(state.data)
    }

    // Placeholder function which will be substituted with the API that will be provided
    pub async fn update(&self, update: Update) -> Result<()> {
        let cmd = "axelard";

        let message = UpdateExecuteMsg {
            light_client_update: update,
        };

        let args = [
            "tx",
            "wasm",
            "execute",
            self.address.as_str(),
            &serde_json::to_string(&message)?,
            "--from",
            "pkakelas",
            "--node",
            self.rpc.as_str(),
            "--gas-prices",
            "0.0001uwasm",
            "--gas",
            "100000000",
            "-y",
        ];

        let output = Command::new(cmd).args(args).output()?;

        if !output.status.success() {
            println!("Error updating light client: {:?}", output);
            return Err(eyre::eyre!("Error updating light client"));
        }

        Ok(())
    }
}
