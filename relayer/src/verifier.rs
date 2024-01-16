use std::process::Command;

use crate::{
    types::{
        BatchVerificationDataRequest, IsVerifiedMessages, IsVerifiedRequest, IsVerifiedResponse,
        IsWorkerSetVerifiedRequest, IsWorkerSetVerifiedResult, LightClientStateResult,
        UpdateExecuteMsg, VerifyDataResponse,
    },
    utils::calc_sync_period,
};
use async_trait::async_trait;
use consensus_types::{
    common::{VerificationResult, WorkerSetMessage},
    consensus::Update,
    lightclient::LightClientState,
    proofs::{BatchVerificationData, Message},
};
use ethers::utils::hex;
use eyre::Result;
use log::error;
// use log::debug;
use mockall::automock;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Verifier {
    rpc: String,
    address: String,
}

#[automock]
#[async_trait]
pub trait VerifierAPI {
    async fn get_period(&mut self) -> Result<u64>;
    async fn is_message_verified(&mut self, messages: Vec<Message>)
        -> Result<Vec<(Message, bool)>>;
    async fn is_worker_set_verified(&mut self, worker_set_msg: WorkerSetMessage) -> Result<bool>;
    async fn update(&self, update: Update) -> Result<()>;
    async fn verify_data(
        &self,
        verification_data: BatchVerificationData,
    ) -> Result<VerificationResult>;
}

impl Verifier {
    pub fn new(rpc: String, address: String) -> Self {
        Self { rpc, address }
    }

    async fn get_state(&mut self) -> Result<LightClientState> {
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

        let _command_line = format!("{} {}", cmd, args.join(" "));
        // debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        // debug!("Output: {:?}", output);

        let state = serde_json::from_slice::<LightClientStateResult>(&output.stdout)?;

        Ok(state.data)
    }
}

#[async_trait]
impl VerifierAPI for Verifier {
    async fn get_period(&mut self) -> Result<u64> {
        let state = self.get_state().await?;
        let period = calc_sync_period(state.update_slot);
        Ok(period)
    }

    async fn is_message_verified(
        &mut self,
        messages: Vec<Message>,
    ) -> Result<Vec<(Message, bool)>> {
        let is_verified = IsVerifiedRequest {
            is_verified: IsVerifiedMessages { messages },
        };

        let cmd = "axelard";
        let args = [
            "query",
            "wasm",
            "contract-state",
            "smart",
            self.address.as_str(),
            &serde_json::to_string(&is_verified)?,
            "--node",
            self.rpc.as_str(),
            "--output",
            "json",
        ];

        let _command_line = format!("{} {}", cmd, args.join(" "));
        // debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        // debug!("Output: {:?}", output);

        let is_verified = serde_json::from_slice::<IsVerifiedResponse>(&output.stdout)?;

        Ok(is_verified.data)
    }

    async fn is_worker_set_verified(&mut self, worker_set_msg: WorkerSetMessage) -> Result<bool> {
        let message = IsWorkerSetVerifiedRequest {
            is_worker_set_verified: worker_set_msg,
        };

        let cmd = "axelard";
        let args = [
            "query",
            "wasm",
            "contract-state",
            "smart",
            self.address.as_str(),
            &serde_json::to_string(&message)?,
            "--node",
            self.rpc.as_str(),
            "--output",
            "json",
        ];

        let _command_line = format!("{} {}", cmd, args.join(" "));
        // debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        // debug!("Output: {:?}", output);

        let state = serde_json::from_slice::<IsWorkerSetVerifiedResult>(&output.stdout)?;

        Ok(state.data)
    }

    // Placeholder function which will be substituted with the API that will be provided
    async fn update(&self, update: Update) -> Result<()> {
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

        // let command_line = format!("{} {}", cmd, args.join(" "));
        // debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        // debug!("Output: {:?}", output);

        if !output.status.success() {
            error!("Error updating light client: {:?}", output);
            return Err(eyre::eyre!("Error updating light client"));
        }

        Ok(())
    }

    async fn verify_data(
        &self,
        verification_data: BatchVerificationData,
    ) -> Result<VerificationResult> {
        let cmd = "axelard";

        let message = BatchVerificationDataRequest {
            batch_verification_data: verification_data,
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
        // debug!("Output: {:?}", output);

        if !output.status.success() {
            error!("Error updating light client: {:?}", output);
            return Err(eyre::eyre!("Error updating light client"));
        }

        let result: VerifyDataResponse = serde_json::from_slice(&output.stdout)?;
        let decoded = hex::decode(result.data)?;
        let str = String::from_utf8_lossy(&decoded);

        if let Some(json_start_index) = str.find("[[") {
            let json_string = &str[json_start_index..];
            let res: VerificationResult = cosmwasm_std::from_json(json_string).unwrap();
            return Ok(res);
        }

        Err(eyre::eyre!("Error decoding verification result"))
    }
}
