use std::process::Command;

use crate::{
    types::{
        BatchVerificationDataRequest, BatchVerificationPayload, IsVerifiedMessages,
        IsVerifiedRequest, IsVerifiedResponse, IsWorkerSetVerifiedRequest,
        IsWorkerSetVerifiedResult, LightClientStateResult, UpdateExecuteMsg, VerifyDataResponse,
    },
    utils::calc_sync_period,
};
use consensus_types::{
    common::{WorkerSetMessage, VerificationResult},
    consensus::Update,
    lightclient::LightClientState,
    proofs::{BatchVerificationData, Message},
};
use ethers::utils::hex;
use eyre::Result;
use log::debug;
use serde::{Serialize, Deserialize};

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

        let command_line = format!("{} {}", cmd, args.join(" "));
        debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        debug!("Output: {:?}", output);

        let state = serde_json::from_slice::<LightClientStateResult>(&output.stdout)?;

        Ok(state.data)
    }

    pub async fn is_message_verified(
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

        let command_line = format!("{} {}", cmd, args.join(" "));
        debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        debug!("Output: {:?}", output);

        let is_verified = serde_json::from_slice::<IsVerifiedResponse>(&output.stdout)?;

        Ok(is_verified.data)
    }

    pub async fn is_worker_set_verified(
        &mut self,
        worker_set_msg: WorkerSetMessage,
    ) -> Result<bool> {
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

        let command_line = format!("{} {}", cmd, args.join(" "));
        debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        debug!("Output: {:?}", output);

        let state = serde_json::from_slice::<IsWorkerSetVerifiedResult>(&output.stdout)?;

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

        let command_line = format!("{} {}", cmd, args.join(" "));
        debug!("Command to be executed: {}", command_line);

        let output = Command::new(cmd).args(args).output()?;
        debug!("Output: {:?}", output);

        if !output.status.success() {
            println!("Error updating light client: {:?}", output);
            return Err(eyre::eyre!("Error updating light client"));
        }

        Ok(())
    }

    pub async fn verify_data(&self, verification_data: BatchVerificationData) -> Result<VerificationResult> {
        let cmd = "axelard";

        let message = BatchVerificationDataRequest {
            batch_verification_data: BatchVerificationPayload {
                payload: verification_data,
            },
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
        debug!("Output: {:?}", output);

        if !output.status.success() {
            println!("Error updating light client: {:?}", output);
            return Err(eyre::eyre!("Error updating light client"));
        }

        let result: VerifyDataResponse = serde_json::from_slice(&output.stdout)?; 
        let decoded = hex::decode(result.data)?;
        let str = String::from_utf8_lossy(&decoded);

        if let Some(json_start_index) = str.find("[[") {
            println!("json_start_index: {}", json_start_index);
            let json_string = &str[json_start_index..];
            println!("json_string: {}", json_string);
            let res: VerificationResult = cosmwasm_std::from_json(json_string).unwrap();
            println!("res: {:?}", res);
            return Ok(res);
        }

        Err(eyre::eyre!("Error decoding verification result"))
    }
}
