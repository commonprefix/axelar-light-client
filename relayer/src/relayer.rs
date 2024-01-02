use std::sync::Arc;

use async_trait::async_trait;
use consensus_types::proofs::UpdateVariant;
use eth::{execution::ExecutionRPC, consensus::{ConsensusRPC, EthBeaconAPI}, utils::get_full_block_details};
use prover::{Prover, prover::{proof_generator::ProofGeneratorAPI, types::EnrichedContent}};
use eyre::{Result, eyre};
use crate::{types::{Config, VerificationMethod, EnrichedLog}, parser::parse_enriched_log};

#[async_trait]
pub trait RelayerAPI {
    async fn digest_messages(&self, messages: &Vec<EnrichedLog>) -> Result<()>;
}

pub struct Relayer<PG> {
    config: Config,
    consensus: Arc<ConsensusRPC>,
    execution: Arc<ExecutionRPC>,
    prover: Prover<PG>
}

impl<PG: ProofGeneratorAPI> Relayer<PG> {
    pub fn new(config: Config, consensus: Arc<ConsensusRPC>, execution: Arc<ExecutionRPC>, prover: Prover<PG>) -> Self {
        Relayer { config, consensus, execution, prover } 
    }

    pub async fn digest_messages(&self, enriched_logs: &Vec<EnrichedLog>) -> Result<()> {
        let update = self.get_update(&self.config.verification_method).await?;
        println!("Got update {:#?}", update);

        let contents = self.generate_enriched_contents(enriched_logs).await?;
        println!("Generated enriched contents {:#?}", contents);
        let batch_contents = self.prover.batch_messages(&contents, &update).await?;
        let batch_verification_data = self.prover.batch_generate_proofs(batch_contents, update).await?;

        println!("Generated batch verification data {:?}", batch_verification_data);

        // TODO: Send batch verification data to cosmwasm

        Ok(())
    }

    async fn get_update(&self, verification_method: &VerificationMethod) -> Result<UpdateVariant> {
        match verification_method {
            VerificationMethod::Finality => match self.consensus.get_finality_update().await {
                Ok(update) => Ok(UpdateVariant::Finality(update)),
                Err(e) => Err(eyre!("Error fetching finality update {}", e))
            }
            VerificationMethod::Optimistic => match self.consensus.get_optimistic_update().await {
                Ok(update) => Ok(UpdateVariant::Optimistic(update)),
                Err(e) => Err(eyre!("Error fetching finality update {}", e))
            }
        }
    }

    async fn generate_enriched_contents(&self, enriched_logs: &Vec<EnrichedLog>) -> Result<Vec<EnrichedContent>>{
        let mut contents: Vec<EnrichedContent>  = vec![];
        for enriched_log in enriched_logs {
            println!("Working on log {}", enriched_log.event_name);
            let block_details = get_full_block_details(
                self.consensus.clone(),
                self.execution.clone(),
                enriched_log.log.block_number.unwrap().as_u64(),
                self.config.genesis_timestamp
            ).await?;

            let content = parse_enriched_log(enriched_log, &block_details)?;
            contents.push(content)
        }

        Ok(contents)
    }
}
