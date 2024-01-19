pub mod error;
pub mod helpers;
pub mod tests;

use cosmwasm_std::Env;
use error::ConsensusError;
use eyre::Result;
use helpers::is_proof_valid;
use milagro_bls::{AggregateSignature, PublicKey};
use types::common::ChainConfig;
use types::ssz_rs::prelude::*;
use types::sync_committee_rs::constants::{
    Version, ALTAIR_FORK_EPOCH, ALTAIR_FORK_VERSION, BELLATRIX_FORK_EPOCH, BELLATRIX_FORK_VERSION,
    CAPELLA_FORK_EPOCH, CAPELLA_FORK_VERSION, DENEB_FORK_EPOCH, DENEB_FORK_VERSION,
    GENESIS_FORK_VERSION,
};
use types::sync_committee_rs::{
    consensus_types::{BeaconBlockHeader, ForkData, SyncCommittee},
    constants::{BlsSignature, Bytes32, SYNC_COMMITTEE_SIZE},
    util::SigningData,
};
use types::{consensus::*, lightclient::LightClientState};

use self::helpers::calc_sync_period;

pub struct LightClient {
    pub state: LightClientState,
    pub chain_config: ChainConfig,
    env: Env,
}

impl LightClient {
    pub fn new(chain_config: &ChainConfig, state: Option<LightClientState>, env: &Env) -> Self {
        let state = state.unwrap_or_default();
        Self {
            state,
            chain_config: chain_config.clone(),
            env: env.clone(),
        }
    }

    /// Initializes the state of the Light Client using a LightClientBootstrap message.
    pub fn bootstrap(&mut self, bootstrap: &Bootstrap) -> Result<(), ConsensusError> {
        let committee_valid = self.is_current_committee_proof_valid(
            &bootstrap.header.beacon,
            &bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
        );

        if !committee_valid {
            return Err(ConsensusError::InvalidCurrentSyncCommitteeProof);
        }

        self.state = LightClientState {
            update_slot: bootstrap.header.beacon.slot,
            current_sync_committee: bootstrap.current_sync_committee.clone(),
            next_sync_committee: None,
        };

        Ok(())
    }

    pub fn verify_update(&self, update: &Update) -> Result<(), ConsensusError> {
        self.verify_finality_update(&FinalityUpdate::from(update))?;

        // Check that next committe in attested header
        let is_valid = self.is_next_committee_proof_valid(
            &update.attested_header.beacon,
            &mut update.next_sync_committee.clone(),
            &update.next_sync_committee_branch,
        );

        if !is_valid {
            return Err(ConsensusError::InvalidNextSyncCommitteeProof);
        }

        Ok(())
    }

    pub fn verify_finality_update(&self, update: &FinalityUpdate) -> Result<(), ConsensusError> {
        self.verify_optimistic_update(&OptimisticUpdate::from(update))?;

        // Check for valid timestamp conditions:
        // 1. The attested header's slot should be equal or greater than the finalized header's slot.
        if update.attested_header.beacon.slot < update.finalized_header.beacon.slot {
            return Err(ConsensusError::InvalidTimestamp);
        }

        let is_valid = self.is_finality_proof_valid(
            &update.attested_header.beacon,
            &mut update.finalized_header.beacon.clone(),
            &update.finality_branch,
        );

        if !is_valid {
            return Err(ConsensusError::InvalidFinalityProof);
        }

        Ok(())
    }

    pub fn verify_optimistic_update(
        &self,
        update: &OptimisticUpdate,
    ) -> Result<(), ConsensusError> {
        // Check if there's any participation in the sync committee at all.
        let bits = self.get_bits(&update.sync_aggregate.sync_committee_bits);
        if bits == 0 {
            return Err(ConsensusError::InsufficientParticipation);
        }

        // Check for valid timestamp conditions:
        // 1. The expected current slot given the genesis time should be equal or greater than the update's signature slot.
        // 2. The slot of the update's signature should be greater than the slot of the attested header.
        let valid_time = self.expected_current_slot() >= update.signature_slot
            && update.signature_slot > update.attested_header.beacon.slot;

        if !valid_time {
            return Err(ConsensusError::InvalidTimestamp);
        }

        let store_period = calc_sync_period(self.state.update_slot);
        let update_sig_period = calc_sync_period(update.signature_slot);

        let valid_period = if self.state.next_sync_committee.is_some() {
            update_sig_period == store_period || update_sig_period == store_period + 1
        } else {
            update_sig_period == store_period
        };

        if !valid_period {
            return Err(ConsensusError::InvalidPeriod);
        }

        // Calculate the period for the attested header and check its relevance.
        // Ensure the attested header isn't already finalized unless the update introduces a new sync committee.
        let update_attested_period = calc_sync_period(update.attested_header.beacon.slot);
        let update_has_next_committee =
            self.state.next_sync_committee.is_none() && update_attested_period == store_period;

        if update.attested_header.beacon.slot <= self.state.update_slot
            && !update_has_next_committee
        {
            return Err(ConsensusError::NotRelevant);
        }

        // Verify the sync committee's aggregate signature for the attested header.
        let sync_committee = if update_sig_period == store_period {
            self.state.current_sync_committee.clone()
        } else {
            self.state.next_sync_committee.clone().unwrap()
        };

        let pks = self
            .get_participating_keys(&sync_committee, &update.sync_aggregate.sync_committee_bits);

        let is_valid_sig = self.verify_sync_committee_signature(
            &self.chain_config,
            &pks,
            &update.attested_header.beacon,
            &update.sync_aggregate.sync_committee_signature,
            update.signature_slot,
        );

        if !is_valid_sig {
            return Err(ConsensusError::InvalidSignature);
        }

        Ok(())
    }

    pub fn apply_update(&mut self, update: &Update) -> Result<(), ConsensusError> {
        self.verify_update(update)?;

        let committee_bits = self.get_bits(&update.sync_aggregate.sync_committee_bits);

        let update_finalized_slot = update.finalized_header.beacon.slot;
        let update_attested_period = calc_sync_period(update.attested_header.beacon.slot);
        let update_finalized_period = calc_sync_period(update_finalized_slot);

        let update_has_finalized_next_committee = update_finalized_period == update_attested_period;

        let should_apply_update = {
            let has_majority = committee_bits * 3 >= 512 * 2;
            let update_is_newer = update_finalized_slot > self.state.update_slot;
            let good_update = update_is_newer || update_has_finalized_next_committee;
            has_majority && good_update
        };

        if should_apply_update {
            let store_period = calc_sync_period(self.state.update_slot);

            if self.state.next_sync_committee.is_none() {
                self.state.next_sync_committee = Some(update.next_sync_committee.clone());
            } else if update_finalized_period == store_period + 1 {
                self.state.current_sync_committee = self.state.next_sync_committee.clone().unwrap();
                self.state.next_sync_committee = Some(update.next_sync_committee.clone());
            }

            if update_finalized_slot > self.state.update_slot {
                self.state.update_slot = update.finalized_header.beacon.slot;
                self.log_finality_update(update);
            }
        }

        Ok(())
    }

    fn is_current_committee_proof_valid(
        &self,
        attested_header: &BeaconBlockHeader,
        current_committee: &SyncCommittee<SYNC_COMMITTEE_SIZE>,
        current_committee_branch: &[Bytes32],
    ) -> bool {
        is_proof_valid(
            &attested_header.state_root,
            &mut current_committee.clone(),
            current_committee_branch,
            5,
            22,
        )
    }

    pub fn get_bits(&self, bitfield: &Bitvector<512>) -> u64 {
        let mut count = 0;
        bitfield.iter().for_each(|bit| {
            if bit == true {
                count += 1;
            }
        });

        count
    }

    fn expected_current_slot(&self) -> u64 {
        let since_genesis = self.env.block.time.seconds() - self.chain_config.genesis_time;

        since_genesis / 12
    }

    fn is_finality_proof_valid(
        &self,
        attested_header: &BeaconBlockHeader,
        finality_header: &mut BeaconBlockHeader,
        finality_branch: &[Bytes32],
    ) -> bool {
        is_proof_valid(
            &attested_header.state_root,
            finality_header,
            finality_branch,
            6,
            41,
        )
    }

    fn is_next_committee_proof_valid(
        &self,
        attested_header: &BeaconBlockHeader,
        next_committee: &mut SyncCommittee<SYNC_COMMITTEE_SIZE>,
        next_committee_branch: &[Bytes32],
    ) -> bool {
        is_proof_valid(
            &attested_header.state_root,
            next_committee,
            next_committee_branch,
            5,
            23,
        )
    }

    /**
     * Returns the fork version for a given slot.
     */
    fn get_fork_version(&self, slot: u64) -> Version {
        let epoch = slot / 32;

        match epoch {
            e if e >= DENEB_FORK_EPOCH => DENEB_FORK_VERSION,
            e if e >= CAPELLA_FORK_EPOCH => CAPELLA_FORK_VERSION,
            e if e >= BELLATRIX_FORK_EPOCH => BELLATRIX_FORK_VERSION,
            e if e >= ALTAIR_FORK_EPOCH => ALTAIR_FORK_VERSION,
            _ => GENESIS_FORK_VERSION,
        }
    }

    fn get_participating_keys(
        &self,
        committee: &SyncCommittee<SYNC_COMMITTEE_SIZE>,
        bitfield: &Bitvector<512>,
    ) -> Vec<PublicKey> {
        let mut pks: Vec<PublicKey> = Vec::new();
        bitfield.iter().enumerate().for_each(|(i, bit)| {
            if bit == true {
                let pk = &committee.public_keys[i];
                let pk = PublicKey::from_bytes_unchecked(pk).unwrap();
                pks.push(pk);
            }
        });

        pks
    }

    fn verify_sync_committee_signature<T>(
        &self,
        config: &ChainConfig,
        pks: &[PublicKey],
        attested_block: &T,
        signature: &BlsSignature,
        signature_slot: u64,
    ) -> bool
    where
        T: ssz_rs::Merkleized + Clone,
    {
        let res: Result<bool> = (move || {
            let pks: Vec<&PublicKey> = pks.iter().collect();
            let header_root = attested_block.clone().hash_tree_root()?;
            let signing_root =
                self.compute_committee_sign_root(config, header_root, signature_slot)?;

            Ok(self.is_aggregate_valid(signature, signing_root.as_ref(), &pks))
        })();

        if let Ok(is_valid) = res {
            is_valid
        } else {
            false
        }
    }

    pub fn is_aggregate_valid(
        &self,
        sig_bytes: &BlsSignature,
        msg: &[u8],
        pks: &[&PublicKey],
    ) -> bool {
        let sig_res = AggregateSignature::from_bytes(sig_bytes);
        match sig_res {
            Ok(sig) => sig.fast_aggregate_verify(msg, pks),
            Err(_) => false,
        }
    }

    fn compute_committee_sign_root(
        &self,
        config: &ChainConfig,
        header: Node,
        slot: u64,
    ) -> Result<Node> {
        let genesis_root = config.genesis_root;

        let domain_type = &hex::decode("07000000")?[..];
        let fork_version = self.get_fork_version(slot);
        let domain = self.compute_domain(domain_type, fork_version, genesis_root)?;
        self.compute_signing_root(header, domain)
    }

    pub fn compute_signing_root(&self, object_root: Node, domain: [u8; 32]) -> Result<Node> {
        let mut data = SigningData {
            object_root,
            domain,
        };
        Ok(data.hash_tree_root()?)
    }

    pub fn compute_domain(
        &self,
        domain_type: &[u8],
        fork_version: [u8; 4],
        genesis_root: Node,
    ) -> Result<[u8; 32]> {
        let fork_data_root = self.compute_fork_data_root(fork_version, genesis_root)?;
        let start = domain_type;
        let end = &fork_data_root.as_ref()[..28];
        let d = [start, end].concat();
        Ok(d.to_vec().try_into().unwrap())
    }

    fn compute_fork_data_root(
        &self,
        current_version: [u8; 4],
        genesis_validators_root: Node,
    ) -> Result<Node> {
        let mut fork_data = ForkData {
            current_version,
            genesis_validators_root,
        };
        Ok(fork_data.hash_tree_root()?)
    }

    fn log_finality_update(&self, update: &Update) {
        println!(
            "finalized slot             slot={}",
            update.finalized_header.beacon.slot,
        );
    }
}
