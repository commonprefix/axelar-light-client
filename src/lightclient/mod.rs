pub mod error;
pub mod helpers;
pub mod tests;
pub mod types;

use error::ConsensusError;
use eyre::Result;
use helpers::{hex_str_to_bytes, is_proof_valid};
use milagro_bls::{AggregateSignature, PublicKey};
use ssz_rs::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};
use types::*;

pub struct LightClient {
    pub state: LightClientState,
    pub config: ChainConfig,
}

impl LightClient {
    pub fn new(config: &ChainConfig, state: Option<LightClientState>) -> Self {
        let state = state.unwrap_or_default();
        return Self {
            state,
            config: config.clone(),
        };
    }

    pub fn bootstrap(&mut self, mut bootstrap: Bootstrap) -> Result<(), ConsensusError> {
        // TODO: Check that bootstrap is recent enough, after the Sync Committee fork
        let committee_valid = self.is_current_committee_proof_valid(
            &bootstrap.header.beacon,
            &mut bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
        );

        if !committee_valid {
            return Err(ConsensusError::InvalidCurrentSyncCommitteeProof.into());
        }

        self.state = LightClientState {
            finalized_header: bootstrap.header.beacon.clone(),
            current_sync_committee: bootstrap.current_sync_committee,
            next_sync_committee: None,
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
        };

        return Ok(());
    }

    pub fn verify_update(&self, update: &Update) -> Result<(), ConsensusError> {
        // Check if there's any participation in the sync committee at all.
        let bits = self.get_bits(&update.sync_aggregate.sync_committee_bits);
        if bits == 0 {
            return Err(ConsensusError::InsufficientParticipation.into());
        }

        // Check for valid timestamp conditions:
        // 1. The expected current slot given the genesis time should be equal or greater than the update's signature slot.
        // 2. The slot of the update's signature should be greater than the slot of the attested header.
        // 3. The attested header's slot should be equal or greater than the finalized header's slot.
        let update_finalized_slot = update.finalized_header.beacon.clone().slot;
        let valid_time = self.expected_current_slot(self.config.genesis_time)
            >= update.signature_slot.as_u64()
            && update.signature_slot > update.attested_header.beacon.slot
            && update.attested_header.beacon.slot >= update_finalized_slot;

        if !valid_time {
            return Err(ConsensusError::InvalidTimestamp.into());
        }

        // Validate the sync committee periods: If there's a next sync committee in
        // the state, the update's signature period should match the current period
        // or the next one.  Otherwise, it should only match the current period.
        let store_period = self.calc_sync_period(self.state.finalized_header.slot.into());
        let update_sig_period = self.calc_sync_period(update.signature_slot.as_u64());

        let valid_period = if self.state.next_sync_committee.is_some() {
            update_sig_period == store_period || update_sig_period == store_period + 1
        } else {
            update_sig_period == store_period
        };

        if !valid_period {
            return Err(ConsensusError::InvalidPeriod.into());
        }

        // Calculate the period for the attested header and check its relevance.
        // Ensure the attested header isn't already finalized unless the update introduces a new sync committee.
        let update_attested_period =
            self.calc_sync_period(update.attested_header.beacon.slot.into());
        let update_has_next_committee =
            self.state.next_sync_committee.is_none() && update_attested_period == store_period;

        if update.attested_header.beacon.slot <= update.finalized_header.beacon.slot
            && !update_has_next_committee
        {
            return Err(ConsensusError::NotRelevant.into());
        }

        let is_valid = self.is_finality_proof_valid(
            &update.attested_header.beacon,
            &mut update.finalized_header.beacon.clone(),
            &update.finality_branch.clone(),
        );

        if !is_valid {
            return Err(ConsensusError::InvalidFinalityProof.into());
        }

        // Check that next committe in attested header
        let is_valid = self.is_next_committee_proof_valid(
            &update.attested_header.beacon,
            &mut update.next_sync_committee.clone(),
            &update.next_sync_committee_branch.clone(),
        );

        if !is_valid {
            return Err(ConsensusError::InvalidNextSyncCommitteeProof.into());
        }

        // Verify the sync committee's aggregate signature for the attested header.

        let sync_committee = if update_sig_period == store_period {
            self.state.current_sync_committee.clone()
        } else {
            self.state.next_sync_committee.clone().unwrap()
        };

        let pks = self
            .get_participating_keys(&sync_committee, &update.sync_aggregate.sync_committee_bits);

        let is_valid_sig = self.verify_sync_committee_signture(
            &self.config,
            &pks,
            &update.attested_header.beacon,
            &update.sync_aggregate.sync_committee_signature,
            update.signature_slot.as_u64(),
        );

        if !is_valid_sig {
            return Err(ConsensusError::InvalidSignature.into());
        }

        Ok(())
    }

    pub fn apply_update(&mut self, update: &Update) -> Result<(), ConsensusError> {
        let committee_bits = self.get_bits(&update.sync_aggregate.sync_committee_bits);

        self.state.current_max_active_participants =
            u64::max(self.state.current_max_active_participants, committee_bits);

        let update_finalized_slot = update.finalized_header.beacon.slot.as_u64();
        let update_attested_period =
            self.calc_sync_period(update.attested_header.beacon.slot.into());
        let update_finalized_period = self.calc_sync_period(update_finalized_slot);

        let update_has_finalized_next_committee = update_finalized_period == update_attested_period;

        let should_apply_update = {
            let has_majority = committee_bits * 3 >= 512 * 2;
            let update_is_newer = update_finalized_slot > self.state.finalized_header.slot.as_u64();
            let good_update = update_is_newer || update_has_finalized_next_committee;
            has_majority && good_update
        };

        if should_apply_update {
            let store_period = self.calc_sync_period(self.state.finalized_header.slot.into());

            if self.state.next_sync_committee.is_none() {
                self.state.next_sync_committee = Some(update.next_sync_committee.clone());
            } else if update_finalized_period == store_period + 1 {
                self.state.current_sync_committee = self.state.next_sync_committee.clone().unwrap();
                self.state.next_sync_committee = Some(update.next_sync_committee.clone());
                self.state.previous_max_active_participants =
                    self.state.current_max_active_participants;
                self.state.current_max_active_participants = 0;
            }

            if update_finalized_slot > self.state.finalized_header.slot.as_u64() {
                self.state.finalized_header = update.finalized_header.beacon.clone();
                self.log_finality_update(update);
            }
        }

        Ok(())
    }

    fn is_current_committee_proof_valid(
        &self,
        attested_header: &Header,
        current_committee: &mut SyncCommittee,
        current_committee_branch: &[Bytes32],
    ) -> bool {
        is_proof_valid(
            attested_header,
            current_committee,
            current_committee_branch,
            5,
            22,
        )
    }

    pub fn calc_sync_period(&self, slot: u64) -> u64 {
        let epoch = slot / 32; // 32 slots per epoch
        epoch / 256 // 256 epochs per sync committee
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

    fn expected_current_slot(&self, genesis_time: u64) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let since_genesis = now - std::time::Duration::from_secs(genesis_time);

        since_genesis.as_secs() / 12
    }

    fn is_finality_proof_valid(
        &self,
        attested_header: &Header,
        finality_header: &mut Header,
        finality_branch: &[Bytes32],
    ) -> bool {
        is_proof_valid(attested_header, finality_header, finality_branch, 6, 41)
    }

    fn is_next_committee_proof_valid(
        &self,
        attested_header: &Header,
        next_committee: &mut SyncCommittee,
        next_committee_branch: &[Bytes32],
    ) -> bool {
        is_proof_valid(
            attested_header,
            next_committee,
            next_committee_branch,
            5,
            23,
        )
    }

    fn get_fork_version(&self, slot: u64) -> Vec<u8> {
        if slot < 74240 {
            // genesis
            return hex_str_to_bytes("0x00000000").unwrap();
        }
        if slot < 144896 {
            // altair
            return hex_str_to_bytes("0x01000000").unwrap();
        }
        if slot < 194048 {
            // bellatrix
            return hex_str_to_bytes("0x02000000").unwrap();
        }
        // capella
        return hex_str_to_bytes("0x03000000").unwrap();
    }

    fn get_participating_keys(
        &self,
        committee: &SyncCommittee,
        bitfield: &Bitvector<512>,
    ) -> Vec<PublicKey> {
        let mut pks: Vec<PublicKey> = Vec::new();
        bitfield.iter().enumerate().for_each(|(i, bit)| {
            if bit == true {
                let pk = &committee.pubkeys[i];
                let pk = PublicKey::from_bytes_unchecked(pk).unwrap();
                pks.push(pk);
            }
        });

        pks
    }

    fn verify_sync_committee_signture(
        &self,
        config: &ChainConfig,
        pks: &[PublicKey],
        attested_header: &Header,
        signature: &SignatureBytes,
        signature_slot: u64,
    ) -> bool {
        let res: Result<bool> = (move || {
            let pks: Vec<&PublicKey> = pks.iter().collect();
            let header_root =
                Bytes32::try_from(attested_header.clone().hash_tree_root()?.as_ref())?;
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
        sig_bytes: &SignatureBytes,
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
        header: Bytes32,
        slot: u64,
    ) -> Result<Node> {
        let genesis_root = config.genesis_root.to_vec().try_into().unwrap();

        let domain_type = &hex::decode("07000000")?[..];
        let fork_version = Vector::try_from(self.get_fork_version(slot)).map_err(|(_, err)| err)?;
        let domain = self.compute_domain(domain_type, fork_version, genesis_root)?;
        self.compute_signing_root(header, domain)
    }
    pub fn compute_signing_root(&self, object_root: Bytes32, domain: Bytes32) -> Result<Node> {
        let mut data = SigningData {
            object_root,
            domain,
        };
        Ok(data.hash_tree_root()?)
    }

    pub fn compute_domain(
        &self,
        domain_type: &[u8],
        fork_version: Vector<u8, 4>,
        genesis_root: Bytes32,
    ) -> Result<Bytes32> {
        let fork_data_root = self.compute_fork_data_root(fork_version, genesis_root)?;
        let start = domain_type;
        let end = &fork_data_root.as_ref()[..28];
        let d = [start, end].concat();
        Ok(d.to_vec().try_into().unwrap())
    }

    fn compute_fork_data_root(
        &self,
        current_version: Vector<u8, 4>,
        genesis_validator_root: Bytes32,
    ) -> Result<Node> {
        let mut fork_data = ForkData {
            current_version,
            genesis_validator_root,
        };
        Ok(fork_data.hash_tree_root()?)
    }

    fn log_finality_update(&self, update: &Update) {
        println!(
            "finalized slot             slot={}",
            update.finalized_header.beacon.slot.as_u64(),
        );
    }

    pub fn log_state(&self) {
        let period = &self.calc_sync_period(self.state.finalized_header.slot.into());
        let body_root = &self.state.finalized_header.body_root.as_ref();
        println!(
            "client: slot: {:?} period: {:?}, finalized_block_hash: {:?}",
            &self.state.finalized_header.slot.as_u64(),
            period,
            hex::encode(body_root)
        );
    }
}