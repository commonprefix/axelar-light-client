use ssz_rs::Bitvector;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::ConsensusError,
    helpers::is_proof_valid,
    types::{Bootstrap, Bytes32, Header, LightClientState, SyncCommittee},
};

pub fn bootstrap(mut bootstrap: Bootstrap) -> Result<LightClientState, ConsensusError> {
    // TODO: Check that bootstrap is recent enough, after the Sync Committee fork
    let committee_valid = is_current_committee_proof_valid(
        &bootstrap.header.beacon,
        &mut bootstrap.current_sync_committee,
        &bootstrap.current_sync_committee_branch,
    );

    if !committee_valid {
        return Err(ConsensusError::InvalidCurrentSyncCommitteeProof.into());
    }

    let state = LightClientState {
        finalized_header: bootstrap.header.beacon.clone(),
        current_sync_committee: bootstrap.current_sync_committee,
        next_sync_committee: None,
        optimistic_header: bootstrap.header.beacon.clone(),
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
    };

    return Ok(state);
}

fn is_current_committee_proof_valid(
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

pub fn calc_sync_period(slot: u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}

pub fn get_bits(bitfield: &Bitvector<512>) -> u64 {
    let mut count = 0;
    bitfield.iter().for_each(|bit| {
        if bit == true {
            count += 1;
        }
    });

    count
}

fn expected_current_slot(genesis_time: u64) -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let since_genesis = now - std::time::Duration::from_secs(genesis_time);

    since_genesis.as_secs() / 12
}
