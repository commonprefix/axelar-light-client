use cw2::ContractVersion;
use cw_storage_plus::{Item, Map};
use types::lightclient::{Hash, Message};
use types::sync_committee_rs::{consensus_types::SyncCommittee, constants::SYNC_COMMITTEE_SIZE};
use types::{common::ChainConfig, lightclient::LightClientState};

pub const CONFIG: Item<ChainConfig> = Item::new("config");
pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const SYNC_COMMITTEE: Item<(SyncCommittee<SYNC_COMMITTEE_SIZE>, u64)> =
    Item::new("sync_committee");
pub const VERSION: Item<ContractVersion> = Item::new("contract_info");

pub const VERIFIED_MESSAGES: Map<Hash, Message> = Map::new("verified_messages");
