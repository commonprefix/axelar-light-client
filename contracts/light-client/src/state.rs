use cw2::ContractVersion;
use cw_storage_plus::{Item, Map};
use sync_committee_rs::{consensus_types::SyncCommittee, constants::SYNC_COMMITTEE_SIZE};
use types::lightclient::{Message, MessageHash};
use types::{common::ChainConfig, lightclient::LightClientState};

pub const CONFIG: Item<ChainConfig> = Item::new("config");
pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const SYNC_COMMITTEES: Map<u64, SyncCommittee<SYNC_COMMITTEE_SIZE>> =
    Map::new("sync_committees");
pub const VERSION: Item<ContractVersion> = Item::new("contract_info");

pub const VERIFIED_MESSAGES: Map<MessageHash, Message> = Map::new("sync_committees");
