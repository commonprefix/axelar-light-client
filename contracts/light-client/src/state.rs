use cw2::ContractVersion;
use cw_storage_plus::{Item, Map};
use types::axelar_wasm_std::hash::Hash;
use types::common::Config;
use types::connection_router::state::Message;
use types::lightclient::LightClientState;
use types::proofs::Operators;
use types::sync_committee_rs::{consensus_types::SyncCommittee, constants::SYNC_COMMITTEE_SIZE};

pub const CONFIG: Item<Config> = Item::new("config");
pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const SYNC_COMMITTEE: Item<(SyncCommittee<SYNC_COMMITTEE_SIZE>, u64)> =
    Item::new("sync_committee");
pub const VERSION: Item<ContractVersion> = Item::new("contract_info");

pub const VERIFIED_MESSAGES: Map<Hash, Message> = Map::new("verified_messages");

pub const VERIFIED_WORKER_SETS: Map<Hash, Operators> = Map::new("worker_sets");
