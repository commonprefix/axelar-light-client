use cw2::ContractVersion;
use cw_storage_plus::{Item, Map};

use crate::lightclient::types::{ChainConfig, LightClientState, SyncCommittee};

pub const CONFIG: Item<ChainConfig> = Item::new("config");
pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const SYNC_COMMITTEES: Map<u64, SyncCommittee> = Map::new("sync_committees");
pub const VERSION: Item<ContractVersion> = Item::new("contract_info");
