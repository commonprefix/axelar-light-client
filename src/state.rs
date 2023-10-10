use cw_storage_plus::{Item, Map};

use crate::lightclient::types::{Bootstrap, ChainConfig, Forks, LightClientState, Update};
use crate::lightclient::types::{ChainConfig, Forks, LightClientState, SyncCommittee};

pub const UPDATES: Map<u64, Update> = Map::new("updates");

pub const BOOTSTRAP: Item<Bootstrap> = Item::new("bootstrap");
pub const CONFIG: Item<ChainConfig> = Item::new("config");
pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const FORKS: Item<Forks> = Item::new("forks");
pub const SYNC_COMMITTEES: Map<u64, SyncCommittee> = Map::new("sync_committees");
