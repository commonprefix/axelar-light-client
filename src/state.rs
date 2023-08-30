use cw_storage_plus::{Item, Map};

use crate::types::{Bootstrap, ChainConfig, LightClientState, Update};

pub const BOOTSTRAP: Item<Bootstrap> = Item::new("bootstrap");
pub const UPDATES: Map<u64, Update> = Map::new("updates");

pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const CONFIG: Item<ChainConfig> = Item::new("config");
