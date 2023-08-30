use cw_storage_plus::{Item, Map};

use crate::types::primitives::U64;
use crate::types::{SyncCommittee, Update};

pub const GENESIS_COMMITTEE: Item<SyncCommittee> = Item::new("genesis_committee");
pub const GENESIS_PERIOD: Item<u64> = Item::new("genesis_period");
pub const GENESIS_TIME: Item<U64> = Item::new("genesis_time");

pub const UPDATES: Map<u64, Update> = Map::new("updates");
