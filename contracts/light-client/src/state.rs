use cw_storage_plus::{Item, Map};
use types::axelar_wasm_std::hash::Hash;
use types::common::{Config, WorkerSetMessage};
use types::connection_router::state::Message;
use types::lightclient::LightClientState;

pub const CONFIG: Item<Config> = Item::new("config");
pub const LIGHT_CLIENT_STATE: Item<LightClientState> = Item::new("light_client_state");
pub const VERIFIED_MESSAGES: Map<Hash, Message> = Map::new("verified_messages");

pub const VERIFIED_WORKER_SETS: Map<String, WorkerSetMessage> = Map::new("worker_sets");
