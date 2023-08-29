use cw_storage_plus::Item;

use crate::types::Bootstrap;

pub const BOOTSTRAP: Item<Bootstrap> = Item::new("bootstrap");
