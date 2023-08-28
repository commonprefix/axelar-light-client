use cw_storage_plus::Item;

use crate::types::Bootstrap;

pub const bootstrap: Item<Bootstrap> = Item::new("bootstrap");
