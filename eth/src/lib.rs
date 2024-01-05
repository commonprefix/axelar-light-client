//! A library for interacting with the Ethereum blockchain.
//! Provides both Consensus and Execution clients.
//!
//! Supports the basic Ethereum JSON-RPC methods, as well as some additional
//! methods for interacting with the Beacon API like `get_block_roots_tree` for
//! a given range

pub mod consensus;
pub mod error;
pub mod execution;
pub mod types;
pub mod utils;
