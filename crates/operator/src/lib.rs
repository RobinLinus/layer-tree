//! Layer Tree operator library.

pub mod api;
pub mod auth;
pub mod block_driver;
pub mod block_producer;
pub mod chain;
pub mod config;
pub mod db;
pub mod keys;
pub mod peer_service;
pub mod signing_coordinator;
pub mod state_driver;

use tokio::sync::Mutex;

/// Shared operator state accessible from all handlers.
pub struct AppState {
    pub config: config::Config,
    pub params: layer_tree_core::Params,
    pub db: Mutex<rusqlite::Connection>,
    pub coordinator: signing_coordinator::SharedCoordinator,
    pub chain_state: peer_service::SharedChainState,
    pub block_producer: block_producer::SharedBlockProducer,
}
