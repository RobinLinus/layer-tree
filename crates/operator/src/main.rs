use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use layer_tree_operator::{
    api, block_driver, block_producer, chain, config, db, keys, peer_service,
    signing_coordinator, state_driver, AppState,
};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load config
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "operator.toml".to_string());

    let config = match config::Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {config_path}: {e}");
            std::process::exit(1);
        }
    };

    let params = config.protocol_params();
    info!(
        "Loaded config: chain={}, fanout={}",
        config.network.chain, params.fanout
    );

    // Initialize database
    let conn = match rusqlite::Connection::open(&config.database.path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to open database at {}: {e}", config.database.path);
            std::process::exit(1);
        }
    };
    if let Err(e) = db::init(&conn) {
        error!("Failed to initialize database schema: {e}");
        std::process::exit(1);
    }
    info!("Database initialized at {}", config.database.path);

    // Load or generate operator key
    let secret_key = match keys::load_or_generate_key(&config.operator.key_file) {
        Ok(sk) => sk,
        Err(e) => {
            error!("Failed to load operator key from {}: {e}", config.operator.key_file);
            std::process::exit(1);
        }
    };
    let our_pubkey = keys::public_key(&secret_key);
    let our_pubkey_hex = {
        let pk: musig2::secp256k1::PublicKey = our_pubkey.into();
        keys::hex_encode(&pk.serialize())
    };
    info!("Operator pubkey: {our_pubkey_hex}");

    // Build key aggregation context
    let (signer_index, n_signers, key_agg_ctx, operator_xonly) =
        if config.peers.pubkeys.is_empty() {
            // Single-operator mode: use our own key
            warn!("No peer pubkeys configured — running in single-operator mode");
            let ctx = match keys::build_key_agg_ctx(&[our_pubkey]) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to build key aggregation context: {e}");
                    std::process::exit(1);
                }
            };
            let agg: musig2::secp::Point = ctx.aggregated_pubkey();
            (0, 1, ctx, keys::point_to_xonly(agg))
        } else {
            // Multi-operator mode: parse all pubkeys
            let mut pubkeys = Vec::new();
            for hex in &config.peers.pubkeys {
                match keys::parse_pubkey_hex(hex) {
                    Ok(pk) => pubkeys.push(pk),
                    Err(e) => {
                        error!("Invalid peer pubkey {hex}: {e}");
                        std::process::exit(1);
                    }
                }
            }
            let idx = keys::find_signer_index(&pubkeys, &our_pubkey).unwrap_or_else(|| {
                error!("Our pubkey not found in peers.pubkeys list");
                std::process::exit(1);
            });
            let n = pubkeys.len();
            let ctx = match keys::build_key_agg_ctx(&pubkeys) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to build key aggregation context: {e}");
                    std::process::exit(1);
                }
            };
            let agg: musig2::secp::Point = ctx.aggregated_pubkey();
            info!("Multi-operator mode: signer {idx}/{n}");
            (idx, n, ctx, keys::point_to_xonly(agg))
        };

    info!(
        "Aggregate x-only pubkey: {}",
        keys::hex_encode(&operator_xonly.serialize())
    );

    let coordinator = Arc::new(Mutex::new(signing_coordinator::SigningCoordinator::new(
        signer_index,
        n_signers,
        secret_key,
        key_agg_ctx,
        operator_xonly,
        params.clone(),
    )));

    let user_addr = config.listen.user_addr.clone();
    let peer_addr = config.listen.peer_addr.clone();

    // Rebuild chain state from DB (checkpoint + post-checkpoint blocks)
    let mut chain_state = match db::rebuild_chain_state(&conn) {
        Ok(cs) => {
            info!("Chain state restored: height={}, {} balances", cs.height, cs.balances.len());
            cs
        }
        Err(e) => {
            error!("Failed to rebuild chain state: {e}");
            std::process::exit(1);
        }
    };

    // Sync with peers to catch up on any missed blocks
    if !config.peers.urls.is_empty() {
        info!("Syncing with peers...");
        for peer_url in &config.peers.urls {
            let client = peer_service::PeerClient::new(peer_url.clone());
            match client.sync(chain_state.height, chain_state.tip_hash).await {
                Ok(resp) => {
                    // Apply checkpoint if we're behind
                    if let Some(cp) = resp.checkpoint {
                        info!("Received checkpoint at height {} from {peer_url}", cp.block_height);
                        chain_state = layer_tree_core::blockchain::ChainState::from_checkpoint(&cp);
                        // Save checkpoint locally
                        if let Err(e) = db::save_checkpoint(&conn, &cp) {
                            error!("Failed to save synced checkpoint: {e}");
                        }
                    }
                    // Apply missing blocks
                    for block in &resp.blocks {
                        match chain_state.apply_block(block) {
                            Ok(new_state) => {
                                if let Err(e) = db::insert_block(&conn, block) {
                                    error!("Failed to store synced block {}: {e}", block.header.height);
                                }
                                chain_state = new_state;
                            }
                            Err(e) => {
                                warn!("Failed to apply synced block {}: {e}", block.header.height);
                                break;
                            }
                        }
                    }
                    info!("Synced to height {} from {peer_url}", chain_state.height);
                    break; // Successfully synced from one peer
                }
                Err(e) => {
                    warn!("Failed to sync from {peer_url}: {e}");
                }
            }
        }
    }

    let shared_chain_state = Arc::new(Mutex::new(chain_state));
    let shared_block_producer = Arc::new(Mutex::new(
        block_producer::BlockProducer::new(),
    ));

    let state = Arc::new(AppState {
        config,
        params,
        db: Mutex::new(conn),
        coordinator: coordinator.clone(),
        chain_state: shared_chain_state.clone(),
        block_producer: shared_block_producer,
    });

    // Start chain monitor (if bitcoind configured)
    if let Some(ref bitcoind_config) = state.config.bitcoind {
        match chain::ChainMonitor::new(bitcoind_config, operator_xonly) {
            Ok(monitor) => {
                let shared_monitor = Arc::new(Mutex::new(monitor));
                let db_for_monitor = Arc::new(Mutex::new(
                    match rusqlite::Connection::open(&state.config.database.path) {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Failed to open DB for chain monitor: {e}");
                            std::process::exit(1);
                        }
                    },
                ));
                tokio::spawn(chain::run_monitor(
                    shared_monitor,
                    db_for_monitor,
                    state.block_producer.clone(),
                    std::time::Duration::from_secs(10),
                ));
                info!("Chain monitor started");
            }
            Err(e) => {
                warn!("Chain monitor disabled: {e}");
            }
        }
    } else {
        info!("No bitcoind config — chain monitor disabled");
    }

    // Start peer HTTP service
    let peer_addr_parsed: std::net::SocketAddr = match peer_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid peer address '{peer_addr}': {e}");
            std::process::exit(1);
        }
    };
    let peer_db = Arc::new(Mutex::new(
        match rusqlite::Connection::open(&state.config.database.path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to open DB for peer service: {e}");
                std::process::exit(1);
            }
        },
    ));
    let peer_state = peer_service::PeerState {
        coordinator: coordinator.clone(),
        chain_state: shared_chain_state.clone(),
        db: peer_db,
    };
    tokio::spawn(async move {
        info!("Starting peer API on {peer_addr}");
        if let Err(e) = peer_service::serve(peer_state, peer_addr_parsed).await {
            error!("Peer service failed: {e}");
        }
    });

    // Start state driver (leader coordinates signing)
    let driver_coordinator = coordinator.clone();
    let driver_db = Arc::new(Mutex::new(
        match rusqlite::Connection::open(&state.config.database.path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to open DB for state driver: {e}");
                std::process::exit(1);
            }
        },
    ));
    let driver_config = state_driver::StateDriverConfig {
        poll_interval: std::time::Duration::from_secs(5),
        min_pending_changes: 1,
        peer_urls: state.config.peers.urls.clone(),
    };
    tokio::spawn(state_driver::run_state_driver(
        driver_coordinator,
        driver_db,
        shared_chain_state.clone(),
        driver_config,
    ));

    // Start block driver (leader produces blocks from mempool)
    let is_leader = signer_index == 0;
    let block_driver_db = Arc::new(Mutex::new(
        match rusqlite::Connection::open(&state.config.database.path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to open DB for block driver: {e}");
                std::process::exit(1);
            }
        },
    ));
    let block_driver_config = block_driver::BlockDriverConfig {
        poll_interval: std::time::Duration::from_secs(1),
        peer_urls: state.config.peers.urls.clone(),
    };
    tokio::spawn(block_driver::run_block_driver(
        state.block_producer.clone(),
        shared_chain_state,
        block_driver_db,
        is_leader,
        block_driver_config,
    ));

    // Build and start REST API
    let app = api::router(state.clone());

    info!("Starting user API on {user_addr}");
    let listener = match tokio::net::TcpListener::bind(&user_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind user API address '{user_addr}': {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("User API server error: {e}");
        std::process::exit(1);
    }
}
