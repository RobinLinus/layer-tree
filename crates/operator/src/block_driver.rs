//! Block driver: periodically produces blocks from the mempool and proposes
//! them to peer operators.
//!
//! Only the leader (signer_index=0) runs the block driver. Followers receive
//! blocks via the peer service's `POST /peer/propose_block` endpoint.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::block_producer::SharedBlockProducer;
use crate::peer_service::{PeerClient, SharedChainState};

/// Configuration for the block driver.
pub struct BlockDriverConfig {
    /// How often to check the mempool for pending operations.
    pub poll_interval: Duration,
    /// Peer URLs for block propagation.
    pub peer_urls: Vec<String>,
}

/// Run the block driver loop.
///
/// Only the leader produces blocks. The loop:
/// 1. Checks if the mempool has pending operations
/// 2. Produces a block against the current chain state
/// 3. Proposes the block to all peers
/// 4. On n-of-n ack, commits the block (stores in DB, updates chain state)
pub async fn run_block_driver(
    block_producer: SharedBlockProducer,
    chain_state: SharedChainState,
    db: Arc<Mutex<rusqlite::Connection>>,
    is_leader: bool,
    config: BlockDriverConfig,
) {
    if !is_leader {
        debug!("Block driver: not leader, blocks received via peer API");
        return;
    }

    info!(
        "Block driver: leader mode, polling every {}ms",
        config.poll_interval.as_millis()
    );

    let peer_clients: Vec<PeerClient> = config
        .peer_urls
        .iter()
        .map(|url| PeerClient::new(url.clone()))
        .collect();

    loop {
        tokio::time::sleep(config.poll_interval).await;

        // Check if mempool has operations
        let pending = {
            let bp = block_producer.lock().await;
            bp.pending_count()
        };

        if pending == 0 {
            continue;
        }

        debug!("Block driver: {pending} pending operations, producing block");

        // Produce a block against current chain state
        let (block, new_state) = {
            let cs = chain_state.lock().await;
            let mut bp = block_producer.lock().await;
            match bp.produce_block(&cs) {
                Ok(Some((block, new_state))) => (block, new_state),
                Ok(None) => {
                    debug!("Block driver: no valid operations after filtering");
                    continue;
                }
                Err(e) => {
                    error!("Block driver: produce_block failed: {e}");
                    continue;
                }
            }
        };

        info!(
            "Block driver: produced block {} with {} operations",
            block.header.height,
            block.operations.len()
        );

        // Propose block to all peers
        let mut all_accepted = true;
        for (i, client) in peer_clients.iter().enumerate() {
            match client.propose_block(&block).await {
                Ok(resp) => {
                    if !resp.accepted {
                        warn!(
                            "Peer {} rejected block {}: {}",
                            i + 1,
                            block.header.height,
                            resp.reject_reason
                        );
                        all_accepted = false;
                    }
                }
                Err(e) => {
                    error!("Failed to reach peer {} for block proposal: {e}", i + 1);
                    all_accepted = false;
                }
            }
        }

        if !all_accepted && !peer_clients.is_empty() {
            warn!(
                "Block {} not accepted by all peers, re-queuing {} operations",
                block.header.height,
                block.operations.len()
            );
            // Re-queue the operations so they can be retried in the next block
            let mut bp = block_producer.lock().await;
            bp.requeue(block.operations.clone());
            continue;
        }

        // Commit: store block in DB and update chain state
        {
            let db_conn = db.lock().await;
            if let Err(e) = crate::db::insert_block(&db_conn, &block) {
                error!("Block driver: failed to store block: {e}");
                continue;
            }
            // Track any withdrawal operations for later L1 payout
            if let Err(e) = crate::db::record_withdrawals_from_block(&db_conn, &block) {
                error!("Block driver: failed to record withdrawals: {e}");
            }
        }

        {
            let mut cs = chain_state.lock().await;
            *cs = new_state;
        }

        info!("Block {} committed", block.header.height);
    }
}
