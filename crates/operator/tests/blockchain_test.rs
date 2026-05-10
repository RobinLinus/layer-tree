//! Integration tests for the operator blockchain.
//!
//! Tests block propagation between operators, rejection of invalid blocks,
//! sync/catch-up, and the full deposit→block→sign→checkpoint pipeline.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid, XOnlyPublicKey};
use tokio::sync::Mutex;

use layer_tree_core::blockchain::{build_block, ChainState, Operation, Sig};
use layer_tree_operator::{block_driver, block_producer, db, keys, peer_service, signing_coordinator};

fn test_xonly(byte: u8) -> XOnlyPublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = byte;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let (xonly, _) = pk.x_only_public_key();
    xonly
}

/// Start a peer service with in-memory DB and genesis chain state.
/// Returns (base_url, chain_state_handle, db_handle).
async fn start_peer_node() -> (String, peer_service::SharedChainState, Arc<Mutex<rusqlite::Connection>>)
{
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let db_arc = Arc::new(Mutex::new(conn));
    let chain_state = Arc::new(Mutex::new(ChainState::genesis()));

    // Minimal coordinator (single-operator, just for PeerState)
    let tmp_dir = tempfile::tempdir().unwrap();
    let key_path = tmp_dir.path().join("key.bin");
    let secret_key = keys::load_or_generate_key(key_path.to_str().unwrap()).unwrap();
    let our_pubkey = keys::public_key(&secret_key);
    let key_agg_ctx = keys::build_key_agg_ctx(&[our_pubkey]).unwrap();
    let agg: musig2::secp::Point = key_agg_ctx.aggregated_pubkey();
    let operator_xonly = keys::point_to_xonly(agg);
    let params = layer_tree_core::REGTEST_PARAMS;
    let coordinator = Arc::new(Mutex::new(signing_coordinator::SigningCoordinator::new(
        0,
        1,
        secret_key,
        key_agg_ctx,
        operator_xonly,
        params,
    )));

    let peer_state = peer_service::PeerState {
        coordinator,
        chain_state: chain_state.clone(),
        db: db_arc.clone(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    tokio::spawn(async move {
        let app = peer_service::router(peer_state);
        axum::serve(listener, app).await.unwrap();
    });

    // Keep tmp_dir alive by leaking it (test only)
    std::mem::forget(tmp_dir);

    tokio::time::sleep(Duration::from_millis(50)).await;
    (base_url, chain_state, db_arc)
}

#[tokio::test]
async fn test_block_proposal_accepted() {
    let (url, chain_state, _db) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);

    // Build a valid block with a deposit
    let state = ChainState::genesis();
    let ops = vec![Operation::DepositConfirm {
        pubkey: alice,
        amount: 100_000,
        outpoint: OutPoint::new(Txid::from_byte_array([0xAA; 32]), 0),
    }];
    let (block, _new_state) = build_block(&state, ops).unwrap();

    // Propose the block to the peer
    let resp = client.propose_block(&block).await.unwrap();
    assert!(resp.accepted, "Block should be accepted: {}", resp.reject_reason);

    // Verify the peer's chain state was updated
    let cs = chain_state.lock().await;
    assert_eq!(cs.height, 1);
    assert_eq!(cs.balances[&alice], 100_000);
}

#[tokio::test]
async fn test_block_proposal_rejected_bad_prev_hash() {
    let (url, _chain_state, _db) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);

    // Build a block that claims prev_hash = [0xFF; 32] (wrong, genesis tip is [0; 32])
    let mut state = ChainState::genesis();
    state.tip_hash = [0xFF; 32]; // fake
    let ops = vec![Operation::DepositConfirm {
        pubkey: alice,
        amount: 50_000,
        outpoint: OutPoint::new(Txid::from_byte_array([0xBB; 32]), 0),
    }];
    let (block, _) = build_block(&state, ops).unwrap();

    let resp = client.propose_block(&block).await.unwrap();
    assert!(!resp.accepted);
    assert!(resp.reject_reason.contains("prev_hash"));
}

#[tokio::test]
async fn test_block_proposal_rejected_wrong_height() {
    let (url, _chain_state, _db) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);

    // Build a valid block at height 1
    let state = ChainState::genesis();
    let (block1, _state1) = build_block(
        &state,
        vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 50_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0),
        }],
    )
    .unwrap();
    let resp = client.propose_block(&block1).await.unwrap();
    assert!(resp.accepted);

    // Try to propose block at height 1 again (should fail — height must be sequential)
    let (duplicate_block, _) = build_block(
        &state, // building from genesis again = height 1 with wrong prev_hash
        vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 25_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xDD; 32]), 0),
        }],
    )
    .unwrap();

    let resp = client.propose_block(&duplicate_block).await.unwrap();
    assert!(!resp.accepted);
    assert!(
        resp.reject_reason.contains("prev_hash") || resp.reject_reason.contains("height"),
        "Expected prev_hash or height error, got: {}",
        resp.reject_reason
    );
}

#[tokio::test]
async fn test_multiple_blocks_sequential() {
    let (url, chain_state, _db) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);
    let bob = test_xonly(2);

    // Block 1: deposit to Alice
    let state = ChainState::genesis();
    let (block1, state1) = build_block(
        &state,
        vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 200_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0x01; 32]), 0),
        }],
    )
    .unwrap();

    let resp = client.propose_block(&block1).await.unwrap();
    assert!(resp.accepted);

    // Block 2: deposit to Bob
    let (block2, state2) = build_block(
        &state1,
        vec![Operation::DepositConfirm {
            pubkey: bob,
            amount: 150_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0x02; 32]), 0),
        }],
    )
    .unwrap();

    let resp = client.propose_block(&block2).await.unwrap();
    assert!(resp.accepted);

    // Verify final state
    let cs = chain_state.lock().await;
    assert_eq!(cs.height, 2);
    assert_eq!(cs.balances[&alice], 200_000);
    assert_eq!(cs.balances[&bob], 150_000);
    assert_eq!(cs.state_hash(), state2.state_hash());
}

#[tokio::test]
async fn test_sync_from_behind() {
    let (url, _chain_state, _db) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);

    // Build and propose 3 blocks
    let mut current_state = ChainState::genesis();
    for i in 0..3u8 {
        let (block, new_state) = build_block(
            &current_state,
            vec![Operation::DepositConfirm {
                pubkey: alice,
                amount: 10_000,
                outpoint: OutPoint::new(Txid::from_byte_array([10 + i; 32]), 0),
            }],
        )
        .unwrap();

        let resp = client.propose_block(&block).await.unwrap();
        assert!(resp.accepted);
        current_state = new_state;
    }

    // Sync from height 0 — should get all 3 blocks
    let sync_resp = client.sync(0, [0u8; 32]).await.unwrap();
    assert!(sync_resp.checkpoint.is_none());
    assert_eq!(sync_resp.blocks.len(), 3);
    assert_eq!(sync_resp.blocks[0].header.height, 1);
    assert_eq!(sync_resp.blocks[2].header.height, 3);

    // Sync from height 2 — should get 1 block
    let sync_resp = client.sync(2, [0u8; 32]).await.unwrap();
    assert!(sync_resp.checkpoint.is_none());
    assert_eq!(sync_resp.blocks.len(), 1);
    assert_eq!(sync_resp.blocks[0].header.height, 3);

    // Sync from height 3 — should get 0 blocks
    let sync_resp = client.sync(3, [0u8; 32]).await.unwrap();
    assert!(sync_resp.checkpoint.is_none());
    assert_eq!(sync_resp.blocks.len(), 0);
}

#[tokio::test]
async fn test_sync_with_checkpoint() {
    let (url, _chain_state, db_arc) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);

    // Build and propose 3 blocks
    let mut current_state = ChainState::genesis();
    for i in 0..3u8 {
        let (block, new_state) = build_block(
            &current_state,
            vec![Operation::DepositConfirm {
                pubkey: alice,
                amount: 10_000,
                outpoint: OutPoint::new(Txid::from_byte_array([20 + i; 32]), 0),
            }],
        )
        .unwrap();

        let resp = client.propose_block(&block).await.unwrap();
        assert!(resp.accepted);
        current_state = new_state;
    }

    // Save a checkpoint at block 2 (simulating a signing round completing)
    // We'll create a checkpoint at height 2 manually
    let mut cp_state = ChainState::genesis();
    {
        let db = db_arc.lock().await;
        let blocks = db::get_blocks_since(&db, 0).unwrap();
        // Apply first 2 blocks to get state at height 2
        for block in blocks.iter().take(2) {
            cp_state = cp_state.apply_block(block).unwrap();
        }
        let checkpoint = cp_state.checkpoint();
        db::save_checkpoint(&db, &checkpoint).unwrap();
    }

    // Sync from height 0 — peer is behind checkpoint, should get checkpoint + block 3
    let sync_resp = client.sync(0, [0u8; 32]).await.unwrap();
    assert!(sync_resp.checkpoint.is_some());
    let cp = sync_resp.checkpoint.unwrap();
    assert_eq!(cp.block_height, 2);
    assert_eq!(cp.balances[&alice], 20_000); // 2 * 10_000
    assert_eq!(sync_resp.blocks.len(), 1);
    assert_eq!(sync_resp.blocks[0].header.height, 3);

    // Sync from height 2 — at checkpoint level, just get remaining block
    let sync_resp = client.sync(2, [0u8; 32]).await.unwrap();
    assert!(sync_resp.checkpoint.is_none());
    assert_eq!(sync_resp.blocks.len(), 1);
}

#[tokio::test]
async fn test_block_producer_and_proposal() {
    let (url, chain_state, _db) = start_peer_node().await;
    let client = peer_service::PeerClient::new(url);

    let alice = test_xonly(1);
    let bob = test_xonly(2);

    // First, fund Alice on both sides
    let state = ChainState::genesis();
    let (deposit_block, state_after_deposit) = build_block(
        &state,
        vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 500_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0x30; 32]), 0),
        }],
    )
    .unwrap();

    // Propose deposit to peer
    let resp = client.propose_block(&deposit_block).await.unwrap();
    assert!(resp.accepted);

    // Now use BlockProducer locally to produce a transfer block
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1; // Alice's secret key
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();

    // Sign a transfer: Alice → Bob, 100_000 sats
    let transfer_msg = layer_tree_core::blockchain::transfer_message(&bob, 100_000, 1);
    let sig = secp.sign_schnorr(&transfer_msg, &keypair);

    let mut bp = block_producer::BlockProducer::new();
    bp.add_operation(Operation::Transfer {
        from: alice,
        to: bob,
        amount: 100_000,
        nonce: 1,
        signature: Sig(sig.serialize()),
    });

    // Produce block
    let result = bp.produce_block(&state_after_deposit).unwrap();
    assert!(result.is_some());
    let (transfer_block, final_state) = result.unwrap();

    assert_eq!(final_state.balances[&alice], 400_000);
    assert_eq!(final_state.balances[&bob], 100_000);

    // Propose the transfer block to the peer
    let resp = client.propose_block(&transfer_block).await.unwrap();
    assert!(resp.accepted);

    // Verify peer's state matches
    let cs = chain_state.lock().await;
    assert_eq!(cs.height, 2);
    assert_eq!(cs.balances[&alice], 400_000);
    assert_eq!(cs.balances[&bob], 100_000);
    assert_eq!(cs.state_hash(), final_state.state_hash());
}

#[tokio::test]
async fn test_deterministic_state_across_nodes() {
    // Two independent nodes process the same blocks and arrive at identical state
    let (url_a, cs_a, _db_a) = start_peer_node().await;
    let (url_b, cs_b, _db_b) = start_peer_node().await;
    let client_a = peer_service::PeerClient::new(url_a);
    let client_b = peer_service::PeerClient::new(url_b);

    let alice = test_xonly(1);
    let bob = test_xonly(2);

    // Build blocks locally
    let state0 = ChainState::genesis();
    let (block1, state1) = build_block(
        &state0,
        vec![
            Operation::DepositConfirm {
                pubkey: alice,
                amount: 300_000,
                outpoint: OutPoint::new(Txid::from_byte_array([0x40; 32]), 0),
            },
            Operation::DepositConfirm {
                pubkey: bob,
                amount: 200_000,
                outpoint: OutPoint::new(Txid::from_byte_array([0x41; 32]), 0),
            },
        ],
    )
    .unwrap();

    // Propose same block to both nodes
    let resp_a = client_a.propose_block(&block1).await.unwrap();
    let resp_b = client_b.propose_block(&block1).await.unwrap();
    assert!(resp_a.accepted);
    assert!(resp_b.accepted);

    // Build a transfer block
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let msg = layer_tree_core::blockchain::transfer_message(&bob, 50_000, 1);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let (block2, state2) = build_block(
        &state1,
        vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 50_000,
            nonce: 1,
            signature: Sig(sig.serialize()),
        }],
    )
    .unwrap();

    let resp_a = client_a.propose_block(&block2).await.unwrap();
    let resp_b = client_b.propose_block(&block2).await.unwrap();
    assert!(resp_a.accepted);
    assert!(resp_b.accepted);

    // Both nodes should have identical state
    let state_a = cs_a.lock().await;
    let state_b = cs_b.lock().await;
    assert_eq!(state_a.state_hash(), state_b.state_hash());
    assert_eq!(state_a.height, state_b.height);
    assert_eq!(state_a.balances, state_b.balances);
    assert_eq!(state_a.state_hash(), state2.state_hash());
}

#[tokio::test]
async fn test_block_driver_produces_and_propagates() {
    // Start a follower peer node
    let (follower_url, follower_cs, _follower_db) = start_peer_node().await;

    // Set up leader's mempool, chain state, and DB
    let leader_db = {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();
        Arc::new(Mutex::new(conn))
    };
    let leader_cs: peer_service::SharedChainState = Arc::new(Mutex::new(ChainState::genesis()));
    let leader_bp = Arc::new(Mutex::new(block_producer::BlockProducer::new()));

    let alice = test_xonly(1);

    // Add a deposit operation to the leader's mempool
    {
        let mut bp = leader_bp.lock().await;
        bp.add_operation(Operation::DepositConfirm {
            pubkey: alice,
            amount: 77_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0x50; 32]), 0),
        });
    }

    // Start block driver pointing at the follower
    let driver_config = block_driver::BlockDriverConfig {
        poll_interval: Duration::from_millis(50),
        peer_urls: vec![follower_url],
    };

    let driver_bp = leader_bp.clone();
    let driver_cs = leader_cs.clone();
    let driver_db = leader_db.clone();
    let handle = tokio::spawn(block_driver::run_block_driver(
        driver_bp,
        driver_cs,
        driver_db,
        true, // is_leader
        driver_config,
    ));

    // Wait for the block driver to produce and propagate the block
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    // Verify leader's chain state was updated
    let leader_state = leader_cs.lock().await;
    assert_eq!(leader_state.height, 1);
    assert_eq!(leader_state.balances[&alice], 77_000);

    // Verify follower received and applied the same block
    let follower_state = follower_cs.lock().await;
    assert_eq!(follower_state.height, 1);
    assert_eq!(follower_state.balances[&alice], 77_000);

    // States must be identical
    assert_eq!(leader_state.state_hash(), follower_state.state_hash());
}
