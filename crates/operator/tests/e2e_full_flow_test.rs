//! Real regtest end-to-end API tests.
//!
//! Starts a temporary bitcoind in regtest mode and a full single-operator
//! system connected to it. Tests all user flows with real on-chain Bitcoin
//! transactions: credit (faucet), transfers, withdrawals, and state signing.
//!
//! Skips automatically if `bitcoind` is not found in PATH.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::XOnlyPublicKey;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::Mutex;

use layer_tree_core::blockchain;
use layer_tree_operator::{
    api, block_driver, block_producer, config, db, keys, peer_service, signing_coordinator,
    state_driver, AppState,
};

// ─── Bitcoind Process Management ──────────────────────────────────────────

struct BitcoindInstance {
    process: std::process::Child,
    _datadir: tempfile::TempDir,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
}

impl Drop for BitcoindInstance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start a temporary bitcoind in regtest mode with a loaded wallet.
/// Returns None if bitcoind is not installed.
async fn start_bitcoind() -> Option<BitcoindInstance> {
    if std::process::Command::new("bitcoind")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return None;
    }

    let datadir = tempfile::tempdir().unwrap();
    let rpc_port = find_free_port();
    let rpc_user = "testuser".to_string();
    let rpc_pass = "testpass".to_string();

    let mut process = std::process::Command::new("bitcoind")
        .args([
            "-regtest",
            &format!("-datadir={}", datadir.path().display()),
            &format!("-rpcport={rpc_port}"),
            &format!("-rpcuser={rpc_user}"),
            &format!("-rpcpassword={rpc_pass}"),
            "-server",
            "-listen=0",
            "-fallbackfee=0.00001",
            "-txindex=1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let base_url = format!("http://127.0.0.1:{rpc_port}");

    // Poll until bitcoind is ready
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(rpc) = bitcoincore_rpc::Client::new(
            &base_url,
            bitcoincore_rpc::Auth::UserPass(rpc_user.clone(), rpc_pass.clone()),
        ) {
            use bitcoincore_rpc::RpcApi;
            if rpc.get_blockchain_info().is_ok() {
                let _ = rpc.create_wallet("test_wallet", None, None, None, None);
                return Some(BitcoindInstance {
                    process,
                    _datadir: datadir,
                    rpc_url: format!("{base_url}/wallet/test_wallet"),
                    rpc_user,
                    rpc_pass,
                });
            }
        }
    }

    let _ = process.kill();
    let _ = process.wait();
    None
}

// ─── Test Environment ─────────────────────────────────────────────────────

struct TestEnv {
    base_url: String,
    block_producer: block_producer::SharedBlockProducer,
    _bitcoind: BitcoindInstance,
    _tmp_dir: tempfile::TempDir,
}

/// Start a full operator backed by a real bitcoind.
async fn start_regtest_env() -> Option<TestEnv> {
    let btc = start_bitcoind().await?;

    let tmp_dir = tempfile::tempdir().unwrap();
    let key_path = tmp_dir.path().join("key.bin");
    let db_path = tmp_dir.path().join("test.db");

    let config_content = format!(
        r#"
[operator]
key_file = "{key_path}"

[network]
chain = "regtest"

[listen]
user_addr = "127.0.0.1:0"
peer_addr = "127.0.0.1:0"

[peers]
urls = []
pubkeys = []

[database]
path = "{db_path}"

[bitcoind]
rpc_url = "{rpc_url}"
rpc_user = "{rpc_user}"
rpc_pass = "{rpc_pass}"
"#,
        key_path = key_path.display(),
        db_path = db_path.display(),
        rpc_url = btc.rpc_url,
        rpc_user = btc.rpc_user,
        rpc_pass = btc.rpc_pass,
    );

    let config: config::Config = toml::from_str(&config_content).unwrap();
    let params = config.protocol_params();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    db::init(&conn).unwrap();

    let secret_key = keys::load_or_generate_key(key_path.to_str().unwrap()).unwrap();
    let our_pubkey = keys::public_key(&secret_key);
    let key_agg_ctx = keys::build_key_agg_ctx(&[our_pubkey]).unwrap();
    let agg: musig2::secp::Point = key_agg_ctx.aggregated_pubkey();
    let operator_xonly = keys::point_to_xonly(agg);

    let coordinator = Arc::new(Mutex::new(signing_coordinator::SigningCoordinator::new(
        0, 1, secret_key, key_agg_ctx, operator_xonly, params.clone(),
    )));
    // No fake pool UTXO — the first credit creates the real one.

    let shared_chain_state = Arc::new(Mutex::new(db::rebuild_chain_state(&conn).unwrap()));
    let shared_block_producer = Arc::new(Mutex::new(block_producer::BlockProducer::new()));

    let state = Arc::new(AppState {
        config,
        params,
        db: Mutex::new(conn),
        coordinator: coordinator.clone(),
        chain_state: shared_chain_state.clone(),
        block_producer: shared_block_producer.clone(),
    });

    // Block driver: mempool → blocks → chain state
    let bd_bp = shared_block_producer.clone();
    let bd_cs = shared_chain_state.clone();
    let bd_db = Arc::new(Mutex::new(rusqlite::Connection::open(&db_path).unwrap()));
    tokio::spawn(block_driver::run_block_driver(
        bd_bp,
        bd_cs,
        bd_db,
        true,
        block_driver::BlockDriverConfig {
            poll_interval: Duration::from_millis(50),
            peer_urls: vec![],
        },
    ));

    // State driver: chain state → exit tree signing → refresh
    let sd_db = Arc::new(Mutex::new(rusqlite::Connection::open(&db_path).unwrap()));
    let btc_config = config::BitcoindConfig {
        rpc_url: btc.rpc_url.clone(),
        rpc_user: btc.rpc_user.clone(),
        rpc_pass: btc.rpc_pass.clone(),
    };
    tokio::spawn(state_driver::run_state_driver(
        coordinator.clone(),
        sd_db,
        shared_chain_state.clone(),
        state_driver::StateDriverConfig {
            poll_interval: Duration::from_millis(300),
            min_pending_changes: 1,
            peer_urls: vec![],
            bitcoind: Some(btc_config),
        },
    ));

    // REST API
    let app = api::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Peer service
    let peer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_db = Arc::new(Mutex::new(rusqlite::Connection::open(&db_path).unwrap()));
    let peer_state = peer_service::PeerState {
        coordinator: coordinator.clone(),
        chain_state: shared_chain_state.clone(),
        db: peer_db,
    };
    tokio::spawn(async move {
        let app = peer_service::router(peer_state);
        axum::serve(peer_listener, app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    Some(TestEnv {
        base_url,
        block_producer: shared_block_producer,
        _bitcoind: btc,
        _tmp_dir: tmp_dir,
    })
}

impl TestEnv {
    /// Credit a user via the faucet endpoint (mines real Bitcoin, deposits to pool).
    async fn credit_user(&self, client: &Client, pubkey_hex: &str, amount: u64) {
        let resp: Value = client
            .post(format!("{}/api/admin/credit", self.base_url))
            .json(&serde_json::json!({
                "pubkey": pubkey_hex,
                "amount_sats": amount,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["status"], "ok", "credit failed: {resp}");
        self.wait_for_mempool_drain().await;
    }

    async fn get_balance(&self, client: &Client, pubkey_hex: &str) -> u64 {
        let resp: Value = client
            .get(format!("{}/api/balance/{pubkey_hex}", self.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        resp["balance_sats"].as_u64().unwrap()
    }

    async fn wait_for_mempool_drain(&self) {
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let pending = {
                let bp = self.block_producer.lock().await;
                bp.pending_count()
            };
            if pending == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                return;
            }
        }
        panic!("mempool did not drain within 4 seconds");
    }
}

// ─── Key / Signing Helpers ────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct TestUser {
    keypair: bitcoin::secp256k1::Keypair,
    xonly: XOnlyPublicKey,
    hex: String,
}

fn make_user(secret_byte: u8) -> TestUser {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = secret_byte;
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let (xonly, _) = keypair.x_only_public_key();
    TestUser {
        keypair,
        xonly,
        hex: hex_encode(&xonly.serialize()),
    }
}

fn sign_transfer(user: &TestUser, to: &XOnlyPublicKey, amount: u64, nonce: u64) -> String {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let msg = blockchain::transfer_message(to, amount, nonce);
    let sig = secp.sign_schnorr(&msg, &user.keypair);
    hex_encode(&sig.serialize())
}

fn sign_withdrawal(user: &TestUser, amount: u64, nonce: u64) -> String {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let msg = blockchain::withdrawal_message(&user.xonly, amount, nonce);
    let sig = secp.sign_schnorr(&msg, &user.keypair);
    hex_encode(&sig.serialize())
}

// ─── Tests ────────────────────────────────────────────────────────────────

/// Full lifecycle against real regtest bitcoind:
/// credit (pool creation) → credit (pool consolidation) → transfer →
/// error cases → withdrawal → balance verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_regtest_full_lifecycle() {
    let Some(env) = start_regtest_env().await else {
        eprintln!("skipping: bitcoind not available");
        return;
    };
    let client = Client::new();

    // === Before any credit: no pool ===
    let info: Value = client
        .get(format!("{}/api/info", env.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["chain"], "regtest");
    assert_eq!(info["epoch_id"], 0, "no epoch before first credit");

    // === Credit Alice: creates pool from a real on-chain deposit ===
    let alice = make_user(10);
    env.credit_user(&client, &alice.hex, 100_000).await;
    assert_eq!(env.get_balance(&client, &alice.hex).await, 100_000);

    let info: Value = client
        .get(format!("{}/api/info", env.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["epoch_id"], 1, "epoch created after first credit");
    let pool_after_first = info["pool_amount_sats"].as_u64().unwrap();
    assert!(pool_after_first >= 100_000);

    // === Credit Bob: consolidates existing pool with new deposit ===
    let bob = make_user(11);
    env.credit_user(&client, &bob.hex, 50_000).await;
    assert_eq!(env.get_balance(&client, &bob.hex).await, 50_000);

    let info: Value = client
        .get(format!("{}/api/info", env.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pool_after_second = info["pool_amount_sats"].as_u64().unwrap();
    assert!(
        pool_after_second > pool_after_first,
        "pool should grow after second credit: {pool_after_second} > {pool_after_first}"
    );

    // === Transfer: Alice → Bob ===
    let sig = sign_transfer(&alice, &bob.xonly, 30_000, 1);
    let resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": alice.hex,
            "to": bob.hex,
            "amount_sats": 30_000,
            "nonce": 1,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "pending");
    env.wait_for_mempool_drain().await;

    assert_eq!(env.get_balance(&client, &alice.hex).await, 70_000);
    assert_eq!(env.get_balance(&client, &bob.hex).await, 80_000);

    // === Error: invalid signature (Eve forges Alice's transfer) ===
    let eve = make_user(12);
    let bad_sig = sign_transfer(&eve, &bob.xonly, 10_000, 2);
    let resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": alice.hex,
            "to": bob.hex,
            "amount_sats": 10_000,
            "nonce": 2,
            "signature": bad_sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("auth failed"));

    // === Error: insufficient balance ===
    let sig = sign_transfer(&alice, &bob.xonly, 999_999, 2);
    let resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": alice.hex,
            "to": bob.hex,
            "amount_sats": 999_999,
            "nonce": 2,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("insufficient"));

    // === Balances unchanged after errors ===
    assert_eq!(env.get_balance(&client, &alice.hex).await, 70_000);
    assert_eq!(env.get_balance(&client, &bob.hex).await, 80_000);

    // === Withdrawal: Alice withdraws 20k ===
    let dest = "512000112233445566778899aabbccddeeff00112233445566778899aabbccddee";
    let sig = sign_withdrawal(&alice, 20_000, 2);
    let resp: Value = client
        .post(format!("{}/api/withdrawal", env.base_url))
        .json(&serde_json::json!({
            "pubkey": alice.hex,
            "amount_sats": 20_000,
            "dest_address": dest,
            "nonce": 2,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "pending", "withdrawal should be accepted: {resp}");
    env.wait_for_mempool_drain().await;

    assert_eq!(env.get_balance(&client, &alice.hex).await, 50_000);
    assert_eq!(env.get_balance(&client, &bob.hex).await, 80_000);

    // === Error: withdrawal with wrong signature ===
    let bad_sig = sign_withdrawal(&eve, 10_000, 3);
    let resp: Value = client
        .post(format!("{}/api/withdrawal", env.base_url))
        .json(&serde_json::json!({
            "pubkey": alice.hex,
            "amount_sats": 10_000,
            "dest_address": dest,
            "nonce": 3,
            "signature": bad_sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("auth failed"));

    // === Error: withdrawal exceeding balance ===
    let sig = sign_withdrawal(&alice, 999_999, 3);
    let resp: Value = client
        .post(format!("{}/api/withdrawal", env.base_url))
        .json(&serde_json::json!({
            "pubkey": alice.hex,
            "amount_sats": 999_999,
            "dest_address": dest,
            "nonce": 3,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("insufficient"));

    // === Final balance check ===
    assert_eq!(env.get_balance(&client, &alice.hex).await, 50_000);
    assert_eq!(env.get_balance(&client, &bob.hex).await, 80_000);
}

/// State driver signs exit tree with real pool UTXO after users are credited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_regtest_state_signing() {
    let Some(env) = start_regtest_env().await else {
        eprintln!("skipping: bitcoind not available");
        return;
    };
    let client = Client::new();

    // Credit 4 users to populate the exit tree
    let users: Vec<TestUser> = (20..24).map(make_user).collect();
    for u in &users {
        env.credit_user(&client, &u.hex, 100_000).await;
    }

    for u in &users {
        assert_eq!(env.get_balance(&client, &u.hex).await, 100_000);
    }

    // Wait for the state driver to sign the exit tree.
    // Polls every 300ms; single-operator signing is immediate.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // System should be healthy and responsive after signing
    let health: Value = client
        .get(format!("{}/api/health", env.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");

    // Balances preserved
    for u in &users {
        assert_eq!(env.get_balance(&client, &u.hex).await, 100_000);
    }

    // Transfer after signing still works
    let sig = sign_transfer(&users[0], &users[1].xonly, 25_000, 1);
    let resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": users[0].hex,
            "to": users[1].hex,
            "amount_sats": 25_000,
            "nonce": 1,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "pending");
    env.wait_for_mempool_drain().await;

    assert_eq!(env.get_balance(&client, &users[0].hex).await, 75_000);
    assert_eq!(env.get_balance(&client, &users[1].hex).await, 125_000);
}

/// Nonce replay is rejected by the blockchain validation layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_regtest_nonce_replay() {
    let Some(env) = start_regtest_env().await else {
        eprintln!("skipping: bitcoind not available");
        return;
    };
    let client = Client::new();

    let alice = make_user(30);
    let bob = make_user(31);
    env.credit_user(&client, &alice.hex, 100_000).await;

    // First transfer: nonce=1
    let sig = sign_transfer(&alice, &bob.xonly, 10_000, 1);
    let resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": alice.hex,
            "to": bob.hex,
            "amount_sats": 10_000,
            "nonce": 1,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "pending");
    env.wait_for_mempool_drain().await;
    assert_eq!(env.get_balance(&client, &alice.hex).await, 90_000);

    // Replay same nonce — block driver drops it during validation
    let sig2 = sign_transfer(&alice, &bob.xonly, 10_000, 1);
    let _resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": alice.hex,
            "to": bob.hex,
            "amount_sats": 10_000,
            "nonce": 1,
            "signature": sig2,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    env.wait_for_mempool_drain().await;

    // Balance unchanged — replay rejected
    assert_eq!(env.get_balance(&client, &alice.hex).await, 90_000);
    assert_eq!(env.get_balance(&client, &bob.hex).await, 10_000);

    // Incrementing nonce works
    let sig3 = sign_transfer(&alice, &bob.xonly, 5_000, 2);
    let resp: Value = client
        .post(format!("{}/api/transfer", env.base_url))
        .json(&serde_json::json!({
            "from": alice.hex,
            "to": bob.hex,
            "amount_sats": 5_000,
            "nonce": 2,
            "signature": sig3,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "pending");
    env.wait_for_mempool_drain().await;

    assert_eq!(env.get_balance(&client, &alice.hex).await, 85_000);
    assert_eq!(env.get_balance(&client, &bob.hex).await, 15_000);
}
