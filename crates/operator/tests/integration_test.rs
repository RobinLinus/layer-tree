//! Integration test: starts an operator and exercises the REST API.

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

/// Start an operator server and return the base URL.
/// Returns the TempDir to keep it alive for the duration of the test.
async fn start_operator() -> (String, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let key_path = tmp_dir.path().join("key.bin");
    let db_path = tmp_dir.path().join("test.db");

    let config_content = format!(
        r#"
[operator]
key_file = "{}"

[network]
chain = "regtest"

[listen]
user_addr = "127.0.0.1:0"
peer_addr = "127.0.0.1:0"

[peers]
urls = []
pubkeys = []

[database]
path = "{}"
"#,
        key_path.display(),
        db_path.display(),
    );

    use std::sync::Arc;
    use tokio::sync::Mutex;

    let config: layer_tree_operator::config::Config =
        toml::from_str(&config_content).unwrap();
    let params = config.protocol_params();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    layer_tree_operator::db::init(&conn).unwrap();

    let secret_key =
        layer_tree_operator::keys::load_or_generate_key(key_path.to_str().unwrap()).unwrap();
    let our_pubkey = layer_tree_operator::keys::public_key(&secret_key);
    let key_agg_ctx = layer_tree_operator::keys::build_key_agg_ctx(&[our_pubkey]).unwrap();
    let agg: musig2::secp::Point = key_agg_ctx.aggregated_pubkey();
    let operator_xonly = layer_tree_operator::keys::point_to_xonly(agg);

    let coordinator = Arc::new(Mutex::new(
        layer_tree_operator::signing_coordinator::SigningCoordinator::new(
            0, 1, secret_key, key_agg_ctx, operator_xonly, params.clone(),
        ),
    ));

    let shared_chain_state = Arc::new(Mutex::new(
        layer_tree_operator::db::rebuild_chain_state(&conn).unwrap(),
    ));
    let shared_block_producer = Arc::new(Mutex::new(
        layer_tree_operator::block_producer::BlockProducer::new(),
    ));

    let state = Arc::new(layer_tree_operator::AppState {
        config,
        params,
        db: Mutex::new(conn),
        coordinator,
        chain_state: shared_chain_state,
        block_producer: shared_block_producer,
    });

    let app = layer_tree_operator::api::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (base_url, handle, tmp_dir)
}

#[tokio::test]
async fn test_info_endpoint() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    let resp: Value = client
        .get(format!("{base_url}/api/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["chain"], "regtest");
    assert_eq!(resp["fanout"], 4);
}

#[tokio::test]
async fn test_balance_zero_for_unknown() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    let resp: Value = client
        .get(format!("{base_url}/api/balance/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["balance_sats"], 0);
}

#[tokio::test]
async fn test_transfer_insufficient_balance() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    // Generate a valid keypair and sign the transfer
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 10;
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let (xonly, _) = keypair.x_only_public_key();
    let from_hex = hex_encode(&xonly.serialize());

    let mut to_sk_bytes = [0u8; 32];
    to_sk_bytes[31] = 11;
    let to_keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &to_sk_bytes).unwrap();
    let (to_xonly, _) = to_keypair.x_only_public_key();
    let to_hex = hex_encode(&to_xonly.serialize());
    let amount = 1000u64;
    let nonce = 0u64;

    let msg = layer_tree_operator::auth::build_transfer_message(&to_hex, amount, nonce);
    let sig = secp.sign_schnorr(&msg, &keypair);
    let sig_hex = hex_encode(&sig.serialize());

    let resp: Value = client
        .post(format!("{base_url}/api/transfer"))
        .json(&serde_json::json!({
            "from": from_hex,
            "to": to_hex,
            "amount_sats": amount,
            "nonce": nonce,
            "signature": sig_hex,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("insufficient"));
}

#[tokio::test]
async fn test_deposit_and_withdrawal_flow() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    // Generate a valid keypair for the user
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 20;
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let (xonly, _) = keypair.x_only_public_key();
    let pubkey_hex = hex_encode(&xonly.serialize());

    // Register a deposit
    let resp: Value = client
        .post(format!("{base_url}/api/deposit"))
        .json(&serde_json::json!({
            "pubkey": pubkey_hex,
            "outpoint": "abcd1234:0",
            "amount_sats": 50000,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "pending", "deposit failed: {resp}");

    // Request withdrawal (should fail — no balance yet)
    let dest_address = "512000112233445566778899aabbccddeeff00112233445566778899aabbccddee"; // p2tr script hex
    let amount = 1000u64;
    let nonce = 0u64;
    let msg = layer_tree_operator::auth::build_withdrawal_message(dest_address, amount, nonce);
    let sig = secp.sign_schnorr(&msg, &keypair);
    let sig_hex = hex_encode(&sig.serialize());

    let resp: Value = client
        .post(format!("{base_url}/api/withdrawal"))
        .json(&serde_json::json!({
            "pubkey": pubkey_hex,
            "amount_sats": amount,
            "dest_address": dest_address,
            "nonce": nonce,
            "signature": sig_hex,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("insufficient"));
}

#[tokio::test]
async fn test_authenticated_transfer() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    // Generate a user keypair
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    secret_bytes[31] = 42;
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &secret_bytes).unwrap();
    let (xonly, _) = keypair.x_only_public_key();
    let from_hex = hex_encode(&xonly.serialize());

    let mut to_sk_bytes = [0u8; 32];
    to_sk_bytes[31] = 43;
    let to_keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &to_sk_bytes).unwrap();
    let (to_xonly, _) = to_keypair.x_only_public_key();
    let to_hex = hex_encode(&to_xonly.serialize());
    let amount = 10_000u64;
    let nonce = 1u64;

    // Sign transfer message
    let msg = layer_tree_operator::auth::build_transfer_message(&to_hex, amount, nonce);
    let sig = secp.sign_schnorr(&msg, &keypair);
    let sig_hex = hex_encode(&sig.serialize());

    // Test that auth fails with bad sig
    let resp: Value = client
        .post(format!("{base_url}/api/transfer"))
        .json(&serde_json::json!({
            "from": from_hex,
            "to": to_hex,
            "amount_sats": amount,
            "nonce": nonce,
            "signature": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Should fail auth (bad sig)
    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("auth failed"));

    // With correct sig but no balance, should fail with "insufficient"
    let resp: Value = client
        .post(format!("{base_url}/api/transfer"))
        .json(&serde_json::json!({
            "from": from_hex,
            "to": to_hex,
            "amount_sats": amount,
            "nonce": nonce,
            "signature": sig_hex,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "error");
    assert!(resp["message"].as_str().unwrap().contains("insufficient"));
}

/// Start an operator with admin token configured.
async fn start_operator_with_admin(token: &str) -> (String, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let key_path = tmp_dir.path().join("key.bin");
    let db_path = tmp_dir.path().join("test.db");

    let config_content = format!(
        r#"
[operator]
key_file = "{}"

[network]
chain = "regtest"

[listen]
user_addr = "127.0.0.1:0"
peer_addr = "127.0.0.1:0"

[peers]
urls = []
pubkeys = []

[database]
path = "{}"

[admin]
token = "{}"
"#,
        key_path.display(),
        db_path.display(),
        token,
    );

    use std::sync::Arc;
    use tokio::sync::Mutex;

    let config: layer_tree_operator::config::Config =
        toml::from_str(&config_content).unwrap();
    let params = config.protocol_params();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    layer_tree_operator::db::init(&conn).unwrap();

    let secret_key =
        layer_tree_operator::keys::load_or_generate_key(key_path.to_str().unwrap()).unwrap();
    let our_pubkey = layer_tree_operator::keys::public_key(&secret_key);
    let key_agg_ctx = layer_tree_operator::keys::build_key_agg_ctx(&[our_pubkey]).unwrap();
    let agg: musig2::secp::Point = key_agg_ctx.aggregated_pubkey();
    let operator_xonly = layer_tree_operator::keys::point_to_xonly(agg);

    let coordinator = Arc::new(Mutex::new(
        layer_tree_operator::signing_coordinator::SigningCoordinator::new(
            0, 1, secret_key, key_agg_ctx, operator_xonly, params.clone(),
        ),
    ));

    let shared_chain_state = Arc::new(Mutex::new(
        layer_tree_operator::db::rebuild_chain_state(&conn).unwrap(),
    ));
    let shared_block_producer = Arc::new(Mutex::new(
        layer_tree_operator::block_producer::BlockProducer::new(),
    ));

    let state = Arc::new(layer_tree_operator::AppState {
        config,
        params,
        db: Mutex::new(conn),
        coordinator,
        chain_state: shared_chain_state,
        block_producer: shared_block_producer,
    });

    let app = layer_tree_operator::api::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (base_url, handle, tmp_dir)
}

#[tokio::test]
async fn test_health_endpoint() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    let resp: Value = client
        .get(format!("{base_url}/api/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "ok");
    assert_eq!(resp["chain_height"], 0);
    assert_eq!(resp["has_epoch"], false);
    assert_eq!(resp["mempool_size"], 0);
}

#[tokio::test]
async fn test_admin_set_epoch_open_without_token() {
    let (base_url, _handle, _tmp_dir) = start_operator().await;
    let client = Client::new();

    // No admin token configured → open by default (regtest convenience)
    let resp: Value = client
        .post(format!("{base_url}/api/admin/set_epoch"))
        .json(&serde_json::json!({
            "epoch_id": 0,
            "outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
            "amount_sats": 1000000,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "ok");
}

#[tokio::test]
async fn test_admin_set_epoch_with_token() {
    let (base_url, _handle, _tmp_dir) = start_operator_with_admin("secret123").await;
    let client = Client::new();

    // Wrong token → 401
    let resp = client
        .post(format!("{base_url}/api/admin/set_epoch"))
        .header("Authorization", "Bearer wrongtoken")
        .json(&serde_json::json!({
            "epoch_id": 0,
            "outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
            "amount_sats": 1000000,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);

    // Correct token → success
    let resp: Value = client
        .post(format!("{base_url}/api/admin/set_epoch"))
        .header("Authorization", "Bearer secret123")
        .json(&serde_json::json!({
            "epoch_id": 0,
            "outpoint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
            "amount_sats": 1000000,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "ok");
    assert_eq!(resp["epoch_id"], 0);
    assert_eq!(resp["amount_sats"], 1000000);

    // Verify via info endpoint
    let info: Value = client
        .get(format!("{base_url}/api/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(info["epoch_id"], 0);
    assert_eq!(info["pool_amount_sats"], 1000000);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
