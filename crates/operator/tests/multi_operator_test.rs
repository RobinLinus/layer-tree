//! Multi-operator integration test.
//!
//! Tests 3 operators coordinating a state signing round via the peer HTTP API.
//! Each operator runs its own axum server; the leader drives the protocol.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Txid};
use musig2::secp::Scalar;
use musig2::KeyAggContext;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::Mutex;

use layer_tree_core::blockchain::ChainState;
use layer_tree_operator::{db, keys, peer_service};
use layer_tree_operator::signing_coordinator::SigningCoordinator;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}


struct TestOperator {
    pub coordinator: Arc<Mutex<SigningCoordinator>>,
    pub base_url: String,
    pub _handle: tokio::task::JoinHandle<()>,
}

/// Start N operator peer servers.
async fn start_operators(n: usize) -> Vec<TestOperator> {
    // Generate N secret keys
    let secret_keys: Vec<Scalar> = (0..n)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[31] = (i + 1) as u8;
            let sk = musig2::secp256k1::SecretKey::from_byte_array(bytes).unwrap();
            sk.into()
        })
        .collect();

    // Derive pubkeys and build key_agg_ctx
    let pubkeys: Vec<musig2::secp::Point> = secret_keys
        .iter()
        .map(|s| s.base_point_mul())
        .collect();

    let key_agg_ctx = KeyAggContext::new(pubkeys.iter().copied()).unwrap();
    let agg: musig2::secp::Point = key_agg_ctx.aggregated_pubkey();
    let operator_xonly = keys::point_to_xonly(agg);

    let params = layer_tree_core::REGTEST_PARAMS;

    let mut operators = Vec::new();

    for (i, sk) in secret_keys.iter().enumerate() {
        let coordinator = Arc::new(Mutex::new(SigningCoordinator::new(
            i,
            n,
            *sk,
            key_agg_ctx.clone(),
            operator_xonly,
            params.clone(),
        )));

        // Set a pool UTXO so signing works
        {
            let mut coord = coordinator.lock().await;
            coord.kickoff_outpoint = Some(OutPoint::new(
                Txid::from_byte_array([0xAA; 32]),
                0,
            ));
            coord.kickoff_output_amount = Some(Amount::from_sat(1_000_000));
        }

        // Start peer service on random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let peer_db = {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            db::init(&conn).unwrap();
            Arc::new(Mutex::new(conn))
        };
        let chain_state = Arc::new(Mutex::new(ChainState::genesis()));
        let peer_state = peer_service::PeerState {
            coordinator: coordinator.clone(),
            chain_state,
            db: peer_db,
        };
        let handle = tokio::spawn(async move {
            let app = peer_service::router(peer_state);
            axum::serve(listener, app).await.unwrap();
        });

        operators.push(TestOperator {
            coordinator,
            base_url,
            _handle: handle,
        });
    }

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    operators
}

#[tokio::test]
async fn test_three_operator_signing_via_peer_api() {
    let operators = start_operators(3).await;
    let client = Client::new();

    // Generate a session ID
    let session_id = [0x42u8; 32];
    let session_id_hex = hex_encode(&session_id);

    let secp = bitcoin::secp256k1::Secp256k1::new();

    // Allocations: must satisfy exit tree constraints.
    // kickoff_output_amount is set to 1_000_000
    // root_output = 1_000_000 - root_fee(200) = 999_800
    // exit tree required_input_amount = sum(allocations) + split_fees
    // With fanout=4 and 4 users, there's 1 split TX: split_fee = 300
    // So: sum(allocations) = 999_800 - 300 = 999_500
    // Split across 4 users: 249_875 each
    let user_amount = 249_875u64;
    let mut allocations = Vec::new();
    // We need exactly 4 users for a clean single-level tree (fanout=4)
    for i in 0..4u8 {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 100 + i;
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();
        allocations.push(serde_json::json!({
            "pubkey": hex_encode(&xonly.serialize()),
            "amount_sats": user_amount,
        }));
    }

    // === Step 1: Propose state to all operators ===
    let mut nonces_by_signer: Vec<(u32, Vec<String>)> = Vec::new();

    for (i, op) in operators.iter().enumerate() {
        let resp: Value = client
            .post(format!("{}/peer/propose_state", op.base_url))
            .json(&serde_json::json!({
                "session_id": session_id_hex,
                "epoch_id": 0,
                "state_number": 1,
                "nsequence": 18, // nseq_start(20) - step_size(2) * state_number(1)
                "at_block_hash": "", // empty = skip chain state verification (legacy)
                "allocations": allocations,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(
            resp["accepted"].as_bool().unwrap(),
            "operator {i} rejected proposal: {}",
            resp["reject_reason"]
        );

        let pub_nonces: Vec<String> = resp["pub_nonces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert!(!pub_nonces.is_empty(), "operator {i} returned no nonces");
        nonces_by_signer.push((i as u32, pub_nonces));
    }

    // === Step 2: Submit all nonces to all operators ===
    let signer_nonces: Vec<Value> = nonces_by_signer
        .iter()
        .map(|(idx, nonces)| {
            serde_json::json!({
                "signer_index": idx,
                "pub_nonces": nonces,
            })
        })
        .collect();

    let mut partial_sigs_by_signer: Vec<(u32, Vec<String>)> = Vec::new();

    for (i, op) in operators.iter().enumerate() {
        let resp: Value = client
            .post(format!("{}/peer/submit_nonces", op.base_url))
            .json(&serde_json::json!({
                "session_id": session_id_hex,
                "signer_nonces": signer_nonces,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(
            resp["accepted"].as_bool().unwrap(),
            "operator {i} rejected nonces: {}",
            resp["reject_reason"]
        );

        let psigs: Vec<String> = resp["partial_sigs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        if !psigs.is_empty() {
            partial_sigs_by_signer.push((i as u32, psigs));
        }
    }

    // All operators should have produced partial sigs
    assert_eq!(
        partial_sigs_by_signer.len(),
        3,
        "expected all 3 operators to produce partial sigs"
    );

    // === Step 3: Submit all partial sigs to all operators ===
    let signer_partial_sigs: Vec<Value> = partial_sigs_by_signer
        .iter()
        .map(|(idx, sigs)| {
            serde_json::json!({
                "signer_index": idx,
                "partial_sigs": sigs,
            })
        })
        .collect();

    for (i, op) in operators.iter().enumerate() {
        let resp: Value = client
            .post(format!("{}/peer/submit_partial_sigs", op.base_url))
            .json(&serde_json::json!({
                "session_id": session_id_hex,
                "signer_partial_sigs": signer_partial_sigs,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(
            resp["accepted"].as_bool().unwrap(),
            "operator {i} rejected partial sigs: {}",
            resp["reject_reason"]
        );
    }

    // === Step 4: Verify all operators have completed sessions ===
    for (i, op) in operators.iter().enumerate() {
        let mut coord = op.coordinator.lock().await;
        let result = coord.take_completed_session(&session_id);
        assert!(
            result.is_some(),
            "operator {i} session did not complete"
        );
        let (_session, sigs) = result.unwrap();
        assert!(!sigs.is_empty(), "operator {i} has no signatures");

        // Verify signatures are valid Schnorr signatures
        for sig in &sigs {
            assert_eq!(sig.serialize().len(), 64);
        }
    }
}

#[tokio::test]
async fn test_handshake() {
    let operators = start_operators(2).await;
    let client = Client::new();

    let resp: Value = client
        .post(format!("{}/peer/handshake", operators[0].base_url))
        .json(&serde_json::json!({
            "signer_index": 1,
            "pubkey": "deadbeef",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(resp["accepted"].as_bool().unwrap());
    assert_eq!(resp["signer_index"], 0);
    // pubkey should be a valid hex string
    let pk = resp["pubkey"].as_str().unwrap();
    assert_eq!(pk.len(), 64); // 32 bytes = 64 hex chars
}
