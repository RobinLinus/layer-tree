//! User-facing REST API served via axum.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::services::ServeDir;

use crate::AppState;

/// Find the static assets directory.
fn static_dir() -> &'static str {
    if std::path::Path::new("static").exists() {
        "static"
    } else if std::path::Path::new("crates/operator/static").exists() {
        "crates/operator/static"
    } else {
        "static" // fallback
    }
}

/// Build the user-facing API router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/info", get(info))
        .route("/api/balance/{pubkey}", get(balance))
        .route("/api/transfer", post(transfer))
        .route("/api/deposit", post(deposit))
        .route("/api/withdrawal", post(withdrawal))
        .route("/api/admin/set_epoch", post(set_epoch))
        .route("/api/admin/credit", post(credit))
        .fallback_service(ServeDir::new(static_dir()))
        .with_state(state)
}

/// GET /api/health — lightweight health check.
async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain_height = {
        let cs = state.chain_state.lock().await;
        cs.height
    };
    let has_epoch = {
        let coord = state.coordinator.lock().await;
        coord.kickoff_outpoint.is_some()
    };
    let mempool_size = {
        let bp = state.block_producer.lock().await;
        bp.pending_count()
    };
    Json(serde_json::json!({
        "status": "ok",
        "chain_height": chain_height,
        "has_epoch": has_epoch,
        "mempool_size": mempool_size,
    }))
}

/// GET /api/info — operator and pool status.
async fn info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let coord = state.coordinator.lock().await;
    let pool_outpoint = coord.kickoff_outpoint.map(|op| format!("{}:{}", op.txid, op.vout));
    let pool_amount = coord.kickoff_output_amount.map(|a| a.to_sat());
    Json(serde_json::json!({
        "chain": state.config.network.chain,
        "fanout": state.params.fanout,
        "n_operators": state.config.n_operators(),
        "epoch_id": coord.current_epoch_id,
        "pool_outpoint": pool_outpoint,
        "pool_amount_sats": pool_amount,
    }))
}

/// GET /api/balance/:pubkey — user balance lookup (from chain state).
async fn balance(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Json<serde_json::Value> {
    // Parse pubkey and look up balance in chain state
    let bal = match parse_xonly(&pubkey_hex) {
        Ok(pk) => {
            let cs = state.chain_state.lock().await;
            cs.balances.get(&pk).copied().unwrap_or(0)
        }
        Err(_) => 0,
    };
    Json(serde_json::json!({
        "pubkey": pubkey_hex,
        "balance_sats": bal,
    }))
}

/// POST /api/transfer — initiate an off-chain transfer.
#[derive(serde::Deserialize)]
struct TransferReq {
    from: String,
    to: String,
    amount_sats: u64,
    nonce: u64,
    signature: String,
}

async fn transfer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TransferReq>,
) -> Json<serde_json::Value> {
    // Validate amounts
    if req.amount_sats == 0 {
        return Json(serde_json::json!({
            "status": "error",
            "message": "amount must be > 0",
        }));
    }

    // Parse pubkeys
    let from_pk = match parse_xonly(&req.from) {
        Ok(pk) => pk,
        Err(e) => return Json(serde_json::json!({ "status": "error", "message": e })),
    };
    let to_pk = match parse_xonly(&req.to) {
        Ok(pk) => pk,
        Err(e) => return Json(serde_json::json!({ "status": "error", "message": e })),
    };

    // Parse signature
    let sig_bytes = match hex_decode(&req.signature) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return Json(serde_json::json!({
                "status": "error",
                "message": "invalid signature (expected 64 hex bytes)",
            }));
        }
    };

    // Verify Schnorr signature
    if let Err(e) = crate::auth::verify_transfer_sig(
        &req.from,
        &req.to,
        req.amount_sats,
        req.nonce,
        &req.signature,
    ) {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("auth failed: {e}"),
        }));
    }

    // Pre-check balance against chain state for immediate feedback
    {
        let cs = state.chain_state.lock().await;
        let bal = cs.balances.get(&from_pk).copied().unwrap_or(0);
        if bal < req.amount_sats {
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("insufficient balance: have {}, need {}", bal, req.amount_sats),
            }));
        }
    }

    // Add to block producer mempool
    let op = layer_tree_core::blockchain::Operation::Transfer {
        from: from_pk,
        to: to_pk,
        amount: req.amount_sats,
        nonce: req.nonce,
        signature: layer_tree_core::blockchain::Sig(sig_bytes),
    };

    let mut bp = state.block_producer.lock().await;
    bp.add_operation(op);

    Json(serde_json::json!({
        "status": "pending",
        "message": "transfer queued for next block",
    }))
}

/// POST /api/deposit — register a deposit.
#[derive(serde::Deserialize)]
struct DepositReq {
    pubkey: String,
    outpoint: String, // "txid:vout"
    amount_sats: u64,
}

async fn deposit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DepositReq>,
) -> Json<serde_json::Value> {
    // Validate inputs
    if let Err(e) = parse_xonly(&req.pubkey) {
        return Json(serde_json::json!({ "status": "error", "message": format!("invalid pubkey: {e}") }));
    }
    if req.amount_sats == 0 {
        return Json(serde_json::json!({ "status": "error", "message": "amount must be > 0" }));
    }
    // Validate outpoint format
    if req.outpoint.rsplit_once(':').is_none() {
        return Json(serde_json::json!({ "status": "error", "message": "outpoint must be in txid:vout format" }));
    }

    let db = state.db.lock().await;

    // Store pending deposit
    let script_pubkey = format!("p2tr:{}", req.pubkey);
    if let Err(e) = db.execute(
        "INSERT INTO pending_deposits (user_pubkey, outpoint, amount, script_pubkey, status) VALUES (?1, ?2, ?3, ?4, 'pending')",
        rusqlite::params![req.pubkey, req.outpoint, req.amount_sats as i64, script_pubkey],
    ) {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("db error: {e}"),
        }));
    }

    Json(serde_json::json!({
        "status": "pending",
        "message": "deposit registered, will be included in next refresh",
    }))
}

/// POST /api/withdrawal — request an on-chain withdrawal.
#[derive(serde::Deserialize)]
struct WithdrawalReq {
    pubkey: String,
    amount_sats: u64,
    dest_address: String,
    nonce: u64,
    signature: String,
}

async fn withdrawal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WithdrawalReq>,
) -> Json<serde_json::Value> {
    // Parse pubkey
    let pk = match parse_xonly(&req.pubkey) {
        Ok(pk) => pk,
        Err(e) => return Json(serde_json::json!({ "status": "error", "message": e })),
    };

    // Parse signature
    let sig_bytes = match hex_decode(&req.signature) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return Json(serde_json::json!({
                "status": "error",
                "message": "invalid signature (expected 64 hex bytes)",
            }));
        }
    };

    // Verify Schnorr signature
    if let Err(e) = crate::auth::verify_withdrawal_sig(
        &req.pubkey,
        &req.dest_address,
        req.amount_sats,
        req.nonce,
        &req.signature,
    ) {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("auth failed: {e}"),
        }));
    }

    // Pre-check balance against chain state for immediate feedback
    {
        let cs = state.chain_state.lock().await;
        let bal = cs.balances.get(&pk).copied().unwrap_or(0);
        if bal < req.amount_sats {
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("insufficient balance: have {}, need {}", bal, req.amount_sats),
            }));
        }
    }

    // Parse dest_address: try as bitcoin address first, fall back to hex script
    let dest_script = if let Ok(addr) = req.dest_address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
        addr.assume_checked().script_pubkey()
    } else {
        match hex_decode(&req.dest_address) {
            Ok(bytes) if !bytes.is_empty() => bitcoin::ScriptBuf::from_bytes(bytes),
            Ok(_) => {
                return Json(serde_json::json!({
                    "status": "error",
                    "message": "dest_address cannot be empty",
                }));
            }
            Err(e) => {
                return Json(serde_json::json!({
                    "status": "error",
                    "message": format!("invalid dest_address: {e}"),
                }));
            }
        }
    };

    // Add to block producer mempool
    let op = layer_tree_core::blockchain::Operation::WithdrawalRequest {
        pubkey: pk,
        amount: req.amount_sats,
        dest_script,
        nonce: req.nonce,
        signature: layer_tree_core::blockchain::Sig(sig_bytes),
    };

    let mut bp = state.block_producer.lock().await;
    bp.add_operation(op);

    Json(serde_json::json!({
        "status": "pending",
        "message": "withdrawal queued for next block",
    }))
}

/// POST /api/admin/set_epoch — bootstrap a new epoch by setting the pool UTXO.
#[derive(serde::Deserialize)]
struct SetEpochReq {
    epoch_id: u64,
    /// Pool UTXO outpoint in "txid:vout" format.
    outpoint: String,
    /// Pool UTXO amount in satoshis.
    amount_sats: u64,
}

async fn set_epoch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetEpochReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify admin token
    if let Err(code) = check_admin_token(&state, &headers) {
        return Err(code);
    }

    // Parse outpoint
    let (txid_hex, vout_str) = match req.outpoint.rsplit_once(':') {
        Some(pair) => pair,
        None => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "outpoint must be in txid:vout format",
            })));
        }
    };

    let vout: u32 = match vout_str.parse() {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "invalid vout in outpoint",
            })));
        }
    };

    let txid: bitcoin::Txid = match txid_hex.parse() {
        Ok(t) => t,
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("invalid txid: {e}"),
            })));
        }
    };

    let outpoint = bitcoin::OutPoint::new(txid, vout);
    let amount = bitcoin::Amount::from_sat(req.amount_sats);

    // Set on the signing coordinator
    {
        let mut coord = state.coordinator.lock().await;
        coord.current_epoch_id = req.epoch_id;
        coord.kickoff_outpoint = Some(outpoint);
        coord.kickoff_output_amount = Some(amount);
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "epoch_id": req.epoch_id,
        "outpoint": req.outpoint,
        "amount_sats": req.amount_sats,
    })))
}

/// POST /api/admin/credit — regtest faucet.
///
/// Flow: mine a block → send BTC to pool → consolidate pool UTXO → credit user.
/// This creates real on-chain backing for the L2 balance.
#[derive(serde::Deserialize)]
struct CreditReq {
    pubkey: String,
    amount_sats: u64,
}

async fn credit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreditReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(code) = check_admin_token(&state, &headers) {
        return Err(code);
    }

    let user_pk = match parse_xonly(&req.pubkey) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("invalid pubkey: {e}"),
            })));
        }
    };

    if req.amount_sats == 0 {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "amount must be > 0",
        })));
    }

    // Require bitcoind
    let btc_config = match &state.config.bitcoind {
        Some(c) => c.clone(),
        None => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "bitcoind not configured — faucet requires a running bitcoin node",
            })));
        }
    };

    let rpc = match bitcoincore_rpc::Client::new(
        &btc_config.rpc_url,
        bitcoincore_rpc::Auth::UserPass(btc_config.rpc_user.clone(), btc_config.rpc_pass.clone()),
    ) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("bitcoind connection failed: {e}"),
            })));
        }
    };

    use bitcoincore_rpc::RpcApi;

    // Get operator key for pool address
    let operator_xonly = {
        let coord = state.coordinator.lock().await;
        coord.operator_xonly
    };
    let pool_address = bitcoin::Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(operator_xonly),
        bitcoin::Network::Regtest,
    );
    let pool_script = pool_address.script_pubkey();
    let deposit_amount = bitcoin::Amount::from_sat(req.amount_sats);

    // Step 1: Mine — ensure wallet has spendable funds
    let wallet_addr = match rpc.get_new_address(None, None) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("get_new_address: {e}"),
            })));
        }
    };

    let balance = rpc.get_balance(None, None).unwrap_or(bitcoin::Amount::ZERO);
    if balance < deposit_amount + bitcoin::Amount::from_sat(10_000) {
        if let Err(e) = rpc.generate_to_address(101, &wallet_addr) {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("mining failed: {e}"),
            })));
        }
    }

    // Step 2: Deposit — send BTC to pool address
    let deposit_txid = match rpc.send_to_address(
        &pool_address, deposit_amount,
        None, None, None, None, None, None,
    ) {
        Ok(txid) => txid,
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("send_to_address: {e}"),
            })));
        }
    };

    // Mine to confirm
    if let Err(e) = rpc.generate_to_address(1, &wallet_addr) {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("mining failed: {e}"),
        })));
    }

    // Find the deposit output
    let deposit_tx = match rpc.get_raw_transaction(&deposit_txid, None) {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("get deposit tx: {e}"),
            })));
        }
    };
    let (deposit_vout, deposit_output_amount) = match deposit_tx
        .output.iter().enumerate()
        .find(|(_, o)| o.script_pubkey == pool_script)
        .map(|(i, o)| (i as u32, o.value))
    {
        Some(v) => v,
        None => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "deposit output to pool address not found in tx",
            })));
        }
    };
    let deposit_outpoint = bitcoin::OutPoint::new(deposit_txid, deposit_vout);

    // Step 3: Consolidate — merge with existing pool UTXO (if any)
    let (new_pool_outpoint, new_pool_amount) = {
        let existing_pool = {
            let coord = state.coordinator.lock().await;
            coord.kickoff_outpoint.map(|op| (op, coord.kickoff_output_amount.unwrap_or(bitcoin::Amount::ZERO)))
        };

        if let Some((old_outpoint, old_amount)) = existing_pool {
            let fee = bitcoin::Amount::from_sat(200);
            let new_amount = old_amount + deposit_output_amount - fee;

            let mut tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![
                    bitcoin::TxIn {
                        previous_output: old_outpoint,
                        script_sig: bitcoin::ScriptBuf::new(),
                        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                    bitcoin::TxIn {
                        previous_output: deposit_outpoint,
                        script_sig: bitcoin::ScriptBuf::new(),
                        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                ],
                output: vec![bitcoin::TxOut {
                    value: new_amount,
                    script_pubkey: pool_script.clone(),
                }],
            };

            // Sign both inputs with operator's MuSig2 key
            let prevouts = vec![
                bitcoin::TxOut { value: old_amount, script_pubkey: pool_script.clone() },
                bitcoin::TxOut { value: deposit_output_amount, script_pubkey: pool_script.clone() },
            ];
            {
                let coord = state.coordinator.lock().await;
                for i in 0..tx.input.len() {
                    layer_tree_core::signing::sign_input_musig2(
                        &mut tx, i, &prevouts,
                        &coord.key_agg_ctx,
                        std::slice::from_ref(&coord.secret_key),
                    );
                }
            }

            // Broadcast and mine
            if let Err(e) = rpc.send_raw_transaction(&tx) {
                return Ok(Json(serde_json::json!({
                    "status": "error",
                    "message": format!("broadcast consolidation tx: {e}"),
                })));
            }
            let _ = rpc.generate_to_address(1, &wallet_addr);

            (bitcoin::OutPoint::new(tx.compute_txid(), 0), new_amount)
        } else {
            // No existing pool — this deposit becomes the initial pool UTXO
            (deposit_outpoint, deposit_output_amount)
        }
    };

    // Update coordinator's pool
    {
        let mut coord = state.coordinator.lock().await;
        coord.kickoff_outpoint = Some(new_pool_outpoint);
        coord.kickoff_output_amount = Some(new_pool_amount);
        if coord.current_epoch_id == 0 {
            coord.current_epoch_id = 1;
        }
    }

    // Step 4: Send — credit user via ephemeral deposit + transfer
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut faucet_sk_bytes = [0u8; 32];
    rand::fill(&mut faucet_sk_bytes);
    let faucet_keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &faucet_sk_bytes)
        .expect("valid random key");
    let (faucet_xonly, _) = faucet_keypair.x_only_public_key();

    // DepositConfirm credits the ephemeral faucet account
    let deposit_op = layer_tree_core::blockchain::Operation::DepositConfirm {
        pubkey: faucet_xonly,
        amount: req.amount_sats,
        outpoint: deposit_outpoint,
    };

    // Transfer from faucet account to user (signed with ephemeral key)
    let nonce = 1u64;
    let msg = layer_tree_core::blockchain::transfer_message(&user_pk, req.amount_sats, nonce);
    let sig = secp.sign_schnorr(&msg, &faucet_keypair);

    let transfer_op = layer_tree_core::blockchain::Operation::Transfer {
        from: faucet_xonly,
        to: user_pk,
        amount: req.amount_sats,
        nonce,
        signature: layer_tree_core::blockchain::Sig(sig.serialize()),
    };

    // Both ops go into the same block: deposit first, then transfer
    {
        let mut bp = state.block_producer.lock().await;
        bp.add_operation(deposit_op);
        bp.add_operation(transfer_op);
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": format!("Mined block, deposited to pool, credited {} sats", req.amount_sats),
        "pubkey": req.pubkey,
        "amount_sats": req.amount_sats,
        "pool_outpoint": format!("{}:{}", new_pool_outpoint.txid, new_pool_outpoint.vout),
        "pool_amount_sats": new_pool_amount.to_sat(),
    })))
}

// --- Helpers ---

/// Check the Authorization header for a valid admin bearer token.
/// Returns Ok(()) if auth passes, Err(StatusCode) otherwise.
fn check_admin_token(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected = &state.config.admin.token;

    // If no token is configured, admin endpoints are open (for regtest convenience).
    // Production deployments MUST set [admin] token in config.
    if expected.is_empty() {
        return Ok(());
    }

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let provided = auth.strip_prefix("Bearer ").unwrap_or("");

    if provided == expected {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn parse_xonly(hex: &str) -> Result<bitcoin::XOnlyPublicKey, String> {
    let bytes = hex_decode(hex)?;
    bitcoin::XOnlyPublicKey::from_slice(&bytes).map_err(|e| format!("invalid pubkey: {e}"))
}
