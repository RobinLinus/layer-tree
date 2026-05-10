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

    // Parse dest_address (hex-encoded script)
    let dest_script = match hex_decode(&req.dest_address) {
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

/// POST /api/admin/credit — regtest faucet: directly credit a pubkey's balance.
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

    let pk = match parse_xonly(&req.pubkey) {
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

    let new_balance = {
        let mut cs = state.chain_state.lock().await;
        let bal = cs.balances.entry(pk).or_insert(0);
        *bal += req.amount_sats;
        *bal
    };

    Ok(Json(serde_json::json!({
        "status": "ok",
        "pubkey": req.pubkey,
        "credited": req.amount_sats,
        "balance_sats": new_balance,
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
