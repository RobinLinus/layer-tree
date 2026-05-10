//! Peer-to-peer HTTP API for operator communication.
//!
//! Uses JSON over HTTP (axum) instead of gRPC for simplicity.
//! Each MuSig2 signing round maps to a POST endpoint.
//! Also handles block propagation and chain sync between operators.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use musig2::{BinaryEncoding, PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use layer_tree_core::blockchain::{Block, ChainState, Checkpoint};
use layer_tree_core::tree::UserAllocation;

use crate::signing_coordinator::SharedCoordinator;

// --- JSON message types for peer protocol ---

#[derive(Serialize, Deserialize)]
pub struct HandshakeReq {
    pub signer_index: u32,
    pub pubkey: String, // hex
}

#[derive(Serialize, Deserialize)]
pub struct HandshakeResp {
    pub accepted: bool,
    pub signer_index: u32,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct AllocationMsg {
    pub pubkey: String, // 32-byte hex x-only
    pub amount_sats: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ProposeStateReq {
    pub session_id: String, // 32-byte hex
    pub epoch_id: u64,
    pub state_number: u32,
    pub nsequence: u32,
    pub at_block_hash: String, // hex-encoded 32-byte chain tip hash
    // allocations are no longer sent — derived from chain state
    #[serde(default)]
    pub allocations: Vec<AllocationMsg>, // deprecated, kept for compat
}

#[derive(Serialize, Deserialize)]
pub struct ProposeStateResp {
    pub accepted: bool,
    pub reject_reason: String,
    pub pub_nonces: Vec<String>, // hex-encoded 66-byte nonces
}

#[derive(Serialize, Deserialize)]
pub struct SignerNoncesMsg {
    pub signer_index: u32,
    pub pub_nonces: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitNoncesReq {
    pub session_id: String,
    pub signer_nonces: Vec<SignerNoncesMsg>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitNoncesResp {
    pub accepted: bool,
    pub reject_reason: String,
    pub partial_sigs: Vec<String>, // hex-encoded 32-byte sigs
}

#[derive(Serialize, Deserialize)]
pub struct SignerPartialSigsMsg {
    pub signer_index: u32,
    pub partial_sigs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitPartialSigsReq {
    pub session_id: String,
    pub signer_partial_sigs: Vec<SignerPartialSigsMsg>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitPartialSigsResp {
    pub accepted: bool,
    pub reject_reason: String,
}

// --- Refresh TX signing messages ---

#[derive(Serialize, Deserialize)]
pub struct DepositInputMsg {
    pub outpoint: String, // "txid:vout"
    pub amount_sats: u64,
    pub script_pubkey: String, // hex
}

#[derive(Serialize, Deserialize)]
pub struct WithdrawalOutputMsg {
    pub script_pubkey: String, // hex
    pub amount_sats: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ProposeRefreshReq {
    pub session_id: String,
    pub deposits: Vec<DepositInputMsg>,
    pub withdrawals: Vec<WithdrawalOutputMsg>,
    pub refresh_fee_sats: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ProposeRefreshResp {
    pub accepted: bool,
    pub reject_reason: String,
    pub pub_nonces: Vec<String>,
}

// --- Block propagation messages ---

#[derive(Serialize, Deserialize)]
pub struct ProposeBlockReq {
    pub block: Block,
}

#[derive(Serialize, Deserialize)]
pub struct ProposeBlockResp {
    pub accepted: bool,
    pub reject_reason: String,
}

#[derive(Serialize, Deserialize)]
pub struct SyncReq {
    pub my_height: u64,
    pub my_tip_hash: String, // hex-encoded 32 bytes
}

#[derive(Serialize, Deserialize)]
pub struct SyncResp {
    pub checkpoint: Option<Checkpoint>,
    pub blocks: Vec<Block>,
}

// --- Hex helpers ---

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- Shared peer state ---

/// Shared chain state for the peer service.
pub type SharedChainState = Arc<Mutex<ChainState>>;

/// All state accessible to peer handlers.
#[derive(Clone)]
pub struct PeerState {
    pub coordinator: SharedCoordinator,
    pub chain_state: SharedChainState,
    pub db: Arc<Mutex<rusqlite::Connection>>,
}

// --- Router ---

/// Build the peer-to-peer API router.
pub fn router(state: PeerState) -> Router {
    Router::new()
        .route("/peer/handshake", post(handshake))
        .route("/peer/propose_state", post(propose_state))
        .route("/peer/submit_nonces", post(submit_nonces))
        .route("/peer/submit_partial_sigs", post(submit_partial_sigs))
        .route("/peer/propose_refresh", post(propose_refresh))
        .route("/peer/propose_block", post(propose_block))
        .route("/peer/sync", post(sync))
        .with_state(state)
}

/// Start the peer HTTP server.
pub async fn serve(
    state: PeerState,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// --- Handlers ---

async fn handshake(
    State(state): State<PeerState>,
    Json(_req): Json<HandshakeReq>,
) -> Json<HandshakeResp> {
    let coord = state.coordinator.lock().await;
    Json(HandshakeResp {
        accepted: true,
        signer_index: coord.signer_index as u32,
        pubkey: hex_encode(&coord.operator_xonly.serialize()),
    })
}

async fn propose_state(
    State(state): State<PeerState>,
    Json(req): Json<ProposeStateReq>,
) -> Json<ProposeStateResp> {
    let session_id = match parse_session_id(&req.session_id) {
        Ok(id) => id,
        Err(e) => return Json(reject(e)),
    };

    // Verify the proposed block hash matches our local chain tip
    let allocations = {
        let cs = state.chain_state.lock().await;
        let our_tip_hex = hex_encode(&cs.tip_hash);
        if !req.at_block_hash.is_empty() && req.at_block_hash != our_tip_hex {
            return Json(reject(format!(
                "chain state mismatch: leader at {}, we are at {}",
                req.at_block_hash, our_tip_hex
            )));
        }
        // Derive allocations from our own chain state (deterministic)
        cs.allocations()
    };

    // Fallback: if allocations were sent directly (legacy), use those instead
    let allocations = if allocations.is_empty() && !req.allocations.is_empty() {
        match parse_allocations(&req.allocations) {
            Ok(a) => a,
            Err(e) => return Json(reject(e)),
        }
    } else {
        allocations
    };

    let mut coord = state.coordinator.lock().await;
    match coord.propose_state(
        session_id,
        req.epoch_id,
        req.state_number,
        req.nsequence as u16,
        allocations,
    ) {
        Ok(nonces) => {
            let pub_nonces = nonces.iter().map(|n| hex_encode(&n.to_bytes())).collect();
            Json(ProposeStateResp {
                accepted: true,
                reject_reason: String::new(),
                pub_nonces,
            })
        }
        Err(e) => Json(reject(e.to_string())),
    }
}

async fn submit_nonces(
    State(state): State<PeerState>,
    Json(req): Json<SubmitNoncesReq>,
) -> Json<SubmitNoncesResp> {
    let session_id = match parse_session_id(&req.session_id) {
        Ok(id) => id,
        Err(e) => {
            return Json(SubmitNoncesResp {
                accepted: false,
                reject_reason: e,
                partial_sigs: vec![],
            })
        }
    };

    let mut coord = state.coordinator.lock().await;
    let our_index = coord.signer_index;
    let mut our_partial_sigs = None;

    for sn in &req.signer_nonces {
        // Skip our own nonces — SigningSession rejects self-nonces
        if sn.signer_index as usize == our_index {
            continue;
        }

        let nonces: Result<Vec<PubNonce>, String> = sn
            .pub_nonces
            .iter()
            .map(|hex| {
                let bytes = hex_decode(hex)?;
                PubNonce::from_bytes(&bytes).map_err(|e| e.to_string())
            })
            .collect();

        let nonces = match nonces {
            Ok(n) => n,
            Err(e) => {
                return Json(SubmitNoncesResp {
                    accepted: false,
                    reject_reason: e,
                    partial_sigs: vec![],
                })
            }
        };

        match coord.receive_nonces(&session_id, sn.signer_index as usize, nonces) {
            Ok(Some(psigs)) => our_partial_sigs = Some(psigs),
            Ok(None) => {}
            Err(e) => {
                return Json(SubmitNoncesResp {
                    accepted: false,
                    reject_reason: e.to_string(),
                    partial_sigs: vec![],
                })
            }
        }
    }

    let partial_sigs = our_partial_sigs
        .map(|sigs| sigs.iter().map(|s| hex_encode(&s.serialize())).collect())
        .unwrap_or_default();

    Json(SubmitNoncesResp {
        accepted: true,
        reject_reason: String::new(),
        partial_sigs,
    })
}

async fn submit_partial_sigs(
    State(state): State<PeerState>,
    Json(req): Json<SubmitPartialSigsReq>,
) -> Json<SubmitPartialSigsResp> {
    let session_id = match parse_session_id(&req.session_id) {
        Ok(id) => id,
        Err(e) => {
            return Json(SubmitPartialSigsResp {
                accepted: false,
                reject_reason: e,
            })
        }
    };

    let mut coord = state.coordinator.lock().await;
    let our_index = coord.signer_index;

    for sp in &req.signer_partial_sigs {
        // Skip our own partial sigs
        if sp.signer_index as usize == our_index {
            continue;
        }

        let partial_sigs: Result<Vec<PartialSignature>, String> = sp
            .partial_sigs
            .iter()
            .map(|hex| {
                let bytes = hex_decode(hex)?;
                PartialSignature::from_slice(&bytes).map_err(|e| e.to_string())
            })
            .collect();

        let partial_sigs = match partial_sigs {
            Ok(s) => s,
            Err(e) => {
                return Json(SubmitPartialSigsResp {
                    accepted: false,
                    reject_reason: e,
                })
            }
        };

        if let Err(e) =
            coord.receive_partial_sigs(&session_id, sp.signer_index as usize, partial_sigs)
        {
            return Json(SubmitPartialSigsResp {
                accepted: false,
                reject_reason: e.to_string(),
            });
        }
    }

    Json(SubmitPartialSigsResp {
        accepted: true,
        reject_reason: String::new(),
    })
}

// --- Refresh signing handler ---

async fn propose_refresh(
    State(state): State<PeerState>,
    Json(req): Json<ProposeRefreshReq>,
) -> Json<ProposeRefreshResp> {
    let session_id = match parse_session_id(&req.session_id) {
        Ok(id) => id,
        Err(e) => {
            return Json(ProposeRefreshResp {
                accepted: false,
                reject_reason: e,
                pub_nonces: vec![],
            })
        }
    };

    // Parse deposits
    let deposits: Result<Vec<layer_tree_core::transactions::DepositInput>, String> = req
        .deposits
        .iter()
        .map(|d| {
            let outpoint = parse_outpoint(&d.outpoint)?;
            let script_bytes = hex_decode(&d.script_pubkey)?;
            Ok(layer_tree_core::transactions::DepositInput {
                outpoint,
                amount: bitcoin::Amount::from_sat(d.amount_sats),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script_bytes),
            })
        })
        .collect();
    let deposits = match deposits {
        Ok(d) => d,
        Err(e) => {
            return Json(ProposeRefreshResp {
                accepted: false,
                reject_reason: e,
                pub_nonces: vec![],
            })
        }
    };

    // Parse withdrawals
    let withdrawals: Result<Vec<layer_tree_core::transactions::WithdrawalOutput>, String> = req
        .withdrawals
        .iter()
        .map(|w| {
            let script_bytes = hex_decode(&w.script_pubkey)?;
            Ok(layer_tree_core::transactions::WithdrawalOutput {
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script_bytes),
                amount: bitcoin::Amount::from_sat(w.amount_sats),
            })
        })
        .collect();
    let withdrawals = match withdrawals {
        Ok(w) => w,
        Err(e) => {
            return Json(ProposeRefreshResp {
                accepted: false,
                reject_reason: e,
                pub_nonces: vec![],
            })
        }
    };

    let refresh_fee = bitcoin::Amount::from_sat(req.refresh_fee_sats);

    let mut coord = state.coordinator.lock().await;
    match coord.propose_refresh(session_id, deposits, withdrawals, refresh_fee) {
        Ok(nonces) => {
            let pub_nonces = nonces
                .iter()
                .map(|n| hex_encode(&n.to_bytes()))
                .collect();
            Json(ProposeRefreshResp {
                accepted: true,
                reject_reason: String::new(),
                pub_nonces,
            })
        }
        Err(e) => Json(ProposeRefreshResp {
            accepted: false,
            reject_reason: e.to_string(),
            pub_nonces: vec![],
        }),
    }
}

fn parse_outpoint(s: &str) -> Result<bitcoin::OutPoint, String> {
    let (txid_hex, vout_str) = s
        .rsplit_once(':')
        .ok_or_else(|| "expected txid:vout format".to_string())?;
    let vout: u32 = vout_str.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    let txid: bitcoin::Txid = txid_hex.parse().map_err(|e: bitcoin::hashes::hex::HexToArrayError| e.to_string())?;
    Ok(bitcoin::OutPoint::new(txid, vout))
}

// --- Block propagation handlers ---

async fn propose_block(
    State(state): State<PeerState>,
    Json(req): Json<ProposeBlockReq>,
) -> Json<ProposeBlockResp> {
    let mut chain = state.chain_state.lock().await;

    // Idempotent: if this block is strictly behind our chain tip, accept silently
    // (e.g., retransmitted block we already have). Height == ours with different
    // content will still fail in apply_block's prev_hash check.
    if req.block.header.height < chain.height {
        return Json(ProposeBlockResp {
            accepted: true,
            reject_reason: String::new(),
        });
    }

    // Validate and apply the block against our local chain state
    match chain.apply_block(&req.block) {
        Ok(new_state) => {
            // Persist the block to our local DB
            let db = state.db.lock().await;
            if let Err(e) = crate::db::insert_block(&db, &req.block) {
                return Json(ProposeBlockResp {
                    accepted: false,
                    reject_reason: format!("db error: {e}"),
                });
            }
            // Track any withdrawal operations for later L1 payout
            let _ = crate::db::record_withdrawals_from_block(&db, &req.block);
            // Update in-memory state
            *chain = new_state;
            Json(ProposeBlockResp {
                accepted: true,
                reject_reason: String::new(),
            })
        }
        Err(e) => Json(ProposeBlockResp {
            accepted: false,
            reject_reason: e.to_string(),
        }),
    }
}

async fn sync(
    State(state): State<PeerState>,
    Json(req): Json<SyncReq>,
) -> Json<SyncResp> {
    let db = state.db.lock().await;

    // Load our checkpoint
    let checkpoint = crate::db::load_checkpoint(&db).ok().flatten();

    // Determine which blocks to send
    let send_checkpoint = match &checkpoint {
        Some(cp) => req.my_height < cp.block_height,
        None => false,
    };

    let blocks_after = if let (true, Some(cp)) = (send_checkpoint, &checkpoint) {
        // Peer is behind our checkpoint — send checkpoint + all post-checkpoint blocks
        crate::db::get_blocks_since(&db, cp.block_height).unwrap_or_default()
    } else {
        // Peer has our checkpoint (or no checkpoint exists) — send blocks after their height
        crate::db::get_blocks_since(&db, req.my_height).unwrap_or_default()
    };

    Json(SyncResp {
        checkpoint: if send_checkpoint { checkpoint } else { None },
        blocks: blocks_after,
    })
}

// --- Helpers ---

fn parse_session_id(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(hex)?;
    bytes
        .try_into()
        .map_err(|_| "session_id must be 32 bytes".to_string())
}

fn parse_allocations(allocs: &[AllocationMsg]) -> Result<Vec<UserAllocation>, String> {
    allocs
        .iter()
        .map(|a| {
            let bytes = hex_decode(&a.pubkey)?;
            let pubkey_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "pubkey must be 32 bytes".to_string())?;
            let pubkey = bitcoin::XOnlyPublicKey::from_slice(&pubkey_bytes)
                .map_err(|e| format!("invalid pubkey: {e}"))?;
            Ok(UserAllocation {
                pubkey,
                amount: bitcoin::Amount::from_sat(a.amount_sats),
            })
        })
        .collect()
}

fn reject(reason: impl Into<String>) -> ProposeStateResp {
    ProposeStateResp {
        accepted: false,
        reject_reason: reason.into(),
        pub_nonces: vec![],
    }
}

// --- Client ---

/// HTTP client for communicating with peer operators.
pub struct PeerClient {
    base_url: String,
    client: reqwest::Client,
}

impl PeerClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn handshake(&self, req: &HandshakeReq) -> Result<HandshakeResp, String> {
        self.post("/peer/handshake", req).await
    }

    pub async fn propose_state(&self, req: &ProposeStateReq) -> Result<ProposeStateResp, String> {
        self.post("/peer/propose_state", req).await
    }

    pub async fn submit_nonces(&self, req: &SubmitNoncesReq) -> Result<SubmitNoncesResp, String> {
        self.post("/peer/submit_nonces", req).await
    }

    pub async fn submit_partial_sigs(
        &self,
        req: &SubmitPartialSigsReq,
    ) -> Result<SubmitPartialSigsResp, String> {
        self.post("/peer/submit_partial_sigs", req).await
    }

    pub async fn propose_refresh(
        &self,
        req: &ProposeRefreshReq,
    ) -> Result<ProposeRefreshResp, String> {
        self.post("/peer/propose_refresh", req).await
    }

    pub async fn propose_block(&self, block: &Block) -> Result<ProposeBlockResp, String> {
        self.post("/peer/propose_block", &ProposeBlockReq { block: block.clone() })
            .await
    }

    pub async fn sync(&self, my_height: u64, my_tip_hash: [u8; 32]) -> Result<SyncResp, String> {
        self.post(
            "/peer/sync",
            &SyncReq {
                my_height,
                my_tip_hash: hex_encode(&my_tip_hash),
            },
        )
        .await
    }

    async fn post<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        req: &Req,
    ) -> Result<Resp, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        resp.json().await.map_err(|e| format!("parse failed: {e}"))
    }
}
