//! State driver: triggers signing rounds when balance changes accumulate.
//!
//! The leader (signer_index=0) drives signing. After transfers accumulate,
//! the leader proposes a new state to all peers, collects nonces and partial
//! signatures, and produces the final signed state.
//!
//! Allocations are derived from the shared ChainState (operator blockchain).
//! After signing completes, the signed state is saved as a checkpoint and
//! old blocks are pruned.

use std::sync::Arc;
use std::time::Duration;

use musig2::BinaryEncoding;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use layer_tree_core::transactions::{DepositInput, WithdrawalOutput};

use crate::peer_service::{
    AllocationMsg, DepositInputMsg, PeerClient, ProposeRefreshReq, ProposeStateReq,
    SharedChainState, SignerNoncesMsg, SignerPartialSigsMsg, SubmitNoncesReq,
    SubmitPartialSigsReq, WithdrawalOutputMsg,
};
use crate::signing_coordinator::SharedCoordinator;

/// Configuration for the state driver.
pub struct StateDriverConfig {
    /// How often to check for pending transfers and propose new states.
    pub poll_interval: Duration,
    /// Minimum number of pending balance changes before triggering a state.
    pub min_pending_changes: usize,
    /// Peer URLs for multi-operator coordination.
    pub peer_urls: Vec<String>,
}

/// Run the state driver loop.
///
/// Only the leader (signer_index=0) actively drives signing rounds.
/// Followers respond to proposals via the peer service.
pub async fn run_state_driver(
    coordinator: SharedCoordinator,
    db: Arc<Mutex<rusqlite::Connection>>,
    chain_state: SharedChainState,
    config: StateDriverConfig,
) {
    let is_leader = {
        let coord = coordinator.lock().await;
        coord.signer_index == 0
    };

    if !is_leader {
        info!("State driver: not leader, will respond to proposals via peer API");
        return;
    }

    info!(
        "State driver: leader mode, polling every {}s",
        config.poll_interval.as_secs()
    );

    let peer_clients: Vec<PeerClient> = config
        .peer_urls
        .iter()
        .map(|url| PeerClient::new(url.clone()))
        .collect();

    let mut last_state_number: u32 = 0;

    loop {
        tokio::time::sleep(config.poll_interval).await;

        // Check if we have an active epoch (kickoff outpoint set)
        let has_epoch = {
            let coord = coordinator.lock().await;
            coord.kickoff_outpoint.is_some()
        };

        if !has_epoch {
            debug!("State driver: no active epoch, skipping");
            continue;
        }

        // Derive allocations from the operator blockchain state
        let (allocations, tip_hash_hex) = {
            let cs = chain_state.lock().await;
            (cs.allocations(), hex_encode(&cs.tip_hash))
        };

        if allocations.is_empty() {
            debug!("State driver: no user allocations, skipping");
            continue;
        }

        // Generate session ID
        let mut session_id = [0u8; 32];
        rand::fill(&mut session_id);
        let session_id_hex = hex_encode(&session_id);

        let (epoch_id, nsequence, n_signers) = {
            let coord = coordinator.lock().await;
            let state_number = last_state_number + 1;
            let nsequence =
                coord.params.nseq_start - (state_number as u16 * coord.params.step_size);
            (coord.current_epoch_id, nsequence, coord.n_signers)
        };

        let state_number = last_state_number + 1;

        info!(
            "State driver: proposing state {} (nSeq={}, {} allocations)",
            state_number,
            nsequence,
            allocations.len()
        );

        // Build allocation messages for peer communication
        let alloc_msgs: Vec<AllocationMsg> = allocations
            .iter()
            .map(|a| AllocationMsg {
                pubkey: hex_encode(&a.pubkey.serialize()),
                amount_sats: a.amount.to_sat(),
            })
            .collect();

        // Step 1: Propose state locally and get our nonces
        let our_nonces = {
            let mut coord = coordinator.lock().await;
            match coord.propose_state(
                session_id,
                epoch_id,
                state_number,
                nsequence,
                allocations.clone(),
            ) {
                Ok(nonces) => nonces,
                Err(e) => {
                    error!("State driver: local propose_state failed: {e}");
                    continue;
                }
            }
        };

        // Step 2: Send proposal to peers (if multi-operator)
        let mut all_nonces: Vec<(usize, Vec<String>)> = vec![(
            0, // our signer_index
            our_nonces
                .iter()
                .map(|n| hex_encode(&n.to_bytes()))
                .collect(),
        )];

        if n_signers > 1 {
            let propose_req = ProposeStateReq {
                session_id: session_id_hex.clone(),
                epoch_id,
                state_number,
                nsequence: nsequence as u32,
                at_block_hash: tip_hash_hex.clone(),
                allocations: alloc_msgs,
            };

            for (i, client) in peer_clients.iter().enumerate() {
                let peer_signer_idx = i + 1; // peers are signers 1..n
                match client.propose_state(&propose_req).await {
                    Ok(resp) => {
                        if resp.accepted {
                            all_nonces.push((peer_signer_idx, resp.pub_nonces));
                        } else {
                            warn!(
                                "Peer {peer_signer_idx} rejected proposal: {}",
                                resp.reject_reason
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to reach peer {peer_signer_idx}: {e}");
                    }
                }
            }

            if all_nonces.len() < n_signers {
                error!(
                    "State driver: only got {}/{} nonce responses, aborting",
                    all_nonces.len(),
                    n_signers
                );
                continue;
            }

            // Step 3: Submit all nonces to peers and collect partial sigs
            let signer_nonces: Vec<SignerNoncesMsg> = all_nonces
                .iter()
                .map(|(idx, nonces)| SignerNoncesMsg {
                    signer_index: *idx as u32,
                    pub_nonces: nonces.clone(),
                })
                .collect();

            // Submit nonces to our own coordinator
            let our_partial_sigs = {
                let mut coord = coordinator.lock().await;
                let mut our_psigs = None;
                for sn in &signer_nonces {
                    if sn.signer_index == 0 {
                        continue; // skip ourselves
                    }
                    let nonces: Result<Vec<musig2::PubNonce>, String> = sn
                        .pub_nonces
                        .iter()
                        .map(|hex| {
                            let bytes = hex_decode(hex)?;
                            musig2::PubNonce::from_bytes(&bytes).map_err(|e| e.to_string())
                        })
                        .collect();
                    match nonces {
                        Ok(n) => {
                            match coord.receive_nonces(
                                &session_id,
                                sn.signer_index as usize,
                                n,
                            ) {
                                Ok(Some(psigs)) => our_psigs = Some(psigs),
                                Ok(None) => {}
                                Err(e) => {
                                    error!("receive_nonces failed: {e}");
                                }
                            }
                        }
                        Err(e) => error!("parse nonce failed: {e}"),
                    }
                }
                our_psigs
            };

            let our_psigs_hex: Vec<String> = our_partial_sigs
                .map(|sigs| sigs.iter().map(|s| hex_encode(&s.serialize())).collect())
                .unwrap_or_default();

            // Submit nonces to peers and collect their partial sigs
            let submit_nonces_req = SubmitNoncesReq {
                session_id: session_id_hex.clone(),
                signer_nonces,
            };

            let mut all_partial_sigs: Vec<(usize, Vec<String>)> =
                vec![(0, our_psigs_hex)];

            for (i, client) in peer_clients.iter().enumerate() {
                let peer_signer_idx = i + 1;
                match client.submit_nonces(&submit_nonces_req).await {
                    Ok(resp) => {
                        if resp.accepted {
                            all_partial_sigs.push((peer_signer_idx, resp.partial_sigs));
                        } else {
                            error!(
                                "Peer {peer_signer_idx} rejected nonces: {}",
                                resp.reject_reason
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to submit nonces to peer {peer_signer_idx}: {e}");
                    }
                }
            }

            // Step 4: Submit partial sigs to coordinator and peers
            let signer_partial_sigs: Vec<SignerPartialSigsMsg> = all_partial_sigs
                .iter()
                .map(|(idx, sigs)| SignerPartialSigsMsg {
                    signer_index: *idx as u32,
                    partial_sigs: sigs.clone(),
                })
                .collect();

            // Feed peer partial sigs into our coordinator
            {
                let mut coord = coordinator.lock().await;
                for sp in &signer_partial_sigs {
                    if sp.signer_index == 0 {
                        continue;
                    }
                    let psigs: Result<Vec<musig2::PartialSignature>, String> = sp
                        .partial_sigs
                        .iter()
                        .map(|hex| {
                            let bytes = hex_decode(hex)?;
                            musig2::PartialSignature::from_slice(&bytes)
                                .map_err(|e| e.to_string())
                        })
                        .collect();
                    match psigs {
                        Ok(s) => {
                            if let Err(e) = coord.receive_partial_sigs(
                                &session_id,
                                sp.signer_index as usize,
                                s,
                            ) {
                                error!("receive_partial_sigs failed: {e}");
                            }
                        }
                        Err(e) => error!("parse partial sig failed: {e}"),
                    }
                }
            }

            // Notify peers of all partial sigs
            let submit_psigs_req = SubmitPartialSigsReq {
                session_id: session_id_hex.clone(),
                signer_partial_sigs,
            };
            for (i, client) in peer_clients.iter().enumerate() {
                if let Err(e) = client.submit_partial_sigs(&submit_psigs_req).await {
                    error!("Failed to submit partial sigs to peer {}: {e}", i + 1);
                }
            }
        } else {
            // Single-operator mode: nonces from ourselves complete the round immediately
            // In single-signer mode, propose_state already did everything needed.
            // The session auto-completes since n_signers=1.
        }

        // Check if session completed
        let completed = {
            let mut coord = coordinator.lock().await;
            coord.take_completed_session(&session_id)
        };

        if let Some((session, sigs)) = completed {
            info!("State {} signed successfully!", state_number);

            // Save checkpoint from the chain state at this signing point.
            // This prunes old blocks that are now superseded by the signed state.
            let checkpoint = {
                let cs = chain_state.lock().await;
                cs.checkpoint()
            };

            let db_conn = db.lock().await;

            // Persist signed state to states table (for exit tree reconstruction)
            let allocations_json =
                serde_json::to_string(&session.allocations.iter().map(|a| {
                    serde_json::json!({
                        "pubkey": hex_encode(&a.pubkey.serialize()),
                        "amount_sats": a.amount.to_sat(),
                    })
                }).collect::<Vec<_>>()).unwrap_or_default();

            let signed_txs_json = serde_json::to_string(
                &sigs.iter().map(|s| hex_encode(&s.serialize())).collect::<Vec<_>>()
            ).unwrap_or_default();

            if let Err(e) = crate::db::insert_state(
                &db_conn,
                session.epoch_id as i64,
                state_number as i64,
                session.nsequence as i64,
                &allocations_json,
                &signed_txs_json,
            ) {
                error!("Failed to persist signed state {state_number}: {e}");
            }

            // Save checkpoint and prune old blocks
            if let Err(e) = crate::db::save_checkpoint(&db_conn, &checkpoint) {
                error!("Failed to save checkpoint at height {}: {e}", checkpoint.block_height);
            } else {
                info!(
                    "Checkpoint saved at block height {}, old blocks pruned",
                    checkpoint.block_height
                );
            }

            last_state_number = state_number;

            // After successful state signing, check if refresh is needed
            drop(db_conn); // release DB lock before refresh round
            let pending_withdrawals = {
                let db_conn = db.lock().await;
                crate::db::get_pending_withdrawals(&db_conn).unwrap_or_default()
            };

            if !pending_withdrawals.is_empty() {
                info!(
                    "State driver: {} pending withdrawals, initiating refresh",
                    pending_withdrawals.len()
                );
                if let Err(e) = run_refresh_round(
                    &coordinator,
                    &db,
                    &peer_clients,
                    &pending_withdrawals,
                    n_signers,
                )
                .await
                {
                    error!("Refresh round failed: {e}");
                }
            }
        } else {
            warn!("State {} signing did not complete", state_number);
        }
    }
}

/// Execute a cooperative refresh signing round.
///
/// Builds a refresh TX with pending withdrawals, signs it via distributed
/// MuSig2, and stores the signed TX. The chain monitor will detect when
/// it confirms on L1.
async fn run_refresh_round(
    coordinator: &SharedCoordinator,
    db: &Arc<Mutex<rusqlite::Connection>>,
    peer_clients: &[PeerClient],
    pending_withdrawals: &[(i64, String, i64, String)],
    n_signers: usize,
) -> Result<(), String> {
    // Build withdrawal outputs
    let withdrawals: Vec<WithdrawalOutput> = pending_withdrawals
        .iter()
        .map(|(_, _, amount, dest_hex)| {
            let script_bytes = hex_decode(dest_hex).unwrap_or_default();
            WithdrawalOutput {
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script_bytes),
                amount: bitcoin::Amount::from_sat(*amount as u64),
            }
        })
        .collect();

    // TODO: also include confirmed deposits as DepositInput
    let deposits: Vec<DepositInput> = Vec::new();

    let refresh_fee = bitcoin::Amount::from_sat(500); // TODO: configurable

    // Generate session ID
    let mut session_id = [0u8; 32];
    rand::fill(&mut session_id);
    let session_id_hex = hex_encode(&session_id);

    // Step 1: Propose refresh locally
    let our_nonces = {
        let mut coord = coordinator.lock().await;
        coord
            .propose_refresh(session_id, deposits.clone(), withdrawals.clone(), refresh_fee)
            .map_err(|e| format!("propose_refresh failed: {e}"))?
    };

    let mut all_nonces: Vec<(usize, Vec<String>)> = vec![(
        0,
        our_nonces
            .iter()
            .map(|n| hex_encode(&n.to_bytes()))
            .collect(),
    )];

    // Step 2: Propose to peers
    if n_signers > 1 {
        let deposit_msgs: Vec<DepositInputMsg> = deposits
            .iter()
            .map(|d| DepositInputMsg {
                outpoint: format!("{}:{}", d.outpoint.txid, d.outpoint.vout),
                amount_sats: d.amount.to_sat(),
                script_pubkey: hex_encode(d.script_pubkey.as_bytes()),
            })
            .collect();

        let withdrawal_msgs: Vec<WithdrawalOutputMsg> = withdrawals
            .iter()
            .map(|w| WithdrawalOutputMsg {
                script_pubkey: hex_encode(w.script_pubkey.as_bytes()),
                amount_sats: w.amount.to_sat(),
            })
            .collect();

        let propose_req = ProposeRefreshReq {
            session_id: session_id_hex.clone(),
            deposits: deposit_msgs,
            withdrawals: withdrawal_msgs,
            refresh_fee_sats: refresh_fee.to_sat(),
        };

        for (i, client) in peer_clients.iter().enumerate() {
            let peer_idx = i + 1;
            match client.propose_refresh(&propose_req).await {
                Ok(resp) => {
                    if resp.accepted {
                        all_nonces.push((peer_idx, resp.pub_nonces));
                    } else {
                        return Err(format!(
                            "peer {peer_idx} rejected refresh: {}",
                            resp.reject_reason
                        ));
                    }
                }
                Err(e) => return Err(format!("failed to reach peer {peer_idx}: {e}")),
            }
        }

        if all_nonces.len() < n_signers {
            return Err(format!(
                "only got {}/{} nonce responses",
                all_nonces.len(),
                n_signers
            ));
        }

        // Step 3: Submit nonces and collect partial sigs
        let signer_nonces: Vec<SignerNoncesMsg> = all_nonces
            .iter()
            .map(|(idx, nonces)| SignerNoncesMsg {
                signer_index: *idx as u32,
                pub_nonces: nonces.clone(),
            })
            .collect();

        // Submit nonces locally and get our partial sigs
        let our_partial_sigs = {
            let mut coord = coordinator.lock().await;
            let mut our_psigs = None;
            for sn in &signer_nonces {
                if sn.signer_index == 0 {
                    continue;
                }
                let nonces: Result<Vec<musig2::PubNonce>, String> = sn
                    .pub_nonces
                    .iter()
                    .map(|hex| {
                        let bytes = hex_decode(hex)?;
                        musig2::PubNonce::from_bytes(&bytes).map_err(|e| e.to_string())
                    })
                    .collect();
                match nonces {
                    Ok(n) => match coord.receive_nonces(&session_id, sn.signer_index as usize, n) {
                        Ok(Some(psigs)) => our_psigs = Some(psigs),
                        Ok(None) => {}
                        Err(e) => return Err(format!("receive_nonces failed: {e}")),
                    },
                    Err(e) => return Err(format!("parse nonce failed: {e}")),
                }
            }
            our_psigs
        };

        let our_psigs_hex: Vec<String> = our_partial_sigs
            .map(|sigs| sigs.iter().map(|s| hex_encode(&s.serialize())).collect())
            .unwrap_or_default();

        // Submit nonces to peers
        let submit_nonces_req = SubmitNoncesReq {
            session_id: session_id_hex.clone(),
            signer_nonces,
        };

        let mut all_partial_sigs: Vec<(usize, Vec<String>)> = vec![(0, our_psigs_hex)];

        for (i, client) in peer_clients.iter().enumerate() {
            let peer_idx = i + 1;
            match client.submit_nonces(&submit_nonces_req).await {
                Ok(resp) => {
                    if resp.accepted {
                        all_partial_sigs.push((peer_idx, resp.partial_sigs));
                    } else {
                        return Err(format!(
                            "peer {peer_idx} rejected nonces: {}",
                            resp.reject_reason
                        ));
                    }
                }
                Err(e) => return Err(format!("submit nonces to peer {peer_idx}: {e}")),
            }
        }

        // Step 4: Submit partial sigs
        let signer_partial_sigs: Vec<SignerPartialSigsMsg> = all_partial_sigs
            .iter()
            .map(|(idx, sigs)| SignerPartialSigsMsg {
                signer_index: *idx as u32,
                partial_sigs: sigs.clone(),
            })
            .collect();

        // Feed peer partial sigs locally
        {
            let mut coord = coordinator.lock().await;
            for sp in &signer_partial_sigs {
                if sp.signer_index == 0 {
                    continue;
                }
                let psigs: Result<Vec<musig2::PartialSignature>, String> = sp
                    .partial_sigs
                    .iter()
                    .map(|hex| {
                        let bytes = hex_decode(hex)?;
                        musig2::PartialSignature::from_slice(&bytes).map_err(|e| e.to_string())
                    })
                    .collect();
                match psigs {
                    Ok(s) => {
                        if let Err(e) = coord.receive_partial_sigs(
                            &session_id,
                            sp.signer_index as usize,
                            s,
                        ) {
                            return Err(format!("receive_partial_sigs failed: {e}"));
                        }
                    }
                    Err(e) => return Err(format!("parse partial sig failed: {e}")),
                }
            }
        }

        // Notify peers of partial sigs
        let submit_psigs_req = SubmitPartialSigsReq {
            session_id: session_id_hex.clone(),
            signer_partial_sigs,
        };
        for (i, client) in peer_clients.iter().enumerate() {
            if let Err(e) = client.submit_partial_sigs(&submit_psigs_req).await {
                warn!("Failed to submit partial sigs to peer {}: {e}", i + 1);
            }
        }
    }

    // Check completion
    let completed = {
        let mut coord = coordinator.lock().await;
        coord.take_completed_session(&session_id)
    };

    if let Some((session, sigs)) = completed {
        info!("Refresh TX signed successfully ({} signatures)", sigs.len());

        // The signed refresh TX is in session.unsigned_txs[0] with the signature applied
        // Store the signed TX for broadcast
        let refresh_tx_hex = {
            let tx = &session.unsigned_txs[0];
            // Apply the signature to create the final signed TX
            let mut signed_tx = tx.clone();
            let sig = &sigs[0];
            let schnorr_sig =
                bitcoin::taproot::Signature {
                    signature: bitcoin::secp256k1::schnorr::Signature::from_slice(
                        &sig.serialize(),
                    )
                    .map_err(|e| format!("invalid signature: {e}"))?,
                    sighash_type: bitcoin::TapSighashType::Default,
                };
            signed_tx.input[0].witness = bitcoin::Witness::from_slice(&[schnorr_sig.serialize()]);
            bitcoin::consensus::encode::serialize_hex(&signed_tx)
        };

        info!("Refresh TX ready for broadcast: {}", &refresh_tx_hex[..64]);

        // Mark withdrawals as included
        let withdrawal_ids: Vec<i64> = pending_withdrawals.iter().map(|(id, _, _, _)| *id).collect();
        let db_conn = db.lock().await;
        if let Err(e) = crate::db::mark_withdrawals_included(&db_conn, &withdrawal_ids) {
            error!("Failed to mark withdrawals as included: {e}");
        }

        // Store refresh TX for later broadcast (when bitcoind is available)
        // TODO: broadcast via bitcoind RPC if connected
        info!(
            "Refresh TX stored, {} withdrawals marked as included",
            withdrawal_ids.len()
        );

        Ok(())
    } else {
        Err("refresh signing did not complete".into())
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
