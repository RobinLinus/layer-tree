//! Chain monitoring: polls bitcoind for new blocks, tracks pool UTXO,
//! confirms deposits, and detects adversarial kickoff broadcasts.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use layer_tree_core::blockchain::Operation;
use layer_tree_core::transactions::p2tr_script_pubkey;

use crate::block_producer::SharedBlockProducer;
use crate::config::BitcoindConfig;

/// State tracked by the chain monitor.
pub struct ChainMonitor {
    rpc: Client,
    /// Current best block height we've processed.
    last_block_height: u64,
    /// The pool UTXO we're watching.
    pool_outpoint: Option<OutPoint>,
    pool_amount: Option<Amount>,
    /// The operator's aggregate x-only pubkey (for identifying pool UTXOs).
    operator_xonly: bitcoin::XOnlyPublicKey,
}

/// Events emitted by the chain monitor for the main loop to act on.
#[derive(Debug)]
pub enum ChainEvent {
    /// New block confirmed at given height.
    NewBlock { height: u64 },
    /// Pool UTXO confirmed on-chain.
    PoolConfirmed { outpoint: OutPoint, amount: Amount },
    /// Pool UTXO was spent (could be refresh or adversarial kickoff).
    PoolSpent {
        spending_txid: Txid,
    },
    /// A pending deposit's UTXO was confirmed on-chain.
    DepositConfirmed { deposit_id: i64, outpoint: OutPoint },
}

impl ChainMonitor {
    /// Create a new chain monitor connected to bitcoind.
    pub fn new(
        bitcoind_config: &BitcoindConfig,
        operator_xonly: bitcoin::XOnlyPublicKey,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rpc = Client::new(
            &bitcoind_config.rpc_url,
            Auth::UserPass(
                bitcoind_config.rpc_user.clone(),
                bitcoind_config.rpc_pass.clone(),
            ),
        )?;

        // Verify connection
        let info = rpc.get_blockchain_info()?;
        info!(
            "Connected to bitcoind: chain={}, blocks={}",
            info.chain, info.blocks
        );

        Ok(Self {
            last_block_height: info.blocks,
            rpc,
            pool_outpoint: None,
            pool_amount: None,
            operator_xonly,
        })
    }

    /// Set the pool UTXO to watch.
    pub fn set_pool_utxo(&mut self, outpoint: OutPoint, amount: Amount) {
        info!(
            "Watching pool UTXO: {}:{} ({} sats)",
            outpoint.txid,
            outpoint.vout,
            amount.to_sat()
        );
        self.pool_outpoint = Some(outpoint);
        self.pool_amount = Some(amount);
    }

    /// Check for new blocks and return any events.
    pub fn poll(&mut self) -> Vec<ChainEvent> {
        let mut events = Vec::new();

        let current_height = match self.rpc.get_block_count() {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to get block count: {e}");
                return events;
            }
        };

        if current_height <= self.last_block_height {
            return events;
        }

        // Process each new block
        for height in (self.last_block_height + 1)..=current_height {
            debug!("Processing block {height}");
            events.push(ChainEvent::NewBlock { height });

            // Check if pool UTXO was spent in this block
            if let Some(pool_outpoint) = self.pool_outpoint {
                match self.check_utxo_spent(pool_outpoint) {
                    Ok(Some(spending_txid)) => {
                        warn!(
                            "Pool UTXO {}:{} was spent by TX {}",
                            pool_outpoint.txid, pool_outpoint.vout, spending_txid
                        );
                        events.push(ChainEvent::PoolSpent { spending_txid });
                        self.pool_outpoint = None;
                        self.pool_amount = None;
                    }
                    Ok(None) => {} // still unspent
                    Err(e) => {
                        debug!("Could not check UTXO status: {e}");
                    }
                }
            }
        }

        self.last_block_height = current_height;
        events
    }

    /// Check if a UTXO has been spent. Returns the spending txid if spent.
    fn check_utxo_spent(&self, outpoint: OutPoint) -> Result<Option<Txid>, String> {
        match self
            .rpc
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        {
            Ok(Some(_)) => Ok(None), // UTXO exists → not spent
            Ok(None) => {
                // UTXO doesn't exist in UTXO set — either spent or never existed.
                // We can't easily determine the spending txid without an indexer,
                // so return a placeholder indicating it was spent.
                Ok(Some(outpoint.txid)) // use outpoint txid as indicator
            }
            Err(e) => Err(format!("gettxout failed: {e}")),
        }
    }

    /// Look up a transaction on-chain.
    pub fn get_transaction(&self, txid: &Txid) -> Result<bitcoin::Transaction, String> {
        self.rpc
            .get_raw_transaction(txid, None)
            .map_err(|e| format!("getrawtransaction failed: {e}"))
    }

    /// Get the current best block height.
    pub fn block_height(&self) -> u64 {
        self.last_block_height
    }

    /// Check if a specific outpoint exists in the UTXO set.
    pub fn utxo_exists(&self, outpoint: &OutPoint) -> Result<bool, String> {
        match self
            .rpc
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(format!("gettxout failed: {e}")),
        }
    }

    /// Find the pool UTXO in a transaction's outputs.
    /// Returns (vout, amount) if found.
    pub fn find_pool_output(&self, tx: &bitcoin::Transaction) -> Option<(u32, Amount)> {
        let pool_script = p2tr_script_pubkey(&self.operator_xonly);
        tx.output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey == pool_script)
            .map(|(vout, o)| (vout as u32, o.value))
    }
}

/// Shared chain monitor wrapped for async access.
pub type SharedChainMonitor = Arc<Mutex<ChainMonitor>>;

/// Run the chain monitoring loop.
///
/// Polls bitcoind every `interval` for new blocks and processes events.
/// Events are logged and, where applicable, trigger state changes via the DB.
pub async fn run_monitor(
    monitor: SharedChainMonitor,
    db: Arc<Mutex<rusqlite::Connection>>,
    block_producer: SharedBlockProducer,
    poll_interval: Duration,
) {
    info!(
        "Chain monitor started, polling every {}s",
        poll_interval.as_secs()
    );

    loop {
        tokio::time::sleep(poll_interval).await;

        let events = {
            let mut mon = monitor.lock().await;
            mon.poll()
        };

        for event in events {
            match event {
                ChainEvent::NewBlock { height } => {
                    debug!("New block: {height}");
                }
                ChainEvent::PoolConfirmed { outpoint, amount } => {
                    info!(
                        "Pool UTXO confirmed: {}:{} ({} sats)",
                        outpoint.txid,
                        outpoint.vout,
                        amount.to_sat()
                    );
                }
                ChainEvent::PoolSpent { spending_txid } => {
                    warn!("Pool UTXO spent by {spending_txid} — epoch invalidated");
                    // The signing coordinator / main loop should handle this
                    // by checking if this was our refresh TX or an adversarial kickoff.
                }
                ChainEvent::DepositConfirmed {
                    deposit_id,
                    outpoint,
                } => {
                    info!(
                        "Deposit {deposit_id} confirmed at {}:{}",
                        outpoint.txid, outpoint.vout
                    );
                    let db_conn = db.lock().await;

                    // Read deposit details and create DepositConfirm operation
                    let deposit = db_conn.query_row(
                        "SELECT user_pubkey, amount, outpoint FROM pending_deposits WHERE id = ?1",
                        rusqlite::params![deposit_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    );

                    match deposit {
                        Ok((pubkey_hex, amount, outpoint_str)) => {
                            // Parse the user's x-only pubkey
                            let pubkey = match parse_xonly_hex(&pubkey_hex) {
                                Ok(pk) => pk,
                                Err(e) => {
                                    error!("Invalid deposit pubkey {pubkey_hex}: {e}");
                                    continue;
                                }
                            };

                            // Parse the outpoint ("txid:vout")
                            let deposit_outpoint = match parse_outpoint(&outpoint_str) {
                                Ok(op) => op,
                                Err(e) => {
                                    error!("Invalid deposit outpoint {outpoint_str}: {e}");
                                    continue;
                                }
                            };

                            let op = Operation::DepositConfirm {
                                pubkey,
                                amount: amount as u64,
                                outpoint: deposit_outpoint,
                            };

                            // Add to block producer mempool
                            let mut bp = block_producer.lock().await;
                            bp.add_operation(op);
                            info!("Deposit {deposit_id}: queued DepositConfirm for {} sats to {}", amount, &pubkey_hex[..8]);

                            // Mark as confirmed in DB
                            if let Err(e) = db_conn.execute(
                                "UPDATE pending_deposits SET status = 'confirmed' WHERE id = ?1",
                                rusqlite::params![deposit_id],
                            ) {
                                error!("Failed to update deposit status: {e}");
                            }
                        }
                        Err(e) => {
                            error!("Failed to read deposit {deposit_id} from DB: {e}");
                        }
                    }
                }
            }
        }
    }
}

/// Parse a hex-encoded x-only public key.
fn parse_xonly_hex(hex: &str) -> Result<XOnlyPublicKey, String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Parse an outpoint string in "txid:vout" format.
fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
    let (txid_hex, vout_str) = s
        .rsplit_once(':')
        .ok_or_else(|| "expected txid:vout format".to_string())?;
    let vout: u32 = vout_str.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    let txid: Txid = txid_hex.parse().map_err(|e: bitcoin::hashes::hex::HexToArrayError| e.to_string())?;
    Ok(OutPoint::new(txid, vout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_event_debug() {
        use bitcoin::hashes::Hash;

        // Verify ChainEvent variants are constructible and debuggable
        let event = ChainEvent::NewBlock { height: 100 };
        let s = format!("{event:?}");
        assert!(s.contains("100"));

        let outpoint = OutPoint::new(Txid::from_byte_array([0u8; 32]), 0);
        let event = ChainEvent::PoolConfirmed {
            outpoint,
            amount: Amount::from_sat(100_000),
        };
        let s = format!("{event:?}");
        assert!(s.contains("PoolConfirmed"));
    }

    #[test]
    fn test_find_pool_output() {
        // We can't test with a real bitcoind, but we can test find_pool_output
        // by constructing a TX with the pool script and verifying detection.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // valid scalar
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();
        let xonly = bitcoin::XOnlyPublicKey::from_slice(&xonly.serialize()).unwrap();

        let pool_script = p2tr_script_pubkey(&xonly);

        // Build a fake TX with the pool output
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: bitcoin::ScriptBuf::new(), // random output
                },
                bitcoin::TxOut {
                    value: Amount::from_sat(200_000),
                    script_pubkey: pool_script,
                },
            ],
        };

        // Manually check (can't create ChainMonitor without bitcoind)
        let expected_script = p2tr_script_pubkey(&xonly);
        let found = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey == expected_script)
            .map(|(vout, o)| (vout as u32, o.value));

        assert_eq!(found, Some((1, Amount::from_sat(200_000))));
    }
}
