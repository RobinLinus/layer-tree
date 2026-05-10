//! SQLite persistence for operator state.

use rusqlite::{Connection, params};

use layer_tree_core::blockchain::{Block, ChainState, Checkpoint};

/// Initialize the database schema (enables WAL mode for safe concurrent access).
pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS epochs (
            epoch_id        INTEGER PRIMARY KEY,
            pool_outpoint   TEXT NOT NULL,
            pool_amount     INTEGER NOT NULL,
            kickoff_tx_hex  TEXT
        );

        CREATE TABLE IF NOT EXISTS states (
            epoch_id        INTEGER NOT NULL,
            state_number    INTEGER NOT NULL,
            nsequence       INTEGER NOT NULL,
            allocations_json TEXT NOT NULL,
            signed_txs_json TEXT NOT NULL,
            PRIMARY KEY (epoch_id, state_number)
        );

        CREATE TABLE IF NOT EXISTS users (
            pubkey_hex      TEXT PRIMARY KEY,
            balance_sats    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS pending_deposits (
            id              INTEGER PRIMARY KEY,
            user_pubkey     TEXT NOT NULL,
            outpoint        TEXT NOT NULL,
            amount          INTEGER NOT NULL,
            script_pubkey   TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS pending_withdrawals (
            id              INTEGER PRIMARY KEY,
            user_pubkey     TEXT NOT NULL,
            amount          INTEGER NOT NULL,
            dest_script     TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS signing_sessions (
            session_id      TEXT PRIMARY KEY,
            status          TEXT NOT NULL,
            epoch_id        INTEGER NOT NULL,
            state_number    INTEGER NOT NULL
        );

        -- Operator blockchain: signed checkpoint (singleton)
        CREATE TABLE IF NOT EXISTS checkpoint (
            id              INTEGER PRIMARY KEY CHECK (id = 0),
            block_hash      BLOB NOT NULL,
            block_height    INTEGER NOT NULL,
            balances_json   TEXT NOT NULL
        );

        -- Operator blockchain: blocks since last checkpoint (pruned on signing)
        CREATE TABLE IF NOT EXISTS blocks (
            height          INTEGER PRIMARY KEY,
            block_json      TEXT NOT NULL
        );
        ",
    )?;
    Ok(())
}

/// Store a new epoch.
pub fn insert_epoch(
    conn: &Connection,
    epoch_id: i64,
    pool_outpoint: &str,
    pool_amount: i64,
    kickoff_tx_hex: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO epochs (epoch_id, pool_outpoint, pool_amount, kickoff_tx_hex)
         VALUES (?1, ?2, ?3, ?4)",
        params![epoch_id, pool_outpoint, pool_amount, kickoff_tx_hex],
    )?;
    Ok(())
}

/// Store a signed state.
pub fn insert_state(
    conn: &Connection,
    epoch_id: i64,
    state_number: i64,
    nsequence: i64,
    allocations_json: &str,
    signed_txs_json: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO states (epoch_id, state_number, nsequence, allocations_json, signed_txs_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![epoch_id, state_number, nsequence, allocations_json, signed_txs_json],
    )?;
    Ok(())
}

/// Get the latest epoch ID.
pub fn latest_epoch_id(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(epoch_id) FROM epochs",
        [],
        |row| row.get(0),
    )
}

/// Get the latest state number for an epoch.
pub fn latest_state_number(conn: &Connection, epoch_id: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(state_number) FROM states WHERE epoch_id = ?1",
        params![epoch_id],
        |row| row.get(0),
    )
}

/// Get or create a user's balance.
pub fn get_balance(conn: &Connection, pubkey_hex: &str) -> rusqlite::Result<i64> {
    match conn.query_row(
        "SELECT balance_sats FROM users WHERE pubkey_hex = ?1",
        params![pubkey_hex],
        |row| row.get(0),
    ) {
        Ok(balance) => Ok(balance),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(e) => Err(e),
    }
}

/// Set a user's balance.
pub fn set_balance(conn: &Connection, pubkey_hex: &str, balance: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO users (pubkey_hex, balance_sats) VALUES (?1, ?2)
         ON CONFLICT(pubkey_hex) DO UPDATE SET balance_sats = ?2",
        params![pubkey_hex, balance],
    )?;
    Ok(())
}

/// Execute a transfer atomically: debit sender, credit receiver.
/// Returns (new_from_balance, new_to_balance) on success.
pub fn execute_transfer(
    conn: &Connection,
    from: &str,
    to: &str,
    amount_sats: u64,
) -> Result<(i64, i64), String> {
    let tx = conn.unchecked_transaction().map_err(|e| format!("begin tx: {e}"))?;

    let from_balance = get_balance(&tx, from).map_err(|e| format!("read from balance: {e}"))?;
    if from_balance < amount_sats as i64 {
        return Err("insufficient balance".to_string());
    }

    let new_from = from_balance - amount_sats as i64;
    let to_balance = get_balance(&tx, to).map_err(|e| format!("read to balance: {e}"))?;
    let new_to = to_balance + amount_sats as i64;

    set_balance(&tx, from, new_from).map_err(|e| format!("set from balance: {e}"))?;
    set_balance(&tx, to, new_to).map_err(|e| format!("set to balance: {e}"))?;

    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok((new_from, new_to))
}

/// Execute a withdrawal atomically: debit balance and queue withdrawal record.
/// Returns new balance on success.
pub fn execute_withdrawal(
    conn: &Connection,
    pubkey: &str,
    amount_sats: u64,
    dest_script: &str,
) -> Result<i64, String> {
    let tx = conn.unchecked_transaction().map_err(|e| format!("begin tx: {e}"))?;

    let balance = get_balance(&tx, pubkey).map_err(|e| format!("read balance: {e}"))?;
    if balance < amount_sats as i64 {
        return Err("insufficient balance".to_string());
    }

    let new_balance = balance - amount_sats as i64;
    set_balance(&tx, pubkey, new_balance).map_err(|e| format!("set balance: {e}"))?;

    tx.execute(
        "INSERT INTO pending_withdrawals (user_pubkey, amount, dest_script, status) VALUES (?1, ?2, ?3, 'pending')",
        params![pubkey, amount_sats as i64, dest_script],
    ).map_err(|e| format!("insert withdrawal: {e}"))?;

    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok(new_balance)
}

/// Record any WithdrawalRequest operations from a committed block into pending_withdrawals.
pub fn record_withdrawals_from_block(conn: &Connection, block: &Block) -> rusqlite::Result<()> {
    use layer_tree_core::blockchain::Operation;

    for op in &block.operations {
        if let Operation::WithdrawalRequest { pubkey, amount, dest_script, .. } = op {
            let pubkey_hex: String = pubkey.serialize().iter().map(|b| format!("{b:02x}")).collect();
            let dest_hex: String = dest_script.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            conn.execute(
                "INSERT INTO pending_withdrawals (user_pubkey, amount, dest_script, status) VALUES (?1, ?2, ?3, 'pending')",
                params![pubkey_hex, *amount as i64, dest_hex],
            )?;
        }
    }
    Ok(())
}

/// Get all pending withdrawals (status='pending').
pub fn get_pending_withdrawals(conn: &Connection) -> rusqlite::Result<Vec<(i64, String, i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_pubkey, amount, dest_script FROM pending_withdrawals WHERE status = 'pending'",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
        ))
    })?;
    rows.collect()
}

/// Mark withdrawals as included in a refresh TX.
pub fn mark_withdrawals_included(conn: &Connection, ids: &[i64]) -> rusqlite::Result<()> {
    for id in ids {
        conn.execute(
            "UPDATE pending_withdrawals SET status = 'included' WHERE id = ?1",
            params![id],
        )?;
    }
    Ok(())
}

// ─── Operator Blockchain Storage ───────────────────────────────────────────

/// Save a checkpoint and prune all blocks at or before that height.
pub fn save_checkpoint(conn: &Connection, checkpoint: &Checkpoint) -> rusqlite::Result<()> {
    let balances_json = serde_json::to_string(&checkpoint.balances)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO checkpoint (id, block_hash, block_height, balances_json)
         VALUES (0, ?1, ?2, ?3)",
        params![&checkpoint.block_hash[..], checkpoint.block_height as i64, balances_json],
    )?;
    // Prune old blocks
    tx.execute(
        "DELETE FROM blocks WHERE height <= ?1",
        params![checkpoint.block_height as i64],
    )?;
    tx.commit()?;
    Ok(())
}

/// Load the checkpoint (if any).
pub fn load_checkpoint(conn: &Connection) -> rusqlite::Result<Option<Checkpoint>> {
    let result = conn.query_row(
        "SELECT block_hash, block_height, balances_json FROM checkpoint WHERE id = 0",
        [],
        |row| {
            let hash_bytes: Vec<u8> = row.get(0)?;
            let height: i64 = row.get(1)?;
            let balances_json: String = row.get(2)?;
            Ok((hash_bytes, height, balances_json))
        },
    );

    match result {
        Ok((hash_bytes, height, balances_json)) => {
            let mut block_hash = [0u8; 32];
            if hash_bytes.len() == 32 {
                block_hash.copy_from_slice(&hash_bytes);
            }
            let balances = serde_json::from_str(&balances_json).unwrap_or_default();
            Ok(Some(Checkpoint {
                block_hash,
                block_height: height as u64,
                balances,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Store a committed block.
pub fn insert_block(conn: &Connection, block: &Block) -> rusqlite::Result<()> {
    let block_json = serde_json::to_string(block)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, block_json) VALUES (?1, ?2)",
        params![block.header.height as i64, block_json],
    )?;
    Ok(())
}

/// Get all blocks since a given height (exclusive).
pub fn get_blocks_since(conn: &Connection, after_height: u64) -> rusqlite::Result<Vec<Block>> {
    let mut stmt = conn.prepare(
        "SELECT block_json FROM blocks WHERE height > ?1 ORDER BY height ASC",
    )?;
    let rows = stmt.query_map(params![after_height as i64], |row| {
        let json: String = row.get(0)?;
        Ok(json)
    })?;

    let mut blocks = Vec::new();
    for row in rows {
        let json = row?;
        if let Ok(block) = serde_json::from_str::<Block>(&json) {
            blocks.push(block);
        }
    }
    Ok(blocks)
}

/// Rebuild ChainState from checkpoint + stored blocks.
pub fn rebuild_chain_state(conn: &Connection) -> Result<ChainState, String> {
    let state = match load_checkpoint(conn).map_err(|e| format!("load checkpoint: {e}"))? {
        Some(cp) => ChainState::from_checkpoint(&cp),
        None => ChainState::genesis(),
    };

    let blocks = get_blocks_since(conn, state.height)
        .map_err(|e| format!("get blocks: {e}"))?;

    let mut current = state;
    for block in &blocks {
        current = current
            .apply_block(block)
            .map_err(|e| format!("replay block {}: {e}", block.header.height))?;
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid, XOnlyPublicKey};
    use layer_tree_core::blockchain::{build_block, Operation};

    #[test]
    fn test_db_init_and_basic_ops() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        // Insert epoch
        insert_epoch(&conn, 0, "abc:0", 100_000, None).unwrap();
        assert_eq!(latest_epoch_id(&conn).unwrap(), Some(0));

        // Insert state
        insert_state(&conn, 0, 0, 20, "[]", "[]").unwrap();
        assert_eq!(latest_state_number(&conn, 0).unwrap(), Some(0));

        // User balance
        assert_eq!(get_balance(&conn, "deadbeef").unwrap(), 0);
        set_balance(&conn, "deadbeef", 50_000).unwrap();
        assert_eq!(get_balance(&conn, "deadbeef").unwrap(), 50_000);
    }

    fn test_xonly(byte: u8) -> XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = byte;
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();
        xonly
    }

    #[test]
    fn test_checkpoint_save_load_prune() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        let alice = test_xonly(1);
        let state = ChainState::genesis();

        // Build and store 3 blocks
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 100_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xAA; 32]), 0),
        }];
        let (block1, state1) = build_block(&state, ops).unwrap();
        insert_block(&conn, &block1).unwrap();

        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 50_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xBB; 32]), 0),
        }];
        let (block2, state2) = build_block(&state1, ops).unwrap();
        insert_block(&conn, &block2).unwrap();

        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 25_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0),
        }];
        let (block3, state3) = build_block(&state2, ops).unwrap();
        insert_block(&conn, &block3).unwrap();

        // Save checkpoint at block 2 — should prune blocks 1 and 2
        let cp = state2.checkpoint();
        save_checkpoint(&conn, &cp).unwrap();

        // Only block 3 should remain
        let remaining = get_blocks_since(&conn, 0).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].header.height, 3);

        // Rebuild state from checkpoint + remaining blocks
        let rebuilt = rebuild_chain_state(&conn).unwrap();
        assert_eq!(rebuilt.state_hash(), state3.state_hash());
        assert_eq!(rebuilt.balances[&alice], 175_000);
    }

    #[test]
    fn test_rebuild_from_empty() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        // No checkpoint, no blocks → genesis
        let state = rebuild_chain_state(&conn).unwrap();
        assert_eq!(state.height, 0);
        assert!(state.balances.is_empty());
    }
}
