//! Simple operator blockchain for multi-operator state sync.
//!
//! Blocks contain signed user operations (transfers, deposit confirmations,
//! withdrawal requests). Balances are deterministic from replaying the chain.
//! Signed exit tree states serve as checkpoints — old blocks are pruned.

use std::collections::BTreeMap;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf};
use serde::{Deserialize, Serialize};

use crate::tree::UserAllocation;

// ─── Signature Wrapper (serde for [u8; 64]) ────────────────────────────────

/// A 64-byte Schnorr signature with serde support.
#[derive(Clone, Copy, Debug)]
pub struct Sig(pub [u8; 64]);

impl Serialize for Sig {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Sig(arr))
    }
}

// ─── Block Types ───────────────────────────────────────────────────────────

/// A block in the operator chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub operations: Vec<Operation>,
}

/// Block header — hashed to produce the block's identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub operations_hash: [u8; 32],
    pub state_hash: [u8; 32],
}

/// User operations that modify balance state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operation {
    Transfer {
        from: XOnlyPublicKey,
        to: XOnlyPublicKey,
        amount: u64,
        nonce: u64,
        signature: Sig,
    },
    DepositConfirm {
        pubkey: XOnlyPublicKey,
        amount: u64,
        outpoint: OutPoint,
    },
    WithdrawalRequest {
        pubkey: XOnlyPublicKey,
        amount: u64,
        dest_script: ScriptBuf,
        nonce: u64,
        signature: Sig,
    },
}

/// A signed checkpoint: the exit tree state at a specific block height.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub balances: BTreeMap<XOnlyPublicKey, u64>,
}

// ─── Chain State ───────────────────────────────────────────────────────────

/// In-memory balance state derived from the chain.
#[derive(Clone, Debug)]
pub struct ChainState {
    pub tip_hash: [u8; 32],
    pub height: u64,
    pub balances: BTreeMap<XOnlyPublicKey, u64>,
    pub nonces: BTreeMap<XOnlyPublicKey, u64>,
}

/// Errors when validating a block or operation.
#[derive(Clone, Debug, PartialEq)]
pub enum ValidationError {
    BadPrevHash,
    BadHeight,
    BadOpsHash,
    BadStateHash,
    InsufficientBalance { pubkey: XOnlyPublicKey, have: u64, need: u64 },
    InvalidSignature(String),
    InvalidNonce { pubkey: XOnlyPublicKey, have: u64, got: u64 },
    DuplicateDeposit(OutPoint),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPrevHash => write!(f, "prev_hash does not match chain tip"),
            Self::BadHeight => write!(f, "height is not sequential"),
            Self::BadOpsHash => write!(f, "operations_hash mismatch"),
            Self::BadStateHash => write!(f, "state_hash mismatch"),
            Self::InsufficientBalance { pubkey, have, need } => {
                write!(f, "insufficient balance for {pubkey}: have {have}, need {need}")
            }
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {msg}"),
            Self::InvalidNonce { pubkey, have, got } => {
                write!(f, "invalid nonce for {pubkey}: expected > {have}, got {got}")
            }
            Self::DuplicateDeposit(op) => write!(f, "duplicate deposit: {op}"),
        }
    }
}

impl ChainState {
    /// Create an empty genesis state.
    pub fn genesis() -> Self {
        Self {
            tip_hash: [0u8; 32],
            height: 0,
            balances: BTreeMap::new(),
            nonces: BTreeMap::new(),
        }
    }

    /// Restore state from a signed checkpoint.
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        Self {
            tip_hash: checkpoint.block_hash,
            height: checkpoint.block_height,
            balances: checkpoint.balances.clone(),
            nonces: BTreeMap::new(), // nonces not tracked across checkpoints
        }
    }

    /// Validate and apply a block, returning the new state.
    /// Does NOT mutate self — returns a new ChainState or error.
    pub fn apply_block(&self, block: &Block) -> Result<ChainState, ValidationError> {
        // Validate header linkage
        if block.header.prev_hash != self.tip_hash {
            return Err(ValidationError::BadPrevHash);
        }
        if block.header.height != self.height + 1 {
            return Err(ValidationError::BadHeight);
        }

        // Validate operations hash
        let ops_hash = hash_operations(&block.operations);
        if block.header.operations_hash != ops_hash {
            return Err(ValidationError::BadOpsHash);
        }

        // Apply operations to produce new state
        let mut new_state = self.clone();
        let secp = Secp256k1::verification_only();

        for op in &block.operations {
            new_state.apply_operation(op, &secp)?;
        }

        // Update tip
        new_state.tip_hash = block_hash(&block.header);
        new_state.height = block.header.height;

        // Validate state hash
        if block.header.state_hash != new_state.state_hash() {
            return Err(ValidationError::BadStateHash);
        }

        Ok(new_state)
    }

    /// Apply a single operation (mutates self).
    fn apply_operation(
        &mut self,
        op: &Operation,
        secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    ) -> Result<(), ValidationError> {
        match op {
            Operation::Transfer { from, to, amount, nonce, signature } => {
                // Check nonce
                let last_nonce = self.nonces.get(from).copied().unwrap_or(0);
                if *nonce <= last_nonce {
                    return Err(ValidationError::InvalidNonce {
                        pubkey: *from,
                        have: last_nonce,
                        got: *nonce,
                    });
                }

                // Verify signature
                let msg = transfer_message(to, *amount, *nonce);
                let sig = schnorr::Signature::from_slice(&signature.0)
                    .map_err(|e| ValidationError::InvalidSignature(e.to_string()))?;
                secp.verify_schnorr(&sig, &msg, from)
                    .map_err(|e| ValidationError::InvalidSignature(e.to_string()))?;

                // Check balance
                let from_balance = self.balances.get(from).copied().unwrap_or(0);
                if from_balance < *amount {
                    return Err(ValidationError::InsufficientBalance {
                        pubkey: *from,
                        have: from_balance,
                        need: *amount,
                    });
                }

                // Execute
                *self.balances.entry(*from).or_insert(0) -= amount;
                *self.balances.entry(*to).or_insert(0) += amount;
                self.nonces.insert(*from, *nonce);

                // Remove zero-balance entries
                if self.balances.get(from) == Some(&0) {
                    self.balances.remove(from);
                }
            }

            Operation::DepositConfirm { pubkey, amount, outpoint: _ } => {
                // Deposits are confirmed by the leader's chain monitor.
                // Followers trust the leader for L1 confirmation (same trust model as signing).
                *self.balances.entry(*pubkey).or_insert(0) += amount;
            }

            Operation::WithdrawalRequest { pubkey, amount, dest_script: _, nonce, signature } => {
                // Check nonce
                let last_nonce = self.nonces.get(pubkey).copied().unwrap_or(0);
                if *nonce <= last_nonce {
                    return Err(ValidationError::InvalidNonce {
                        pubkey: *pubkey,
                        have: last_nonce,
                        got: *nonce,
                    });
                }

                // Verify signature
                let msg = withdrawal_message(pubkey, *amount, *nonce);
                let sig = schnorr::Signature::from_slice(&signature.0)
                    .map_err(|e| ValidationError::InvalidSignature(e.to_string()))?;
                secp.verify_schnorr(&sig, &msg, pubkey)
                    .map_err(|e| ValidationError::InvalidSignature(e.to_string()))?;

                // Check balance
                let balance = self.balances.get(pubkey).copied().unwrap_or(0);
                if balance < *amount {
                    return Err(ValidationError::InsufficientBalance {
                        pubkey: *pubkey,
                        have: balance,
                        need: *amount,
                    });
                }

                // Debit
                *self.balances.entry(*pubkey).or_insert(0) -= amount;
                self.nonces.insert(*pubkey, *nonce);

                if self.balances.get(pubkey) == Some(&0) {
                    self.balances.remove(pubkey);
                }
            }
        }

        Ok(())
    }

    /// Derive user allocations for exit tree signing.
    pub fn allocations(&self) -> Vec<UserAllocation> {
        self.balances
            .iter()
            .map(|(pubkey, amount)| UserAllocation {
                pubkey: *pubkey,
                amount: Amount::from_sat(*amount),
            })
            .collect()
    }

    /// Compute deterministic state hash (SHA256 of sorted balances).
    pub fn state_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        for (pubkey, amount) in &self.balances {
            data.extend_from_slice(&pubkey.serialize());
            data.extend_from_slice(&amount.to_le_bytes());
        }
        *sha256::Hash::hash(&data).as_ref()
    }

    /// Create a checkpoint from the current state.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            block_hash: self.tip_hash,
            block_height: self.height,
            balances: self.balances.clone(),
        }
    }
}

// ─── Block Construction ────────────────────────────────────────────────────

/// Build a valid block from operations and the current state.
/// Validates all operations and computes header hashes.
pub fn build_block(
    state: &ChainState,
    operations: Vec<Operation>,
) -> Result<(Block, ChainState), ValidationError> {
    let ops_hash = hash_operations(&operations);

    // Apply operations to get new state
    let mut new_state = state.clone();
    let secp = Secp256k1::verification_only();
    for op in &operations {
        new_state.apply_operation(op, &secp)?;
    }

    let height = state.height + 1;
    new_state.height = height;

    let header = BlockHeader {
        height,
        prev_hash: state.tip_hash,
        operations_hash: ops_hash,
        state_hash: new_state.state_hash(),
    };

    new_state.tip_hash = block_hash(&header);

    let block = Block { header, operations };
    Ok((block, new_state))
}

// ─── Message Formats (for signature verification) ──────────────────────────

/// Transfer message: SHA256(to_pubkey_bytes || amount_le8 || nonce_le8)
pub fn transfer_message(to: &XOnlyPublicKey, amount: u64, nonce: u64) -> Message {
    let hash = sha256::Hash::hash(
        &[
            &to.serialize()[..],
            &amount.to_le_bytes(),
            &nonce.to_le_bytes(),
        ]
        .concat(),
    );
    Message::from_digest(*hash.as_ref())
}

/// Withdrawal message: SHA256(pubkey_bytes || amount_le8 || nonce_le8)
/// The pubkey is included so withdrawals are bound to the requester.
pub fn withdrawal_message(pubkey: &XOnlyPublicKey, amount: u64, nonce: u64) -> Message {
    let hash = sha256::Hash::hash(
        &[
            &pubkey.serialize()[..],
            &amount.to_le_bytes(),
            &nonce.to_le_bytes(),
        ]
        .concat(),
    );
    Message::from_digest(*hash.as_ref())
}

// ─── Hashing Helpers ───────────────────────────────────────────────────────

/// Hash a block header to get the block's identity.
pub fn block_hash(header: &BlockHeader) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&header.height.to_le_bytes());
    data.extend_from_slice(&header.prev_hash);
    data.extend_from_slice(&header.operations_hash);
    data.extend_from_slice(&header.state_hash);
    *sha256::Hash::hash(&data).as_ref()
}

/// Hash the operations list for inclusion in the block header.
fn hash_operations(ops: &[Operation]) -> [u8; 32] {
    let mut data = Vec::new();
    for op in ops {
        hash_operation_into(op, &mut data);
    }
    *sha256::Hash::hash(&data).as_ref()
}

/// Deterministic serialization of a single operation for hashing.
fn hash_operation_into(op: &Operation, buf: &mut Vec<u8>) {
    match op {
        Operation::Transfer { from, to, amount, nonce, signature } => {
            buf.push(0x01); // tag
            buf.extend_from_slice(&from.serialize());
            buf.extend_from_slice(&to.serialize());
            buf.extend_from_slice(&amount.to_le_bytes());
            buf.extend_from_slice(&nonce.to_le_bytes());
            buf.extend_from_slice(&signature.0);
        }
        Operation::DepositConfirm { pubkey, amount, outpoint } => {
            buf.push(0x02); // tag
            buf.extend_from_slice(&pubkey.serialize());
            buf.extend_from_slice(&amount.to_le_bytes());
            buf.extend_from_slice(outpoint.txid.as_ref());
            buf.extend_from_slice(&outpoint.vout.to_le_bytes());
        }
        Operation::WithdrawalRequest { pubkey, amount, dest_script, nonce, signature } => {
            buf.push(0x03); // tag
            buf.extend_from_slice(&pubkey.serialize());
            buf.extend_from_slice(&amount.to_le_bytes());
            let script_bytes = dest_script.as_bytes();
            buf.extend_from_slice(&(script_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(script_bytes);
            buf.extend_from_slice(&nonce.to_le_bytes());
            buf.extend_from_slice(&signature.0);
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::Txid;

    fn test_keypair(secret_byte: u8) -> (Keypair, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = secret_byte;
        let keypair = Keypair::from_seckey_slice(&secp, &bytes).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        (keypair, xonly)
    }

    fn sign_transfer(keypair: &Keypair, to: &XOnlyPublicKey, amount: u64, nonce: u64) -> Sig {
        let secp = Secp256k1::new();
        let msg = transfer_message(to, amount, nonce);
        let sig = secp.sign_schnorr(&msg, keypair);
        Sig(sig.serialize())
    }

    fn sign_withdrawal(keypair: &Keypair, pubkey: &XOnlyPublicKey, amount: u64, nonce: u64) -> Sig {
        let secp = Secp256k1::new();
        let msg = withdrawal_message(pubkey, amount, nonce);
        let sig = secp.sign_schnorr(&msg, keypair);
        Sig(sig.serialize())
    }

    #[test]
    fn test_genesis_state() {
        let state = ChainState::genesis();
        assert_eq!(state.height, 0);
        assert!(state.balances.is_empty());
        assert!(state.allocations().is_empty());
    }

    #[test]
    fn test_deposit_and_transfer() {
        let (alice_kp, alice) = test_keypair(1);
        let (_, bob) = test_keypair(2);

        let state = ChainState::genesis();

        // Block 1: Deposit 100k sats to Alice
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 100_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xAA; 32]), 0),
        }];
        let (block1, state1) = build_block(&state, ops).unwrap();
        let state1_applied = state.apply_block(&block1).unwrap();
        assert_eq!(state1.state_hash(), state1_applied.state_hash());
        assert_eq!(state1.balances[&alice], 100_000);

        // Block 2: Alice transfers 30k to Bob
        let sig = sign_transfer(&alice_kp, &bob, 30_000, 1);
        let ops = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 30_000,
            nonce: 1,
            signature: sig,
        }];
        let (block2, state2) = build_block(&state1, ops).unwrap();
        let state2_applied = state1.apply_block(&block2).unwrap();
        assert_eq!(state2.state_hash(), state2_applied.state_hash());
        assert_eq!(state2.balances[&alice], 70_000);
        assert_eq!(state2.balances[&bob], 30_000);
    }

    #[test]
    fn test_insufficient_balance() {
        let (alice_kp, alice) = test_keypair(1);
        let (_, bob) = test_keypair(2);

        let state = ChainState::genesis();

        // Deposit 50k
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 50_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xBB; 32]), 0),
        }];
        let (_, state1) = build_block(&state, ops).unwrap();

        // Try to transfer 60k (more than balance)
        let sig = sign_transfer(&alice_kp, &bob, 60_000, 1);
        let ops = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 60_000,
            nonce: 1,
            signature: sig,
        }];
        let result = build_block(&state1, ops);
        assert!(matches!(result, Err(ValidationError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_invalid_signature() {
        let (_, alice) = test_keypair(1);
        let (_, bob) = test_keypair(2);

        let state = ChainState::genesis();

        // Deposit
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 100_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0),
        }];
        let (_, state1) = build_block(&state, ops).unwrap();

        // Transfer with garbage signature
        let ops = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 10_000,
            nonce: 1,
            signature: Sig([0xAB; 64]),
        }];
        let result = build_block(&state1, ops);
        assert!(matches!(result, Err(ValidationError::InvalidSignature(_))));
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let (alice_kp, alice) = test_keypair(1);
        let (_, bob) = test_keypair(2);

        let state = ChainState::genesis();

        // Deposit
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 100_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xDD; 32]), 0),
        }];
        let (_, state1) = build_block(&state, ops).unwrap();

        // Transfer with nonce=1
        let sig = sign_transfer(&alice_kp, &bob, 10_000, 1);
        let ops = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 10_000,
            nonce: 1,
            signature: sig,
        }];
        let (_, state2) = build_block(&state1, ops).unwrap();

        // Try same nonce again
        let sig2 = sign_transfer(&alice_kp, &bob, 10_000, 1);
        let ops = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 10_000,
            nonce: 1,
            signature: sig2,
        }];
        let result = build_block(&state2, ops);
        assert!(matches!(result, Err(ValidationError::InvalidNonce { .. })));
    }

    #[test]
    fn test_withdrawal() {
        let (alice_kp, alice) = test_keypair(1);

        let state = ChainState::genesis();

        // Deposit
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 100_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xEE; 32]), 0),
        }];
        let (_, state1) = build_block(&state, ops).unwrap();

        // Withdraw 40k
        let sig = sign_withdrawal(&alice_kp, &alice, 40_000, 1);
        let ops = vec![Operation::WithdrawalRequest {
            pubkey: alice,
            amount: 40_000,
            dest_script: ScriptBuf::from_bytes(vec![0x51, 0x20, 0xAA]),
            nonce: 1,
            signature: sig,
        }];
        let (_, state2) = build_block(&state1, ops).unwrap();
        assert_eq!(state2.balances[&alice], 60_000);
    }

    #[test]
    fn test_checkpoint_restore() {
        let (alice_kp, alice) = test_keypair(1);
        let (_, bob) = test_keypair(2);

        let state = ChainState::genesis();

        // Block 1: Deposit
        let ops = vec![Operation::DepositConfirm {
            pubkey: alice,
            amount: 100_000,
            outpoint: OutPoint::new(Txid::from_byte_array([0xFF; 32]), 0),
        }];
        let (_, state1) = build_block(&state, ops).unwrap();

        // Block 2: Transfer
        let sig = sign_transfer(&alice_kp, &bob, 25_000, 1);
        let ops = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 25_000,
            nonce: 1,
            signature: sig,
        }];
        let (_, state2) = build_block(&state1, ops).unwrap();

        // Save checkpoint at state2
        let checkpoint = state2.checkpoint();

        // Restore from checkpoint
        let restored = ChainState::from_checkpoint(&checkpoint);
        assert_eq!(restored.tip_hash, state2.tip_hash);
        assert_eq!(restored.height, state2.height);
        assert_eq!(restored.balances, state2.balances);
        assert_eq!(restored.state_hash(), state2.state_hash());
        assert_eq!(restored.allocations().len(), 2);
    }

    #[test]
    fn test_deterministic_state_hash() {
        // Two independent state machines applying the same blocks must produce
        // identical state hashes.
        let (alice_kp, alice) = test_keypair(1);
        let (_, bob) = test_keypair(2);

        let state_a = ChainState::genesis();
        let state_b = ChainState::genesis();

        let ops = vec![
            Operation::DepositConfirm {
                pubkey: alice,
                amount: 50_000,
                outpoint: OutPoint::new(Txid::from_byte_array([0x11; 32]), 0),
            },
            Operation::DepositConfirm {
                pubkey: bob,
                amount: 30_000,
                outpoint: OutPoint::new(Txid::from_byte_array([0x22; 32]), 1),
            },
        ];

        let (block1, new_a) = build_block(&state_a, ops.clone()).unwrap();
        let new_b = state_b.apply_block(&block1).unwrap();

        assert_eq!(new_a.state_hash(), new_b.state_hash());
        assert_eq!(new_a.tip_hash, new_b.tip_hash);

        // Another block
        let sig = sign_transfer(&alice_kp, &bob, 10_000, 1);
        let ops2 = vec![Operation::Transfer {
            from: alice,
            to: bob,
            amount: 10_000,
            nonce: 1,
            signature: sig,
        }];
        let (block2, final_a) = build_block(&new_a, ops2).unwrap();
        let final_b = new_b.apply_block(&block2).unwrap();

        assert_eq!(final_a.state_hash(), final_b.state_hash());
        assert_eq!(final_a.tip_hash, final_b.tip_hash);
        assert_eq!(final_a.balances[&alice], 40_000);
        assert_eq!(final_a.balances[&bob], 40_000);
    }

    #[test]
    fn test_bad_prev_hash_rejected() {
        let state = ChainState::genesis();

        // Build a valid block
        let ops = vec![Operation::DepositConfirm {
            pubkey: test_keypair(1).1,
            amount: 1000,
            outpoint: OutPoint::new(Txid::from_byte_array([0x33; 32]), 0),
        }];
        let (mut block, _) = build_block(&state, ops).unwrap();

        // Corrupt prev_hash
        block.header.prev_hash = [0xFF; 32];

        let result = state.apply_block(&block);
        assert!(matches!(result, Err(ValidationError::BadPrevHash)));
    }
}
