use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use crate::transactions::p2tr_script_pubkey;
use crate::FANOUT;

/// A user's allocation in the exit tree.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserAllocation {
    pub pubkey: XOnlyPublicKey,
    pub amount: Amount,
}

/// The exit tree: a tree of pre-signed split transactions.
///
/// `levels[0]` contains 1 transaction (the root split),
/// `levels[1]` contains FANOUT transactions, etc.
/// Leaf outputs are individual user P2TR outputs.
pub struct ExitTree {
    /// Split transactions organized by level. levels[0] = root split.
    pub levels: Vec<Vec<Transaction>>,
    /// The total amount needed as input to the root split (including all fees).
    pub required_input_amount: Amount,
}

impl ExitTree {
    /// Build the exit tree for the given user allocations.
    ///
    /// `root_outpoint` is the outpoint that the root split tx will spend
    /// (i.e., the root TX's output at index 0).
    pub fn build(
        root_outpoint: OutPoint,
        allocations: &[UserAllocation],
        operator_xonly: &XOnlyPublicKey,
        split_fee: Amount,
    ) -> Self {
        let n = allocations.len();
        assert!(n > 0, "need at least one user");
        // Pad to next power of FANOUT
        let depth = compute_depth(n);
        let padded_n = FANOUT.pow(depth as u32);

        // Pad allocations with zero-amount entries if needed
        let mut padded_allocs = allocations.to_vec();
        if padded_allocs.len() < padded_n {
            // Use the operator key for padding (these outputs will have zero value
            // and can be pruned in a real implementation)
            let dummy = UserAllocation {
                pubkey: *operator_xonly,
                amount: Amount::ZERO,
            };
            padded_allocs.resize(padded_n, dummy);
        }

        // Pass 1: bottom-up amount computation.
        // amounts_by_level[depth] = leaf amounts, amounts_by_level[0] = root split input amount
        let mut amounts_by_level: Vec<Vec<Amount>> = vec![Vec::new(); depth + 1];

        // Leaf level
        amounts_by_level[depth] = padded_allocs.iter().map(|a| a.amount).collect();

        // Internal levels (bottom-up)
        for level in (0..depth).rev() {
            let child_amounts = &amounts_by_level[level + 1];
            let n_nodes = FANOUT.pow(level as u32);
            let mut node_amounts = Vec::with_capacity(n_nodes);
            for i in 0..n_nodes {
                let start = i * FANOUT;
                let end = start + FANOUT;
                let children_sum: Amount =
                    child_amounts[start..end].iter().copied().sum();
                // This node's input amount = sum of children + fee for this split tx
                node_amounts.push(children_sum + split_fee);
            }
            amounts_by_level[level] = node_amounts;
        }

        let required_input_amount = amounts_by_level[0][0];

        // Pass 2: top-down transaction construction.
        let mut levels: Vec<Vec<Transaction>> = Vec::with_capacity(depth);

        // Track outpoints for each level so children know their inputs
        let mut current_outpoints: Vec<OutPoint> = vec![root_outpoint];

        for level in 0..depth {
            let n_txs = FANOUT.pow(level as u32);
            let mut level_txs = Vec::with_capacity(n_txs);

            let mut next_outpoints = Vec::with_capacity(n_txs * FANOUT);
            let is_last_level = level == depth - 1;

            for tx_idx in 0..n_txs {
                let input_outpoint = current_outpoints[tx_idx];

                // Build outputs for this split tx
                let mut outputs = Vec::with_capacity(FANOUT);
                for child in 0..FANOUT {
                    let child_global_idx = tx_idx * FANOUT + child;

                    if is_last_level {
                        // Leaf outputs: P2TR with user's key
                        let alloc = &padded_allocs[child_global_idx];
                        outputs.push(TxOut {
                            value: alloc.amount,
                            script_pubkey: p2tr_script_pubkey(&alloc.pubkey),
                        });
                    } else {
                        // Internal outputs: P2TR with operator aggregate key
                        let child_amount = amounts_by_level[level + 1][child_global_idx];
                        outputs.push(TxOut {
                            value: child_amount,
                            script_pubkey: p2tr_script_pubkey(operator_xonly),
                        });
                    }
                }

                // Filter out zero-value outputs (padding)
                let outputs: Vec<TxOut> =
                    outputs.into_iter().filter(|o| o.value > Amount::ZERO).collect();

                let tx = Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: input_outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: Witness::new(),
                    }],
                    output: outputs,
                };

                // Compute outpoints for children of this tx
                // Note: after filtering, output indices may shift. For simplicity,
                // we track by iterating the unfiltered child indices.
                if !is_last_level {
                    let txid = tx.compute_txid();
                    // Map children to output indices (skipping zero-amount padding)
                    let mut vout = 0u32;
                    for child in 0..FANOUT {
                        let child_global_idx = tx_idx * FANOUT + child;
                        let child_amount = amounts_by_level[level + 1][child_global_idx];
                        if child_amount > Amount::ZERO {
                            next_outpoints.push(OutPoint::new(txid, vout));
                            vout += 1;
                        } else {
                            // Padding child - push a dummy outpoint (won't be used)
                            next_outpoints.push(OutPoint::null());
                        }
                    }
                }

                level_txs.push(tx);
            }

            levels.push(level_txs);
            current_outpoints = next_outpoints;
        }

        ExitTree {
            levels,
            required_input_amount,
        }
    }

    /// Get all transactions in the tree in level-order (for signing).
    pub fn all_transactions(&self) -> Vec<&Transaction> {
        self.levels.iter().flat_map(|level| level.iter()).collect()
    }

    /// Get the exit path for a specific user (by leaf index).
    /// Returns the split transactions from root to the leaf's parent, in order.
    pub fn exit_path(&self, leaf_index: usize) -> Vec<&Transaction> {
        let mut path = Vec::new();
        let mut idx = 0; // index within the current level

        for level in &self.levels {
            path.push(&level[idx]);
            // Next level: which child group does our leaf fall into?
            idx = idx * FANOUT + (leaf_index / FANOUT.pow((self.levels.len() - path.len()) as u32))
                % FANOUT;
        }

        // Actually, simpler: at each level, the tx index is leaf_index / FANOUT^(depth - level)
        let depth = self.levels.len();
        let mut path = Vec::with_capacity(depth);
        for (level, txs) in self.levels.iter().enumerate() {
            let tx_idx = leaf_index / FANOUT.pow((depth - 1 - level) as u32);
            path.push(&txs[tx_idx]);
        }
        path
    }

    /// Total number of split transactions in the tree.
    pub fn total_transactions(&self) -> usize {
        self.levels.iter().map(|l| l.len()).sum()
    }
}

/// Compute the depth of the tree for `n` users with the configured FANOUT.
fn compute_depth(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut depth = 0;
    let mut capacity = 1;
    while capacity < n {
        capacity *= FANOUT;
        depth += 1;
    }
    depth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_depth() {
        assert_eq!(compute_depth(1), 1);
        assert_eq!(compute_depth(4), 1);
        assert_eq!(compute_depth(5), 2);
        assert_eq!(compute_depth(16), 2);
        assert_eq!(compute_depth(17), 3);
        assert_eq!(compute_depth(64), 3);
    }

    #[test]
    fn test_exit_tree_structure() {
        use bitcoin::hashes::Hash;

        let operator_xonly = {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x01; 32]).unwrap();
            let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
            pk.x_only_public_key().0
        };

        // Create 4 users (depth = 1, single split tx)
        let allocations: Vec<UserAllocation> = (0..4)
            .map(|i| {
                let mut bytes = [0x01; 32];
                bytes[0] = (i + 2) as u8;
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
                UserAllocation {
                    pubkey: pk.x_only_public_key().0,
                    amount: Amount::from_sat(10_000),
                }
            })
            .collect();

        let root_outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
        let tree = ExitTree::build(
            root_outpoint,
            &allocations,
            &operator_xonly,
            Amount::from_sat(300),
        );

        // With 4 users and fanout 4, depth = 1 (single split tx)
        assert_eq!(tree.levels.len(), 1);
        assert_eq!(tree.levels[0].len(), 1);
        assert_eq!(tree.levels[0][0].output.len(), 4);
        assert_eq!(
            tree.required_input_amount,
            Amount::from_sat(4 * 10_000 + 300)
        );
    }
}
