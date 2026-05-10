use bitcoin::{Amount, OutPoint, Transaction, XOnlyPublicKey};
use musig2::KeyAggContext;
use musig2::secp::Scalar;

use bitcoin::TxOut;

use crate::signing::{compute_sighash_for_input, sign_input_musig2, sign_transactions, PrevoutInfo};
use crate::transactions::{
    build_kickoff_tx, build_refresh_tx, build_refresh_with_io, build_root_tx, p2tr_script_pubkey,
    DepositInput, WithdrawalOutput,
};
use crate::tree::{ExitTree, UserAllocation};
use crate::FANOUT;

/// A signed state: root TX + exit tree, all transactions signed.
pub struct StatePackage {
    pub state_number: u32,
    pub nsequence: u16,
    pub exit_tree: ExitTree,
    pub allocations: Vec<UserAllocation>,
    /// signed_txs[0] = root TX, signed_txs[1..] = split TXs in level order.
    pub signed_txs: Vec<Transaction>,
}

impl StatePackage {
    /// The signed root transaction.
    pub fn signed_root_tx(&self) -> &Transaction {
        &self.signed_txs[0]
    }

    /// The signed split transactions (level order).
    pub fn signed_split_txs(&self) -> &[Transaction] {
        &self.signed_txs[1..]
    }

    /// Get the signed exit path for a specific user (by leaf index).
    pub fn signed_exit_path(&self, leaf_index: usize) -> Vec<&Transaction> {
        let unsigned_path = self.exit_tree.exit_path(leaf_index);
        unsigned_path
            .iter()
            .map(|unsigned_tx| {
                let txid = unsigned_tx.compute_txid();
                self.signed_split_txs()
                    .iter()
                    .find(|t| t.compute_txid() == txid)
                    .expect("signed split tx not found for exit path")
            })
            .collect()
    }
}

/// Build unsigned state transactions deterministically.
///
/// All operators calling this with identical inputs produce identical transactions
/// and sighashes. This is the foundation of distributed signing: each operator
/// independently builds the same unsigned TXs, then they exchange only nonces
/// and partial signatures.
///
/// Returns `(exit_tree, transactions, prevouts, sighashes)` where:
/// - `transactions[0]` = root TX, `transactions[1..]` = split TXs (level order)
/// - `prevouts[i]` = prevout info for `transactions[i]`
/// - `sighashes[i]` = taproot keyspend sighash for `transactions[i]`
pub fn build_state_transactions(
    kickoff_outpoint: OutPoint,
    kickoff_output_amount: Amount,
    operator_xonly: &XOnlyPublicKey,
    allocations: &[UserAllocation],
    nsequence: u16,
    root_fee: Amount,
    split_fee: Amount,
) -> (ExitTree, Vec<Transaction>, Vec<PrevoutInfo>, Vec<[u8; 32]>) {
    let operator_script = p2tr_script_pubkey(operator_xonly);

    // Build unsigned root TX
    let root_tx = build_root_tx(
        kickoff_outpoint,
        kickoff_output_amount,
        operator_xonly,
        nsequence,
        root_fee,
    );
    let root_outpoint = OutPoint::new(root_tx.compute_txid(), 0);
    let root_output_amount = kickoff_output_amount - root_fee;

    // Build exit tree
    let exit_tree = ExitTree::build(root_outpoint, allocations, operator_xonly, split_fee);

    assert_eq!(
        exit_tree.required_input_amount, root_output_amount,
        "total allocations + split fees ({}) must equal root TX output ({})",
        exit_tree.required_input_amount, root_output_amount
    );

    // Collect all transactions and prevouts
    let mut txs = vec![root_tx];
    let mut prevouts = vec![PrevoutInfo {
        amount: kickoff_output_amount,
        script_pubkey: operator_script.clone(),
    }];

    for (level_idx, level) in exit_tree.levels.iter().enumerate() {
        for (tx_idx, tx) in level.iter().enumerate() {
            let prevout_amount = if level_idx == 0 {
                root_output_amount
            } else {
                let parent_tx_idx = tx_idx / FANOUT;
                let parent_tx = &exit_tree.levels[level_idx - 1][parent_tx_idx];
                let spent_outpoint = tx.input[0].previous_output;
                parent_tx
                    .output
                    .iter()
                    .enumerate()
                    .find(|(vout, _)| {
                        OutPoint::new(parent_tx.compute_txid(), *vout as u32) == spent_outpoint
                    })
                    .map(|(_, o)| o.value)
                    .expect("split tx input should match parent output")
            };

            txs.push(tx.clone());
            prevouts.push(PrevoutInfo {
                amount: prevout_amount,
                script_pubkey: operator_script.clone(),
            });
        }
    }

    // Compute sighashes
    let sighashes: Vec<[u8; 32]> = txs
        .iter()
        .zip(prevouts.iter())
        .map(|(tx, prevout)| {
            compute_sighash_for_input(
                tx,
                0,
                &[TxOut {
                    value: prevout.amount,
                    script_pubkey: prevout.script_pubkey.clone(),
                }],
            )
        })
        .collect();

    (exit_tree, txs, prevouts, sighashes)
}

/// An epoch: one kickoff TX shared by multiple states.
///
/// All states compete for the same kickoff output. The latest state
/// (lowest nSequence) matures first and wins the race.
pub struct Epoch {
    /// The kickoff transaction (unsigned until `sign_kickoff` is called).
    pub kickoff_tx: Transaction,
    /// States in order of creation. Latest state has lowest nSequence.
    pub states: Vec<StatePackage>,
    pub pool_outpoint: OutPoint,
    pub pool_amount: Amount,
    pub operator_xonly: XOnlyPublicKey,
}

impl Epoch {
    /// Create a new epoch. Builds an unsigned kickoff TX.
    pub fn new(
        pool_outpoint: OutPoint,
        pool_amount: Amount,
        operator_xonly: XOnlyPublicKey,
        kickoff_delay: u16,
        kickoff_fee: Amount,
    ) -> Self {
        let kickoff_tx = build_kickoff_tx(
            pool_outpoint,
            pool_amount,
            &operator_xonly,
            kickoff_delay,
            kickoff_fee,
        );
        Epoch {
            kickoff_tx,
            states: Vec::new(),
            pool_outpoint,
            pool_amount,
            operator_xonly,
        }
    }

    /// Sign the kickoff transaction.
    pub fn sign_kickoff(&mut self, key_agg_ctx: &KeyAggContext, secret_keys: &[Scalar]) {
        let pool_script = p2tr_script_pubkey(&self.operator_xonly);
        let mut txs = vec![self.kickoff_tx.clone()];
        let prevouts = vec![PrevoutInfo {
            amount: self.pool_amount,
            script_pubkey: pool_script,
        }];
        sign_transactions(&mut txs, &prevouts, key_agg_ctx, secret_keys);
        self.kickoff_tx = txs.into_iter().next().unwrap();
    }

    /// The kickoff TX output amount.
    pub fn kickoff_output_amount(&self) -> Amount {
        self.kickoff_tx.output[0].value
    }

    /// Build, sign, and add a new state to this epoch.
    ///
    /// nSequence = nseq_start - (state_number * step_size).
    /// The latest state has the lowest nSequence and matures first.
    pub fn add_state(
        &mut self,
        allocations: Vec<UserAllocation>,
        nseq_start: u16,
        step_size: u16,
        split_fee: Amount,
        root_fee: Amount,
        key_agg_ctx: &KeyAggContext,
        secret_keys: &[Scalar],
    ) {
        let state_number = self.states.len() as u32;
        let nsequence = nseq_start - (state_number as u16 * step_size);

        let kickoff_txid = self.kickoff_tx.compute_txid();
        let kickoff_outpoint = OutPoint::new(kickoff_txid, 0);
        let kickoff_output_amount = self.kickoff_output_amount();

        let (exit_tree, mut all_txs, all_prevouts, _sighashes) = build_state_transactions(
            kickoff_outpoint,
            kickoff_output_amount,
            &self.operator_xonly,
            &allocations,
            nsequence,
            root_fee,
            split_fee,
        );

        // Sign all transactions (root + splits)
        sign_transactions(&mut all_txs, &all_prevouts, key_agg_ctx, secret_keys);

        self.states.push(StatePackage {
            state_number,
            nsequence,
            exit_tree,
            allocations,
            signed_txs: all_txs,
        });
    }

    /// Cooperatively refresh the pool UTXO, starting a new epoch.
    ///
    /// Returns the signed refresh TX and a new Epoch with the fresh pool UTXO.
    /// Once the refresh TX confirms, all states in this epoch become invalid.
    pub fn refresh(
        &self,
        refresh_fee: Amount,
        kickoff_delay: u16,
        kickoff_fee: Amount,
        key_agg_ctx: &KeyAggContext,
        secret_keys: &[Scalar],
    ) -> (Transaction, Epoch) {
        let mut txs = vec![build_refresh_tx(
            self.pool_outpoint,
            self.pool_amount,
            &self.operator_xonly,
            refresh_fee,
        )];
        let prevouts = vec![PrevoutInfo {
            amount: self.pool_amount,
            script_pubkey: p2tr_script_pubkey(&self.operator_xonly),
        }];
        sign_transactions(&mut txs, &prevouts, key_agg_ctx, secret_keys);
        let signed_refresh = txs.into_iter().next().unwrap();

        let new_pool_amount = self.pool_amount - refresh_fee;
        let new_pool_outpoint = OutPoint::new(signed_refresh.compute_txid(), 0);

        let new_epoch = Epoch::new(
            new_pool_outpoint,
            new_pool_amount,
            self.operator_xonly,
            kickoff_delay,
            kickoff_fee,
        );

        (signed_refresh, new_epoch)
    }

    /// Cooperative refresh with deposit inputs and withdrawal outputs.
    ///
    /// Signs the pool input (index 0) with MuSig2.
    /// Deposit inputs (indices 1..N) must be signed externally by depositors
    /// using `signing::sign_input_keyspend`.
    ///
    /// Returns the partially-signed refresh TX, the prevouts (for deposit signing),
    /// and the new Epoch.
    pub fn refresh_with_io(
        &self,
        deposits: &[DepositInput],
        withdrawals: &[WithdrawalOutput],
        refresh_fee: Amount,
        kickoff_delay: u16,
        kickoff_fee: Amount,
        key_agg_ctx: &KeyAggContext,
        secret_keys: &[Scalar],
    ) -> (Transaction, Vec<TxOut>, Epoch) {
        let mut tx = build_refresh_with_io(
            self.pool_outpoint,
            self.pool_amount,
            &self.operator_xonly,
            deposits,
            withdrawals,
            refresh_fee,
        );

        // Build prevouts for all inputs (needed for sighash)
        let mut all_prevouts = vec![TxOut {
            value: self.pool_amount,
            script_pubkey: p2tr_script_pubkey(&self.operator_xonly),
        }];
        for dep in deposits {
            all_prevouts.push(TxOut {
                value: dep.amount,
                script_pubkey: dep.script_pubkey.clone(),
            });
        }

        // Sign pool input with MuSig2
        sign_input_musig2(&mut tx, 0, &all_prevouts, key_agg_ctx, secret_keys);

        let new_pool_amount = tx.output[0].value;
        let new_pool_outpoint = OutPoint::new(tx.compute_txid(), 0);

        let new_epoch = Epoch::new(
            new_pool_outpoint,
            new_pool_amount,
            self.operator_xonly,
            kickoff_delay,
            kickoff_fee,
        );

        (tx, all_prevouts, new_epoch)
    }
}
