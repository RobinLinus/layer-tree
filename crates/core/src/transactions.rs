use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};

/// Create a P2TR script_pubkey for a given x-only public key (keyspend only, no scripts).
pub fn p2tr_script_pubkey(xonly: &XOnlyPublicKey) -> ScriptBuf {
    Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(*xonly),
        Network::Regtest,
    )
    .script_pubkey()
}

/// Build an unsigned kickoff transaction.
///
/// Spends the pool UTXO with a relative timelock (nSequence = kickoff_delay).
/// Output is a P2TR with the operator aggregate key.
pub fn build_kickoff_tx(
    pool_outpoint: OutPoint,
    pool_amount: Amount,
    operator_xonly: &XOnlyPublicKey,
    kickoff_delay: u16,
    fee: Amount,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: pool_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(kickoff_delay),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: pool_amount - fee,
            script_pubkey: p2tr_script_pubkey(operator_xonly),
        }],
    }
}

/// Build an unsigned cooperative refresh transaction.
///
/// Spends the old pool UTXO and creates a new pool UTXO.
/// No timelock — this is a cooperative transaction signed by all operators.
/// Once confirmed, all old epoch states become permanently invalid.
pub fn build_refresh_tx(
    pool_outpoint: OutPoint,
    pool_amount: Amount,
    operator_xonly: &XOnlyPublicKey,
    fee: Amount,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: pool_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: pool_amount - fee,
            script_pubkey: p2tr_script_pubkey(operator_xonly),
        }],
    }
}

/// A deposit: an L1 UTXO being added to the pool via a refresh TX.
#[derive(Clone)]
pub struct DepositInput {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub script_pubkey: ScriptBuf,
}

/// A withdrawal: a direct L1 output in a refresh TX.
#[derive(Clone)]
pub struct WithdrawalOutput {
    pub script_pubkey: ScriptBuf,
    pub amount: Amount,
}

/// Build an unsigned refresh TX with deposit inputs and withdrawal outputs.
///
/// Input 0 is always the pool UTXO (signed by operators via MuSig2).
/// Inputs 1..N are deposit UTXOs (signed individually by depositors).
/// Output 0 is the new pool UTXO.
/// Outputs 1..M are withdrawal destinations.
pub fn build_refresh_with_io(
    pool_outpoint: OutPoint,
    pool_amount: Amount,
    operator_xonly: &XOnlyPublicKey,
    deposits: &[DepositInput],
    withdrawals: &[WithdrawalOutput],
    fee: Amount,
) -> Transaction {
    let mut inputs = vec![TxIn {
        previous_output: pool_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }];
    for dep in deposits {
        inputs.push(TxIn {
            previous_output: dep.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    let total_deposits: Amount = deposits.iter().map(|d| d.amount).sum();
    let total_withdrawals: Amount = withdrawals.iter().map(|w| w.amount).sum();
    let new_pool_amount = pool_amount + total_deposits - total_withdrawals - fee;

    let mut outputs = vec![TxOut {
        value: new_pool_amount,
        script_pubkey: p2tr_script_pubkey(operator_xonly),
    }];
    for w in withdrawals {
        outputs.push(TxOut {
            value: w.amount,
            script_pubkey: w.script_pubkey.clone(),
        });
    }

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Build an unsigned root transaction.
///
/// Spends the kickoff output with a relative timelock (nSequence = state-specific value).
/// Output is a P2TR with the operator aggregate key (exit tree root).
pub fn build_root_tx(
    kickoff_outpoint: OutPoint,
    kickoff_amount: Amount,
    operator_xonly: &XOnlyPublicKey,
    nsequence: u16,
    fee: Amount,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: kickoff_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(nsequence),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: kickoff_amount - fee,
            script_pubkey: p2tr_script_pubkey(operator_xonly),
        }],
    }
}
