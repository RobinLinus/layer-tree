use std::collections::HashSet;

use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use musig2::{
    BinaryEncoding, FirstRound, KeyAggContext, LiftedSignature, PartialSignature, PubNonce,
    SecNonceSpices, SecondRound,
};

// Use musig2's secp types
use musig2::secp::Scalar;

/// Information about the previous output being spent by a transaction.
pub struct PrevoutInfo {
    pub amount: Amount,
    pub script_pubkey: ScriptBuf,
}

/// Sign a batch of transactions using MuSig2 with the given operator keys.
///
/// Each transaction spends a single P2TR keyspend input.
/// Inserts Schnorr signatures into each transaction's witness.
/// Returns the signatures.
pub fn sign_transactions(
    transactions: &mut [Transaction],
    prevouts: &[PrevoutInfo],
    key_agg_ctx: &KeyAggContext,
    secret_keys: &[Scalar],
) -> Vec<LiftedSignature> {
    let n_signers = secret_keys.len();
    let n_txs = transactions.len();
    assert_eq!(prevouts.len(), n_txs);

    // Compute sighashes for all transactions
    let sighashes: Vec<[u8; 32]> = transactions
        .iter()
        .zip(prevouts.iter())
        .map(|(tx, prevout)| compute_sighash(tx, prevout))
        .collect();

    // === ROUND 1: Generate and exchange nonces ===

    // Create FirstRound for each (transaction, signer) pair
    // sessions[tx_idx][signer_idx]
    let mut sessions: Vec<Vec<FirstRound>> = (0..n_txs)
        .map(|tx_idx| {
            (0..n_signers)
                .map(|signer_idx| {
                    let mut nonce_seed = [0u8; 32];
                    rand::fill(&mut nonce_seed);
                    FirstRound::new(
                        key_agg_ctx.clone(),
                        nonce_seed,
                        signer_idx,
                        SecNonceSpices::new()
                            .with_seckey(secret_keys[signer_idx])
                            .with_message(&sighashes[tx_idx]),
                    )
                    .expect("valid signer index")
                })
                .collect()
        })
        .collect();

    // Collect all public nonces: nonces[tx_idx][signer_idx]
    let nonces: Vec<Vec<PubNonce>> = sessions
        .iter()
        .map(|tx_sessions| {
            tx_sessions
                .iter()
                .map(|round| round.our_public_nonce())
                .collect()
        })
        .collect();

    // Distribute nonces to all signers within each session
    for tx_idx in 0..n_txs {
        for signer_idx in 0..n_signers {
            for other_idx in 0..n_signers {
                if other_idx != signer_idx {
                    sessions[tx_idx][signer_idx]
                        .receive_nonce(other_idx, nonces[tx_idx][other_idx].clone())
                        .expect("valid nonce");
                }
            }
        }
    }

    // === ROUND 2: Generate and exchange partial signatures ===

    // Finalize first rounds -> second rounds
    let mut second_rounds: Vec<Vec<_>> = Vec::with_capacity(n_txs);
    for (tx_idx, tx_sessions) in sessions.into_iter().enumerate() {
        let mut tx_second_rounds = Vec::with_capacity(n_signers);
        for (signer_idx, first_round) in tx_sessions.into_iter().enumerate() {
            let second = first_round
                .finalize(secret_keys[signer_idx], sighashes[tx_idx])
                .expect("finalize first round");
            tx_second_rounds.push(second);
        }
        second_rounds.push(tx_second_rounds);
    }

    // Collect partial signatures
    let partial_sigs: Vec<Vec<musig2::PartialSignature>> = second_rounds
        .iter()
        .map(|tx_rounds| tx_rounds.iter().map(|r| r.our_signature()).collect())
        .collect();

    // Distribute partial signatures
    for tx_idx in 0..n_txs {
        for signer_idx in 0..n_signers {
            for other_idx in 0..n_signers {
                if other_idx != signer_idx {
                    second_rounds[tx_idx][signer_idx]
                        .receive_signature(other_idx, partial_sigs[tx_idx][other_idx])
                        .expect("valid partial signature");
                }
            }
        }
    }

    // === FINALIZE: Aggregate signatures and insert into witnesses ===

    let mut signatures = Vec::with_capacity(n_txs);
    for (tx_idx, tx_rounds) in second_rounds.into_iter().enumerate() {
        let sig: LiftedSignature = tx_rounds
            .into_iter()
            .next()
            .unwrap()
            .finalize()
            .expect("finalize second round");
        signatures.push(sig);

        // Insert signature into the transaction's witness
        let sig_bytes = sig.to_bytes();
        transactions[tx_idx].input[0].witness = {
            let mut w = bitcoin::Witness::new();
            w.push(sig_bytes);
            w
        };
    }

    signatures
}

/// Compute the taproot keyspend sighash for a specific input.
/// `prevouts` must contain a TxOut for every input in the transaction.
pub fn compute_sighash_for_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> [u8; 32] {
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .expect("valid sighash");
    sighash.to_byte_array()
}

/// Compute the taproot keyspend sighash for a transaction with a single input.
fn compute_sighash(tx: &Transaction, prevout: &PrevoutInfo) -> [u8; 32] {
    let prev_txout = TxOut {
        value: prevout.amount,
        script_pubkey: prevout.script_pubkey.clone(),
    };
    compute_sighash_for_input(tx, 0, &[prev_txout])
}

/// Sign a single input of a transaction using MuSig2 keyspend.
pub fn sign_input_musig2(
    tx: &mut Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    key_agg_ctx: &KeyAggContext,
    secret_keys: &[Scalar],
) {
    let sighash = compute_sighash_for_input(tx, input_index, prevouts);
    let n_signers = secret_keys.len();

    // Round 1: nonces
    let mut sessions: Vec<FirstRound> = (0..n_signers)
        .map(|signer_idx| {
            let mut nonce_seed = [0u8; 32];
            rand::fill(&mut nonce_seed);
            FirstRound::new(
                key_agg_ctx.clone(),
                nonce_seed,
                signer_idx,
                SecNonceSpices::new()
                    .with_seckey(secret_keys[signer_idx])
                    .with_message(&sighash),
            )
            .expect("valid signer index")
        })
        .collect();

    let nonces: Vec<PubNonce> = sessions.iter().map(|s| s.our_public_nonce()).collect();

    for signer_idx in 0..n_signers {
        for other_idx in 0..n_signers {
            if other_idx != signer_idx {
                sessions[signer_idx]
                    .receive_nonce(other_idx, nonces[other_idx].clone())
                    .expect("valid nonce");
            }
        }
    }

    // Round 2: partial signatures
    let mut second_rounds: Vec<_> = sessions
        .into_iter()
        .enumerate()
        .map(|(idx, first)| {
            first
                .finalize(secret_keys[idx], sighash)
                .expect("finalize first round")
        })
        .collect();

    let partial_sigs: Vec<musig2::PartialSignature> =
        second_rounds.iter().map(|r| r.our_signature()).collect();

    for signer_idx in 0..n_signers {
        for other_idx in 0..n_signers {
            if other_idx != signer_idx {
                second_rounds[signer_idx]
                    .receive_signature(other_idx, partial_sigs[other_idx])
                    .expect("valid partial sig");
            }
        }
    }

    let sig: LiftedSignature = second_rounds
        .into_iter()
        .next()
        .unwrap()
        .finalize()
        .expect("finalize second round");

    tx.input[input_index].witness = {
        let mut w = bitcoin::Witness::new();
        w.push(sig.to_bytes());
        w
    };
}

/// Sign a single input using a regular Schnorr keyspend (single signer, no MuSig).
pub fn sign_input_keyspend(
    tx: &mut Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    secret_key: &bitcoin::secp256k1::SecretKey,
) {
    let sighash = compute_sighash_for_input(tx, input_index, prevouts);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, secret_key);
    let msg = bitcoin::secp256k1::Message::from_digest(sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    tx.input[input_index].witness = {
        let mut w = bitcoin::Witness::new();
        w.push(sig.serialize());
        w
    };
}

// === Distributed MuSig2 Signing ===

/// Errors during distributed MuSig2 signing.
#[derive(Debug)]
pub enum SigningError {
    /// Received data from an invalid or own signer index.
    InvalidSignerIndex(usize),
    /// Received duplicate data from the same signer.
    DuplicateSigner(usize),
    /// Wrong number of items received.
    WrongCount { expected: usize, got: usize },
    /// Session is not in the expected state.
    WrongState(&'static str),
    /// Underlying MuSig2 protocol error.
    Musig2(String),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignerIndex(i) => write!(f, "invalid signer index: {i}"),
            Self::DuplicateSigner(i) => write!(f, "duplicate data from signer {i}"),
            Self::WrongCount { expected, got } => {
                write!(f, "expected {expected} items, got {got}")
            }
            Self::WrongState(msg) => write!(f, "wrong session state: {msg}"),
            Self::Musig2(msg) => write!(f, "musig2: {msg}"),
        }
    }
}

impl std::error::Error for SigningError {}

/// Internal state machine for [`SigningSession`].
enum SessionState {
    /// Round 1: collecting public nonces from other signers.
    CollectingNonces {
        first_rounds: Vec<FirstRound>,
        received: HashSet<usize>,
    },
    /// Round 2: collecting partial signatures from other signers.
    CollectingPartialSigs {
        second_rounds: Vec<SecondRound<[u8; 32]>>,
        received: HashSet<usize>,
    },
    /// All rounds complete; aggregated signatures available.
    Complete {
        signatures: Vec<LiftedSignature>,
    },
    /// Temporary placeholder during state transitions.
    Transitioning,
}

/// Distributed MuSig2 signing session for a batch of transactions.
///
/// Each operator creates their own `SigningSession` with their secret key,
/// then exchanges nonces and partial signatures with peers. All operators
/// calling this with identical sighashes produce identical final signatures.
///
/// Protocol (2 communication rounds total for any number of transactions):
/// 1. Each operator calls [`SigningSession::new`] → gets `Vec<PubNonce>` to broadcast.
/// 2. Each operator feeds received nonces via [`SigningSession::receive_nonces`].
///    When the last nonce arrives, returns `Vec<PartialSignature>` to broadcast.
/// 3. Each operator feeds received partial sigs via [`SigningSession::receive_partial_sigs`].
///    When the last sig arrives, returns `Vec<LiftedSignature>` — the final signatures.
///
/// For single-operator mode (n_signers=1), `new()` completes immediately.
pub struct SigningSession {
    signer_index: usize,
    n_signers: usize,
    n_txs: usize,
    sighashes: Vec<[u8; 32]>,
    state: SessionState,
}

impl SigningSession {
    /// Create a new signing session. Returns our public nonces to send to peers.
    ///
    /// For single-operator mode (n_signers=1), the session completes immediately
    /// and signatures are available via [`SigningSession::signatures`].
    pub fn new(
        signer_index: usize,
        n_signers: usize,
        sighashes: Vec<[u8; 32]>,
        key_agg_ctx: &KeyAggContext,
        secret_key: &Scalar,
    ) -> Result<(Self, Vec<PubNonce>), SigningError> {
        let n_txs = sighashes.len();
        let mut first_rounds = Vec::with_capacity(n_txs);
        let mut pub_nonces = Vec::with_capacity(n_txs);

        for sighash in &sighashes {
            let mut nonce_seed = [0u8; 32];
            rand::fill(&mut nonce_seed);
            let first = FirstRound::new(
                key_agg_ctx.clone(),
                nonce_seed,
                signer_index,
                SecNonceSpices::new()
                    .with_seckey(*secret_key)
                    .with_message(sighash),
            )
            .map_err(|e| SigningError::Musig2(e.to_string()))?;
            pub_nonces.push(first.our_public_nonce());
            first_rounds.push(first);
        }

        let mut session = SigningSession {
            signer_index,
            n_signers,
            n_txs,
            sighashes,
            state: SessionState::CollectingNonces {
                first_rounds,
                received: HashSet::new(),
            },
        };

        // Single signer: no peers to wait for, complete immediately
        if n_signers == 1 {
            session.transition_to_partial_sigs(secret_key)?;
            session.transition_to_complete()?;
        }

        Ok((session, pub_nonces))
    }

    /// Feed public nonces from another signer.
    ///
    /// Returns `Some(partial_sigs)` when all nonces have been received,
    /// meaning round 1 is complete. Send these partial sigs to all peers.
    pub fn receive_nonces(
        &mut self,
        from_signer: usize,
        nonces: Vec<PubNonce>,
        secret_key: &Scalar,
    ) -> Result<Option<Vec<PartialSignature>>, SigningError> {
        if from_signer >= self.n_signers || from_signer == self.signer_index {
            return Err(SigningError::InvalidSignerIndex(from_signer));
        }
        if nonces.len() != self.n_txs {
            return Err(SigningError::WrongCount {
                expected: self.n_txs,
                got: nonces.len(),
            });
        }

        let SessionState::CollectingNonces {
            first_rounds,
            received,
        } = &mut self.state
        else {
            return Err(SigningError::WrongState("not collecting nonces"));
        };

        if received.contains(&from_signer) {
            return Err(SigningError::DuplicateSigner(from_signer));
        }

        for (round, nonce) in first_rounds.iter_mut().zip(nonces) {
            round
                .receive_nonce(from_signer, nonce)
                .map_err(|e| SigningError::Musig2(e.to_string()))?;
        }
        received.insert(from_signer);

        if received.len() == self.n_signers - 1 {
            let partial_sigs = self.transition_to_partial_sigs(secret_key)?;
            Ok(Some(partial_sigs))
        } else {
            Ok(None)
        }
    }

    /// Feed partial signatures from another signer.
    ///
    /// Returns `Some(signatures)` when all partial sigs have been received,
    /// meaning round 2 is complete. These are the final aggregated Schnorr signatures.
    pub fn receive_partial_sigs(
        &mut self,
        from_signer: usize,
        partial_sigs: Vec<PartialSignature>,
    ) -> Result<Option<Vec<LiftedSignature>>, SigningError> {
        if from_signer >= self.n_signers || from_signer == self.signer_index {
            return Err(SigningError::InvalidSignerIndex(from_signer));
        }
        if partial_sigs.len() != self.n_txs {
            return Err(SigningError::WrongCount {
                expected: self.n_txs,
                got: partial_sigs.len(),
            });
        }

        let SessionState::CollectingPartialSigs {
            second_rounds,
            received,
        } = &mut self.state
        else {
            return Err(SigningError::WrongState("not collecting partial sigs"));
        };

        if received.contains(&from_signer) {
            return Err(SigningError::DuplicateSigner(from_signer));
        }

        for (round, sig) in second_rounds.iter_mut().zip(partial_sigs) {
            round
                .receive_signature(from_signer, sig)
                .map_err(|e| SigningError::Musig2(e.to_string()))?;
        }
        received.insert(from_signer);

        if received.len() == self.n_signers - 1 {
            let sigs = self.transition_to_complete()?;
            Ok(Some(sigs))
        } else {
            Ok(None)
        }
    }

    /// Whether the session has completed and signatures are available.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, SessionState::Complete { .. })
    }

    /// Get the final aggregated signatures, if the session is complete.
    pub fn signatures(&self) -> Option<&[LiftedSignature]> {
        match &self.state {
            SessionState::Complete { signatures } => Some(signatures),
            _ => None,
        }
    }

    /// Transition from CollectingNonces → CollectingPartialSigs.
    /// Consumes all FirstRound sessions, producing SecondRound sessions.
    fn transition_to_partial_sigs(
        &mut self,
        secret_key: &Scalar,
    ) -> Result<Vec<PartialSignature>, SigningError> {
        let old = std::mem::replace(&mut self.state, SessionState::Transitioning);
        match old {
            SessionState::CollectingNonces { first_rounds, .. } => {
                let mut second_rounds = Vec::with_capacity(self.n_txs);
                let mut partial_sigs = Vec::with_capacity(self.n_txs);

                for (first, sighash) in first_rounds.into_iter().zip(&self.sighashes) {
                    let second = first
                        .finalize(*secret_key, *sighash)
                        .map_err(|e| SigningError::Musig2(e.to_string()))?;
                    partial_sigs.push(second.our_signature());
                    second_rounds.push(second);
                }

                self.state = SessionState::CollectingPartialSigs {
                    second_rounds,
                    received: HashSet::new(),
                };
                Ok(partial_sigs)
            }
            other => {
                self.state = other;
                Err(SigningError::WrongState("not collecting nonces"))
            }
        }
    }

    /// Transition from CollectingPartialSigs → Complete.
    /// Consumes all SecondRound sessions, producing final signatures.
    fn transition_to_complete(&mut self) -> Result<Vec<LiftedSignature>, SigningError> {
        let old = std::mem::replace(&mut self.state, SessionState::Transitioning);
        match old {
            SessionState::CollectingPartialSigs { second_rounds, .. } => {
                let mut signatures = Vec::with_capacity(self.n_txs);
                for round in second_rounds {
                    let sig = round
                        .finalize()
                        .map_err(|e| SigningError::Musig2(e.to_string()))?;
                    signatures.push(sig);
                }
                let result = signatures.clone();
                self.state = SessionState::Complete { signatures };
                Ok(result)
            }
            other => {
                self.state = other;
                Err(SigningError::WrongState("not collecting partial sigs"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::OperatorSet;
    use crate::state::build_state_transactions;
    use crate::transactions::build_kickoff_tx;
    use crate::tree::UserAllocation;
    use bitcoin::Amount;

    #[test]
    fn test_distributed_signing_3_signers() {
        let n_signers = 3;
        let ops = OperatorSet::generate(n_signers);
        let operator_xonly = ops.aggregate_xonly();
        let key_agg_ctx = &ops.key_agg_ctx;

        // Build a dummy kickoff
        let pool_outpoint =
            bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([0xAB; 32]), 0);
        let pool_amount = Amount::from_sat(100_000);
        let kickoff_tx = build_kickoff_tx(
            pool_outpoint,
            pool_amount,
            &operator_xonly,
            10,
            Amount::from_sat(200),
        );
        let kickoff_outpoint = bitcoin::OutPoint::new(kickoff_tx.compute_txid(), 0);
        let kickoff_output_amount = kickoff_tx.output[0].value;

        // Create 4 user allocations (depth=1, single split tx)
        // kickoff_output = 100_000 - 200 = 99_800
        // root_output = 99_800 - 200 = 99_600
        // 99_600 = 4 * user_amount + 300 (1 split fee)
        // user_amount = (99_600 - 300) / 4 = 24_825
        let allocations: Vec<UserAllocation> = (0..4)
            .map(|i| {
                let mut bytes = [0x01; 32];
                bytes[0] = (i + 10) as u8;
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
                UserAllocation {
                    pubkey: pk.x_only_public_key().0,
                    amount: Amount::from_sat(24_825),
                }
            })
            .collect();

        let nsequence = 20;
        let root_fee = Amount::from_sat(200);
        let split_fee = Amount::from_sat(300);

        // Build transactions deterministically
        let (_exit_tree, _txs, _prevouts, sighashes) = build_state_transactions(
            kickoff_outpoint,
            kickoff_output_amount,
            &operator_xonly,
            &allocations,
            nsequence,
            root_fee,
            split_fee,
        );

        let n_txs = sighashes.len();
        assert!(n_txs > 0, "should have at least 1 transaction");

        // === Create signing sessions for each operator ===
        let mut sessions: Vec<SigningSession> = Vec::new();
        let mut all_nonces: Vec<Vec<PubNonce>> = Vec::new();

        for (i, key) in ops.keys.iter().enumerate() {
            let (session, nonces) = SigningSession::new(
                i,
                n_signers,
                sighashes.clone(),
                key_agg_ctx,
                &key.secret,
            )
            .expect("create session");
            assert!(!session.is_complete());
            sessions.push(session);
            all_nonces.push(nonces);
        }

        // === Round 1: Exchange nonces ===
        let mut all_partial_sigs: Vec<Option<Vec<PartialSignature>>> = vec![None; n_signers];
        for i in 0..n_signers {
            for j in 0..n_signers {
                if i != j {
                    let nonces = all_nonces[j].clone();
                    let result = sessions[i]
                        .receive_nonces(j, nonces, &ops.keys[i].secret)
                        .expect("receive nonces");
                    if let Some(partial_sigs) = result {
                        all_partial_sigs[i] = Some(partial_sigs);
                    }
                }
            }
        }

        // All sessions should have produced partial sigs
        for (i, ps) in all_partial_sigs.iter().enumerate() {
            assert!(ps.is_some(), "signer {i} should have partial sigs");
            assert_eq!(ps.as_ref().unwrap().len(), n_txs);
        }

        // === Round 2: Exchange partial signatures ===
        let mut all_signatures: Vec<Option<Vec<LiftedSignature>>> = vec![None; n_signers];
        for i in 0..n_signers {
            for j in 0..n_signers {
                if i != j {
                    let psigs = all_partial_sigs[j].clone().unwrap();
                    let result = sessions[i]
                        .receive_partial_sigs(j, psigs)
                        .expect("receive partial sigs");
                    if let Some(sigs) = result {
                        all_signatures[i] = Some(sigs);
                    }
                }
            }
        }

        // All sessions should be complete with matching signatures
        for i in 0..n_signers {
            assert!(sessions[i].is_complete(), "session {i} should be complete");
            assert!(
                all_signatures[i].is_some(),
                "signer {i} should have final signatures"
            );
        }

        // Verify all operators got byte-identical signatures
        let sigs_0 = all_signatures[0].as_ref().unwrap();
        for i in 1..n_signers {
            let sigs_i = all_signatures[i].as_ref().unwrap();
            for (j, (s0, si)) in sigs_0.iter().zip(sigs_i.iter()).enumerate() {
                assert_eq!(
                    s0.to_bytes(),
                    si.to_bytes(),
                    "sig {j} differs between signer 0 and signer {i}"
                );
            }
        }

        // Verify signatures are valid Schnorr signatures against the aggregate key
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        for (j, sig) in sigs_0.iter().enumerate() {
            let schnorr_sig =
                bitcoin::secp256k1::schnorr::Signature::from_slice(&sig.to_bytes())
                    .expect("valid sig format");
            let msg = bitcoin::secp256k1::Message::from_digest(sighashes[j]);
            secp.verify_schnorr(&schnorr_sig, &msg, &operator_xonly)
                .unwrap_or_else(|e| panic!("signature {j} should verify: {e}"));
        }
    }

    #[test]
    fn test_single_signer_session() {
        let ops = OperatorSet::generate(1);
        let key_agg_ctx = &ops.key_agg_ctx;

        let sighashes = vec![[0xAB; 32], [0xCD; 32], [0xEF; 32]];

        let (session, _nonces) =
            SigningSession::new(0, 1, sighashes, key_agg_ctx, &ops.keys[0].secret)
                .expect("create single-signer session");

        assert!(session.is_complete());
        let sigs = session.signatures().unwrap();
        assert_eq!(sigs.len(), 3);
    }

    #[test]
    fn test_signing_session_error_cases() {
        let ops = OperatorSet::generate(3);
        let key_agg_ctx = &ops.key_agg_ctx;
        let sighashes = vec![[0xAB; 32]];

        // Create a second session to get a valid PubNonce
        let (_, valid_nonces) =
            SigningSession::new(1, 3, sighashes.clone(), key_agg_ctx, &ops.keys[1].secret)
                .expect("create helper session");

        let (mut session, _) =
            SigningSession::new(0, 3, sighashes, key_agg_ctx, &ops.keys[0].secret)
                .expect("create session");

        // Wrong signer index (own index)
        assert!(matches!(
            session.receive_nonces(0, valid_nonces.clone(), &ops.keys[0].secret),
            Err(SigningError::InvalidSignerIndex(0))
        ));

        // Wrong signer index (out of range)
        assert!(matches!(
            session.receive_nonces(5, valid_nonces.clone(), &ops.keys[0].secret),
            Err(SigningError::InvalidSignerIndex(5))
        ));

        // Wrong count
        assert!(matches!(
            session.receive_nonces(1, vec![], &ops.keys[0].secret),
            Err(SigningError::WrongCount {
                expected: 1,
                got: 0
            })
        ));
    }
}
